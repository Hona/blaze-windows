//! Traced describe records for unsealed crates: captures every portable dependency that
//! describing an instance (including `code_walk`, MIR optimization, inlining and
//! `always_inlinable`) reads, and validates it across daemon restarts via [`blaze_record`].
//!
//! Sealed crates (`hir_def::deps::sealed` with an image) use the single-key path in
//! [`super`], because their transitive closure is pinned and cannot change. Unsealed crates
//! (workspace crates, path dependencies, crates above them, and generics instantiated over
//! workspace types) cannot reuse a describe on the strength of the caller's own source alone:
//! `describe_reads::an_unchanged_callers_body_identity_cannot_validate_its_walk` proves that
//! changing an `#[inline]` callee's body alters the caller's call targets while leaving the
//! caller's own body identity unchanged.
//!
//! Instead, each unsealed describe is filed as a constructive trace (`blaze_record`):
//! - **Base key**: schema, codegen producer (`Toolchain::id`), build stage + requester settings,
//!   the home crate's settings (`crate_inputs`, no other source files), the instance's own
//!   `early_identity` (when it has a body), and the instance ported by content (`port::Writer`).
//! - **Read-list (shape)**: every dependency read during `HirFrontend::described`, recorded by
//!   `blaze_memo::record` (which flattens non-boundary queries including `code_walk` down to
//!   marked fact boundaries and inputs) and classified by `blaze_item_hash::reads::fact_of_in`
//!   into portable content-keyed [`DescribeFact`] entries with zero database-local IDs.
//! - **Answer**: magic `"bztd0001"`, its `AnswerKey` echoed for verification, and the portable
//!   encoded `Described` payload (`super::encode_described`).
//!
//! Any read that cannot be represented as a portable fact refuses caching for that describe:
//! nothing unsound is ever written to the store (rule 21).

use std::cell::RefCell;

use base_db::{Crate, Db};
use blaze_cas::Key;
use blaze_codegen::{
    CodegenError,
    backend::Described,
    driver::{Put, RECORD_KIND, Records},
    plan::Origin,
};
use blaze_format::{
    Part, SchemaHash,
    cursor::{Put as _, Reader},
    schema_of,
};
use blaze_ids::{ContentId, Hasher};
use blaze_item_hash::{
    Bodies,
    identity::{crate_inputs, early_identity},
    reads as item_reads, values as item_values,
};
use blaze_items::{ItemId, ItemKey, Resolved, key as item_keys};
use blaze_record::{
    AnswerKey, Bounds, Digest, Filing, Found as RecordFound, Kind as RecordKind,
    Store as RecordStore, Tally,
};
use hir_def::DefWithBodyId;
use hir_ty::{
    body_store::{Classified, Step, step_value_with},
    next_solver::{
        DbInterner, ParamEnv,
        goal_store::{FactObject, FactRef},
    },
};

use super::{
    Closure, HirFrontend, HirInstance, HirStatic, Kind, body_of, decode_described,
    encode_described, port, put_instance,
};

/// Magic prefix of a traced describe answer record.
const ANSWER_MAGIC: &[u8; 8] = b"bztd0001";

const TRACE_DOMAIN: &str = "blaze v2 traced describe record 1";
const TRACE_LAYOUT: u64 = 1;

const TRACE_SCHEMA: SchemaHash = schema_of(&[
    Part::Str(TRACE_DOMAIN),
    Part::U64(TRACE_LAYOUT),
    Part::Schema(port::SCHEMA),
    Part::U64(blaze_record::LAYOUT as u64),
]);

const FACT_ABSENT_DOMAIN: &str = "blaze v2 traced describe fact absent 1";

/// Fact encoding tags.
const TAG_ITEM_HASH_FACT: u8 = 0;
const TAG_BODY_MIR: u8 = 7;
const TAG_BODY_INFER: u8 = 8;

/// Planted bug switch for tests: omits `code_walk` dependencies from the captured read-list
/// so the oracle control proves stale inlined-callee hits are caught.
#[cfg(test)]
pub(crate) mod planted {
    use std::cell::Cell;

    thread_local! {
        pub(crate) static DROP_WALK_READS: Cell<bool> = const { Cell::new(false) };
    }
}

/// A portable, database-independent dependency read by a function's describe / code walk.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) enum DescribeFact {
    /// Any fact from `blaze-item-hash` or `blaze-items::goals`.
    ItemHash(FactRef),
    /// Deterministic hash of a body's built MIR (`step_value_with(..., Step::Mir)`),
    /// covering the caller's own body as well as any inlined or `#[inline(always)]` callee.
    BodyMir(ContentId),
    /// Deterministic hash of a body's inference (`step_value_with(..., Step::Infer)`).
    BodyInfer(ContentId),
}

impl DescribeFact {
    fn encode(&self, out: &mut Vec<u8>) {
        match *self {
            DescribeFact::ItemHash(FactRef { kind, subject, object }) => {
                out.put_u8(TAG_ITEM_HASH_FACT);
                out.put_u16(kind.0);
                out.put_bytes(&subject.0);
                match object {
                    FactObject::None => out.put_u8(0),
                    FactObject::Field(field) => {
                        out.put_u8(1);
                        out.put_u32(field);
                    }
                    FactObject::Id(id) => {
                        out.put_u8(2);
                        out.put_bytes(&id.0);
                    }
                }
            }
            DescribeFact::BodyMir(body) => {
                out.put_u8(TAG_BODY_MIR);
                out.put_bytes(&body.0);
            }
            DescribeFact::BodyInfer(body) => {
                out.put_u8(TAG_BODY_INFER);
                out.put_bytes(&body.0);
            }
        }
    }

    fn decode(bytes: &[u8]) -> Option<DescribeFact> {
        let mut r = Reader::new(bytes);
        let tag = r.u8().ok()?;
        let fact = match tag {
            TAG_ITEM_HASH_FACT => {
                let kind = blaze_query::QueryKind(r.u16().ok()?);
                let subject = ContentId(*r.array::<32>().ok()?);
                let object = match r.u8().ok()? {
                    0 => FactObject::None,
                    1 => FactObject::Field(r.u32().ok()?),
                    2 => FactObject::Id(ContentId(*r.array::<32>().ok()?)),
                    _ => return None,
                };
                DescribeFact::ItemHash(FactRef { kind, subject, object })
            }
            TAG_BODY_MIR => DescribeFact::BodyMir(ContentId(*r.array::<32>().ok()?)),
            TAG_BODY_INFER => DescribeFact::BodyInfer(ContentId(*r.array::<32>().ok()?)),
            _ => return None,
        };
        r.finish().ok()?;
        Some(fact)
    }
}

/// Evaluates `fact` in `db` for an instance homed in `home` with optional body `def`.
fn evaluate(
    db: &Db,
    home: Crate,
    def: Option<DefWithBodyId>,
    fact: DescribeFact,
) -> Option<ContentId> {
    match fact {
        DescribeFact::ItemHash(fact) => {
            let fact = if fact.subject == item_values::OWN {
                FactRef { subject: item_values::body_key(db, def?), ..fact }
            } else {
                fact
            };
            if fact.kind == item_values::kinds::STEP_MIR
                || fact.kind == item_values::kinds::STEP_INFER
            {
                let step =
                    if fact.kind == item_values::kinds::STEP_MIR { Step::Mir } else { Step::Infer };
                return match resolve_body(db, fact.subject)? {
                    None => Some(item_values::absent(fact.kind)),
                    Some(body) => step_value_with(db, &Bodies, body, step),
                };
            }
            item_values::value(db, home, fact)
        }
        DescribeFact::BodyMir(body) => match resolve_body(db, body)? {
            None => Some(absent(TAG_BODY_MIR)),
            Some(body) => step_value_with(db, &Bodies, body, Step::Mir),
        },
        DescribeFact::BodyInfer(body) => match resolve_body(db, body)? {
            None => Some(absent(TAG_BODY_INFER)),
            Some(body) => step_value_with(db, &Bodies, body, Step::Infer),
        },
    }
}

fn absent(tag: u8) -> ContentId {
    Hasher::new(FACT_ABSENT_DOMAIN).update(&[tag]).finish()
}

fn resolve_body(db: &Db, subject: ContentId) -> Option<Option<DefWithBodyId>> {
    match item_keys::resolve(db, ItemKey(subject)) {
        None => Some(None),
        Some(Resolved::Item(ItemId::Function(it))) => Some(Some(DefWithBodyId::FunctionId(it))),
        Some(Resolved::Item(ItemId::Const(it))) => Some(Some(DefWithBodyId::ConstId(it))),
        Some(Resolved::Item(ItemId::Static(it))) => Some(Some(DefWithBodyId::StaticId(it))),
        Some(Resolved::Variant(it)) => Some(Some(DefWithBodyId::VariantId(it))),
        Some(_) => None,
    }
}

/// Adapts `blaze_codegen::driver::Records` + a `Vec<Put>` sink to `blaze_record::Store`.
struct TraceStore<'a> {
    records: &'a dyn Records,
    puts: RefCell<&'a mut Vec<Put>>,
    tally: Tally,
}

impl RecordStore for TraceStore<'_> {
    type Held = Vec<u8>;
    type Error = String;

    fn get(&self, _kind: RecordKind, key: &ContentId) -> Result<Option<Vec<u8>>, String> {
        let mut out = None;
        let had = self.records.read(&Key(*key), &mut |bytes| {
            // alloc: one read-list or answer buffer on a store hit
            out = Some(bytes.to_vec());
        })?;
        Ok(if had { out } else { None })
    }

    fn put(&self, _kind: RecordKind, key: ContentId, bytes: &[u8]) -> Result<(), String> {
        self.puts.borrow_mut().push(Put {
            key: Key(key),
            kind: RECORD_KIND,
            // alloc: one stored record on a describe miss
            bytes: bytes.to_vec(),
            of: None,
        });
        Ok(())
    }

    fn bytes(held: &Vec<u8>) -> &[u8] {
        held.as_slice()
    }

    fn tally(&self) -> &Tally {
        &self.tally
    }
}

/// Inputs that identify a traced describe before the describe runs.
struct Base<'db> {
    base: ContentId,
    home: Crate,
    def: Option<DefWithBodyId>,
    closure: Closure<'db>,
}

/// Computes the content-addressed base key for an unsealed instance before running `describe`.
fn base_of<'db>(
    front: &HirFrontend<'db>,
    db: &'db Db,
    instance: &HirInstance,
    requester: &Origin,
) -> Option<Base<'db>> {
    let (producer, stage) = front.record_stage_for_trace()?;
    let Kind::Code(_, env) = &instance.0 else { return None };
    if env.param_env(db) != ParamEnv::empty() {
        return None;
    }
    let home = env.krate;
    let def = body_of(db, instance);
    let body_id = match def {
        Some(def) => Some(early_identity(db, def).ok()?),
        None => {
            // Require a front-end build identity so `crate_inputs` covers the solver version.
            if blaze_item_hash::identity::FrontEnd::try_get(db).is_none() {
                return None;
            }
            None
        }
    };
    let home_inputs = crate_inputs(db, home);
    let mut asked = Hasher::new(super::STAGE_DOMAIN);
    asked.id(&stage);
    front.units.as_ref()?.asked_as(requester, &mut asked)?;
    let closure = Closure::of(db, home);
    let mut writer = port::Writer::new(db, DbInterner::new_no_crate(db));
    let mut named = Vec::with_capacity(64); // alloc: once per traced base key
    put_instance(&closure, &mut writer, &mut named, instance)?;
    let ported = writer.finish(&mut |item| closure.name(item)).ok()?;
    let mut inputs = Hasher::new(TRACE_DOMAIN);
    inputs.id(&asked.finish()).id(&home_inputs);
    match body_id {
        Some(id) => {
            inputs.update(&[1]).id(&id);
        }
        None => {
            inputs.update(&[0]);
        }
    }
    inputs.part(&named).part(&ported);
    let key = Key::of(TRACE_SCHEMA, producer, &[inputs.finish()]);
    Some(Base { base: key.0, home, def, closure })
}

/// Encodes a traced answer payload (magic + answer key + portable described bytes).
fn encode_answer(answer_key: &ContentId, payload: &[u8]) -> Vec<u8> {
    // alloc: one answer record on a miss
    let mut out = Vec::with_capacity(ANSWER_MAGIC.len() + 32 + payload.len());
    out.put_bytes(ANSWER_MAGIC);
    out.put_bytes(&answer_key.0);
    out.put_bytes(payload);
    out
}

/// Decodes and validates a traced answer payload against its expected `answer_key`.
pub(crate) fn open_answer<'a>(bytes: &'a [u8], expected: &ContentId) -> Result<&'a [u8], String> {
    let mut r = Reader::new(bytes);
    let magic = r.array::<8>().map_err(|e| e.to_string())?;
    if magic != ANSWER_MAGIC {
        // alloc: error path
        return Err(format!(
            "traced describe answer magic is {magic:?}, not `bztd0001`: an answer of another layout"
        ));
    }
    let stored_key = r.array::<32>().map_err(|e| e.to_string())?;
    if stored_key != &expected.0 {
        return Err(
            "traced describe answer key does not match the lookup key (corrupt or mismatched)"
                .to_owned(), // alloc: error path
        );
    }
    Ok(&bytes[ANSWER_MAGIC.len() + 32..])
}

/// Extracts every portable [`DescribeFact`] from a captured `blaze_memo::record` list.
/// Returns `Err(read_name)` when any read cannot be represented as a portable fact.
pub(crate) fn capture_facts(
    db: &Db,
    home: Crate,
    _def: Option<DefWithBodyId>,
    reads: &[blaze_memo::Read],
) -> Result<Vec<DescribeFact>, &'static str> {
    let mut facts = Vec::new(); // alloc: per describe miss, the captured facts
    for &read in reads {
        match item_reads::fact_of_in(db, home, None, read) {
            Classified::Covered => {}
            Classified::Fact(fact) | Classified::Scan(fact, _) => {
                if fact.kind == item_values::kinds::STEP_MIR {
                    facts.push(DescribeFact::BodyMir(fact.subject));
                } else if fact.kind == item_values::kinds::STEP_INFER {
                    facts.push(DescribeFact::BodyInfer(fact.subject));
                } else {
                    facts.push(DescribeFact::ItemHash(fact));
                }
            }
            Classified::Refused(name) => return Err(name),
        }
    }
    facts.sort_unstable();
    facts.dedup();
    Ok(facts)
}

/// Looks up or computes `instance` for `requester` via a traced describe record.
///
/// Returns `Ok((described, true))` on a valid traced record hit, `Ok((described, false))` when
/// computed fresh (pushing any newly captured `list` + `answer` records to `puts`), or `Err`
/// on a corrupt record or front-end describe failure.
pub(super) fn describe_recorded<'db>(
    front: &HirFrontend<'db>,
    db: &'db Db,
    instance: &HirInstance,
    requester: &Origin,
    // dyn: store reader from `Build::recording`
    records_store: &dyn Records,
    puts: &mut Vec<Put>,
) -> Result<(Described<HirInstance, HirStatic>, bool), CodegenError> {
    let unread = |key: ContentId, why: String| {
        crate::v2::undescribed(
            db,
            &crate::v2::Named(db, instance),
            None,
            // alloc: error path
            format!(
                "the traced describe record of `{}` under {:x} does not read: {why}",
                super::spelled(db, &instance.0),
                key
            ),
        )
    };

    // 1. Try lookup when a traced base key exists.
    let world_active = front.devirt.world().is_some();
    let base = base_of(front, db, instance, requester);
    if let Some(ref base) = base {
        let store = TraceStore {
            records: records_store,
            puts: RefCell::new(puts),
            tally: Tally::new(),
        };
        let found = blaze_record::lookup(&store, Bounds::STANDARD, &base.base, |raw| {
            let fact = DescribeFact::decode(raw)?;
            let value = evaluate(db, base.home, base.def, fact)?;
            Some(Digest::Is(value))
        });
        match found {
            Ok(RecordFound::Hit { answer, key, .. }) => {
                let desc = open_answer(&answer, &key)
                    .and_then(|payload| {
                        decode_described(db, requester, payload, |callee, c| {
                            if let Kind::Code(_, env) = &callee.0
                                && hir_def::deps::sealed(db, env.krate)
                                && let Some(found) = &front.found
                            {
                                found.counted.pin().insert(callee.clone(), c);
                            }
                        })
                    })
                    .map_err(|why| unread(key, why))?;
                if !(world_active && desc.takes_world) {
                    return Ok((desc, true));
                }
            }
            Ok(RecordFound::Miss { .. }) => {}
            Err(err) => return Err(unread(base.base, err.to_string())),
        }
    }

    // 2. Miss: describe live while capturing all flattened reads from blaze-memo.
    let (made, captured) = describe_and_capture(front, db, instance, requester);
    let described = made?;

    // 3. If eligible, not world-dependent, and all captured reads classify into portable facts,
    //    file the read-list and answer via `blaze_record`.
    let Some(base) = base else {
        return Ok((described, false));
    };
    if world_active && described.takes_world {
        return Ok((described, false));
    }
    let Some(reads) = captured else {
        return Ok((described, false));
    };
    let Ok(facts) = capture_facts(db, base.home, base.def, &reads) else {
        return Ok((described, false));
    };
    // Compute every fact's value now; refuse caching if any fact is unhashable.
    let mut encoded_facts: Vec<Vec<u8>> = Vec::with_capacity(facts.len()); // alloc: per miss, the read-list's entries
    let mut values: Vec<ContentId> = Vec::with_capacity(facts.len()); // alloc: as above
    for &fact in &facts {
        let Some(value) = evaluate(db, base.home, base.def, fact) else {
            return Ok((described, false));
        };
        let mut buf = Vec::with_capacity(68);
        fact.encode(&mut buf);
        encoded_facts.push(buf);
        values.push(value);
    }
    let own = match super::crate_of(db, &instance.0) {
        Some(krate) if !super::user_compiled(db, &instance.0) => Some(front.origin(db, krate)),
        _ => None,
    };
    if described.origin != own.unwrap_or(*requester) {
        return Ok((described, false));
    }
    let Some(payload) = encode_described(db, &base.closure, own.as_ref(), &described) else {
        return Ok((described, false));
    };
    let mut list_bytes = Vec::new(); // alloc: one read-list buffer on a miss
    blaze_record::write_list(
        &mut list_bytes,
        &base.base,
        &[],
        encoded_facts.iter().map(|it| it.as_slice()),
    );
    let mut answer_key = AnswerKey::new(&list_bytes);
    for value in &values {
        answer_key.value(Digest::Is(*value));
    }
    let answer_key = answer_key.finish();
    let answer_bytes = encode_answer(&answer_key, &payload);

    let store = TraceStore {
        records: records_store,
        puts: RefCell::new(puts),
        tally: Tally::new(),
    };
    let mut filing = Filing::new(base.base, Bounds::STANDARD);
    match filing.place(&store, &list_bytes) {
        Ok(blaze_record::Placed::Written(_) | blaze_record::Placed::Kept(_)) => {
            if let Err(err) = blaze_record::keep_answer(&store, answer_key, &answer_bytes) {
                return Err(unread(answer_key, err.to_string()));
            }
        }
        Ok(blaze_record::Placed::Full) => {}
        Err(err) => return Err(unread(base.base, err.to_string())),
    }
    Ok((described, false))
}

/// Runs `HirFrontend::described` while recording its flattened reads from `blaze-memo`.
fn describe_and_capture(
    front: &HirFrontend<'_>,
    db: &Db,
    instance: &HirInstance,
    requester: &Origin,
) -> (
    Result<Described<HirInstance, HirStatic>, CodegenError>,
    Option<Vec<blaze_memo::Read, std::alloc::Global>>,
) {
    let world = front.key_world(db, instance);
    let memo = blaze_memo::Database::memo(db);
    #[cfg(test)]
    if planted::DROP_WALK_READS.get() {
        return match blaze_memo::record_readers(memo, || {
            front.described(db, instance, requester, world)
        }) {
            Ok((made, readers)) => {
                let mut kept: Vec<blaze_memo::Read, std::alloc::Global> =
                    Vec::new_in(std::alloc::Global);
                for (read, reader) in &readers.rows {
                    let from_walk = readers.chain(*reader).any(|kind| {
                        kind.name().ends_with("::code_walk") || kind.name() == "code_walk"
                    });
                    if !from_walk {
                        kept.push(*read);
                    }
                }
                kept.sort_unstable();
                kept.dedup();
                (made, Some(kept))
            }
            Err(_) => (front.described(db, instance, requester, world), None),
        };
    }
    match blaze_memo::record(memo, || front.described(db, instance, requester, world)) {
        Ok((made, reads)) => (made, Some(reads)),
        Err(_) => (front.described(db, instance, requester, world), None),
    }
}
