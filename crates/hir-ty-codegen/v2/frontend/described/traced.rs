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
//! - **Read-list (shape)**: every dependency read during `HirFrontend::described`, descended
//!   through `code_walk` and every other pure derived memo via `Reads::for_each_read_through`
//!   (so dependencies are captured even on warm memo hits!), converted to portable content-keyed
//!   [`DescribeFact`] entries with zero database-local IDs.
//! - **Answer**: magic `"bztd0001"`, its `AnswerKey` echoed for verification, and the portable
//!   encoded `Described` payload (`super::encode_described`).
//!
//! Any read that cannot be represented as a portable fact (or any `Stored` / `Unsettled` read
//! encountered when descending through a memo) refuses caching for that describe: nothing
//! unsound is ever written to the store (rule 21).

use std::cell::{Cell, RefCell};
use std::ops::ControlFlow;

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
use blaze_items::{
    ItemId, ItemKey, Resolved,
    goals::Goals,
    key as item_keys,
};
use blaze_query::db::{
    Database as _, DatabaseKeyIndex, FromIdIn, Id, Read, ReadKind, RowRead, capture_reads,
};
use blaze_record::{AnswerKey, Bounds, Digest, Filing, Found as RecordFound, Kind as RecordKind, Store as RecordStore, Tally};
use hir_def::{
    AdtId, AttrDefId, DefWithBodyId, ExpressionStoreOwnerId, FunctionId, HasModule as _,
    ModuleIdLt,
    attrs::AttrFlags,
    hir::{ClosureKind, CoroutineKind},
};
use hir_ty::{
    InferBodyId,
    body_store::{Classified, Step, step_value_with},
    db::{InternedClosureId, InternedCoroutineId},
    next_solver::{
        DbInterner, ParamEnv,
        goal_store::{FactObject, FactRef, GoalFacts as _},
    },
};

use super::{
    Closure, HirFrontend, HirInstance, HirStatic, Kind, body_of, decode_described,
    encode_described, names_files, port, put_instance, witnesses,
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
const FACT_ITEM_KEY_DOMAIN: &str = "blaze v2 traced describe item key 1";
const FACT_MODULE_KEY_DOMAIN: &str = "blaze v2 traced describe module key 1";
const FACT_MACROS_BUILT_DOMAIN: &str = "blaze v2 traced describe macros built 1";
const FACT_CODEGEN_ATTRS_DOMAIN: &str = "blaze v2 traced describe codegen attrs 1";
const FACT_ITEM_HASH_DOMAIN: &str = "blaze v2 traced describe item hash 1";
const FACT_LOC_MACROS_DOMAIN: &str = "blaze v2 traced describe location macros 1";
const FACT_LINE_LITERALS_DOMAIN: &str = "blaze v2 traced describe line literals 1";
const FACT_SERVED_IMAGE_DOMAIN: &str = "blaze v2 traced describe served image 1";

/// Fact encoding tags.
const TAG_ITEM_HASH_FACT: u8 = 0;
const TAG_CRATE_INPUTS: u8 = 1;
const TAG_CODEGEN_ATTRS: u8 = 2;
const TAG_ITEM_HASH_KIND: u8 = 3;
const TAG_ITEM_KEY: u8 = 4;
const TAG_MODULE_KEY: u8 = 5;
const TAG_MACROS_BUILT: u8 = 6;
const TAG_BODY_MIR: u8 = 7;
const TAG_BODY_INFER: u8 = 8;
const TAG_LOCATION_MACROS: u8 = 9;
const TAG_LINE_LITERALS: u8 = 10;
const TAG_SERVED_IMAGE: u8 = 11;

/// Sub-kinds for [`DescribeFact::ItemHashKind`].
const HASH_INTERFACE: u8 = 0;
const HASH_SIGNATURE: u8 = 1;
const HASH_LAYOUT: u8 = 2;
const HASH_CODE: u8 = 3;
const HASH_DEEP: u8 = 4;
const HASH_BOUND: u8 = 5;

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
    /// A crate's settings (`blaze_item_hash::identity::crate_inputs`, no source files).
    CrateInputs(ContentId),
    /// Codegen-relevant attributes of an item (`export_name`, `link_name`, `linkage`,
    /// `link_section`, `target_features`, `repr`, `bits`, `nounwind`, flags).
    CodegenAttrs(ItemKey),
    /// One of `blaze-items`'s item hashes (`interface`, `signature`, `layout`, `code`, `deep`,
    /// `bound`) keyed directly by [`ItemKey`].
    ItemHashKind { kind: u8, item: ItemKey },
    /// Existence and kind of an item at [`ItemKey`].
    ItemKey(ItemKey),
    /// Existence of a module at [`ItemKey`].
    ModuleKey(ItemKey),
    /// Whether every proc-macro dependency of a crate (by crate key) has been built.
    MacrosBuilt(ContentId),
    /// Deterministic hash of a body's built MIR (`step_value_with(..., Step::Mir)`),
    /// covering the caller's own body as well as any inlined or `#[inline(always)]` callee.
    BodyMir(ContentId),
    /// Deterministic hash of a body's inference (`step_value_with(..., Step::Infer)`).
    BodyInfer(ContentId),
    /// That a body calls no `file!()` / `concat!(..., file!())` location macros.
    LocationMacros(ContentId),
    /// The set of `line!()` literal expressions in a body.
    LineLiterals(ContentId),
    /// A sealed dependency crate whose runtime MIR was read from its served image.
    ServedImage(ContentId),
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
            DescribeFact::CrateInputs(krate) => {
                out.put_u8(TAG_CRATE_INPUTS);
                out.put_bytes(&krate.0);
            }
            DescribeFact::CodegenAttrs(item) => {
                out.put_u8(TAG_CODEGEN_ATTRS);
                out.put_bytes(&item.0.0);
            }
            DescribeFact::ItemHashKind { kind, item } => {
                out.put_u8(TAG_ITEM_HASH_KIND);
                out.put_u8(kind);
                out.put_bytes(&item.0.0);
            }
            DescribeFact::ItemKey(item) => {
                out.put_u8(TAG_ITEM_KEY);
                out.put_bytes(&item.0.0);
            }
            DescribeFact::ModuleKey(module) => {
                out.put_u8(TAG_MODULE_KEY);
                out.put_bytes(&module.0.0);
            }
            DescribeFact::MacrosBuilt(krate) => {
                out.put_u8(TAG_MACROS_BUILT);
                out.put_bytes(&krate.0);
            }
            DescribeFact::BodyMir(body) => {
                out.put_u8(TAG_BODY_MIR);
                out.put_bytes(&body.0);
            }
            DescribeFact::BodyInfer(body) => {
                out.put_u8(TAG_BODY_INFER);
                out.put_bytes(&body.0);
            }
            DescribeFact::LocationMacros(body) => {
                out.put_u8(TAG_LOCATION_MACROS);
                out.put_bytes(&body.0);
            }
            DescribeFact::LineLiterals(body) => {
                out.put_u8(TAG_LINE_LITERALS);
                out.put_bytes(&body.0);
            }
            DescribeFact::ServedImage(krate) => {
                out.put_u8(TAG_SERVED_IMAGE);
                out.put_bytes(&krate.0);
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
            TAG_CRATE_INPUTS => DescribeFact::CrateInputs(ContentId(*r.array::<32>().ok()?)),
            TAG_CODEGEN_ATTRS => DescribeFact::CodegenAttrs(ItemKey(ContentId(*r.array::<32>().ok()?))),
            TAG_ITEM_HASH_KIND => {
                let kind = r.u8().ok()?;
                let item = ItemKey(ContentId(*r.array::<32>().ok()?));
                DescribeFact::ItemHashKind { kind, item }
            }
            TAG_ITEM_KEY => DescribeFact::ItemKey(ItemKey(ContentId(*r.array::<32>().ok()?))),
            TAG_MODULE_KEY => DescribeFact::ModuleKey(ItemKey(ContentId(*r.array::<32>().ok()?))),
            TAG_MACROS_BUILT => DescribeFact::MacrosBuilt(ContentId(*r.array::<32>().ok()?)),
            TAG_BODY_MIR => DescribeFact::BodyMir(ContentId(*r.array::<32>().ok()?)),
            TAG_BODY_INFER => DescribeFact::BodyInfer(ContentId(*r.array::<32>().ok()?)),
            TAG_LOCATION_MACROS => DescribeFact::LocationMacros(ContentId(*r.array::<32>().ok()?)),
            TAG_LINE_LITERALS => DescribeFact::LineLiterals(ContentId(*r.array::<32>().ok()?)),
            TAG_SERVED_IMAGE => DescribeFact::ServedImage(ContentId(*r.array::<32>().ok()?)),
            _ => return None,
        };
        r.finish().ok()?;
        Some(fact)
    }
}

/// Evaluates `fact` in `db` for an instance homed in `home` with optional body `def`.
fn evaluate(db: &Db, home: Crate, def: Option<DefWithBodyId>, fact: DescribeFact) -> Option<ContentId> {
    match fact {
        DescribeFact::ItemHash(fact) => {
            let fact = if fact.subject == item_values::OWN {
                FactRef { subject: item_values::body_key(db, def?), ..fact }
            } else {
                fact
            };
            // Evaluate `STEP_MIR` / `STEP_INFER` via `step_value_with` so standalone databases
            // without an installed `body_store` compute the exact same hash.
            if fact.kind == item_values::kinds::STEP_MIR
                || fact.kind == item_values::kinds::STEP_INFER
            {
                let step = if fact.kind == item_values::kinds::STEP_MIR {
                    Step::Mir
                } else {
                    Step::Infer
                };
                return match resolve_body(db, fact.subject)? {
                    None => Some(item_values::absent(fact.kind)),
                    Some(body) => step_value_with(db, &Bodies, body, step),
                };
            }
            item_values::value(db, home, fact)
        }
        DescribeFact::CrateInputs(krate_key) => match item_keys::resolve_crate(db, &krate_key) {
            None => Some(absent(TAG_CRATE_INPUTS)),
            Some(krate) => Some(crate_inputs(db, krate)),
        },
        DescribeFact::CodegenAttrs(item) => match item_keys::resolve(db, item) {
            None => Some(absent(TAG_CODEGEN_ATTRS)),
            Some(resolved) => Some(codegen_attrs_digest(db, attr_owner(resolved)?)),
        },
        DescribeFact::ItemHashKind { kind, item } => match item_keys::resolve(db, item) {
            None => Some(absent_item_hash(kind)),
            Some(Resolved::Item(id)) => {
                let mut h = Hasher::new(FACT_ITEM_HASH_DOMAIN);
                h.update(&[kind]);
                match kind {
                    HASH_INTERFACE => {
                        h.id(&blaze_items::interface_hash(db, id).ok()?.0);
                    }
                    HASH_SIGNATURE => {
                        h.id(&blaze_items::signature_hash(db, id).ok()?.0);
                    }
                    HASH_LAYOUT => {
                        let ItemId::Adt(adt) = id else { return None };
                        h.id(&blaze_items::layout_hash(db, adt).ok()?.0);
                    }
                    HASH_CODE => match blaze_items::code_hash(db, id).ok()? {
                        Some(code) => {
                            h.update(&[1]).id(&code.0);
                        }
                        None => {
                            h.update(&[0]);
                        }
                    },
                    HASH_DEEP => {
                        h.id(&blaze_items::deep_hash(db, id).ok()?.0);
                    }
                    HASH_BOUND => match blaze_items::bound_hash(db, id).ok()? {
                        Some(bound) => {
                            h.update(&[1]).id(&bound);
                        }
                        None => {
                            h.update(&[0]);
                        }
                    },
                    _ => return None,
                }
                Some(h.finish())
            }
            Some(_) => None,
        },
        DescribeFact::ItemKey(item) => {
            let tag: u8 = match item_keys::resolve(db, item) {
                None => 0,
                Some(Resolved::Item(ItemId::Function(_))) => 1,
                Some(Resolved::Item(ItemId::Adt(AdtId::StructId(_)))) => 2,
                Some(Resolved::Item(ItemId::Adt(AdtId::EnumId(_)))) => 3,
                Some(Resolved::Item(ItemId::Adt(AdtId::UnionId(_)))) => 4,
                Some(Resolved::Item(ItemId::Trait(_))) => 5,
                Some(Resolved::Item(ItemId::Impl(_))) => 6,
                Some(Resolved::Item(ItemId::Const(_))) => 7,
                Some(Resolved::Item(ItemId::Static(_))) => 8,
                Some(Resolved::Item(ItemId::Alias(_))) => 9,
                Some(Resolved::Item(ItemId::Macro(_))) => 10,
                Some(Resolved::Variant(_)) => 11,
                Some(_) => 12,
            };
            Some(Hasher::new(FACT_ITEM_KEY_DOMAIN).update(&[tag]).finish())
        }
        DescribeFact::ModuleKey(module) => {
            let present = matches!(item_keys::resolve(db, module), Some(Resolved::Module(_)));
            Some(Hasher::new(FACT_MODULE_KEY_DOMAIN).update(&[u8::from(present)]).finish())
        }
        DescribeFact::MacrosBuilt(krate_key) => match item_keys::resolve_crate(db, &krate_key) {
            None => Some(absent(TAG_MACROS_BUILT)),
            Some(krate) => {
                // Never cache while any proc macro this crate can expand is unbuilt.
                blaze_items::macros_built(db, krate).ok()?;
                Some(Hasher::new(FACT_MACROS_BUILT_DOMAIN).update(&[1]).finish())
            }
        },
        DescribeFact::BodyMir(body) => match resolve_body(db, body)? {
            None => Some(absent(TAG_BODY_MIR)),
            Some(body) => step_value_with(db, &Bodies, body, Step::Mir),
        },
        DescribeFact::BodyInfer(body) => match resolve_body(db, body)? {
            None => Some(absent(TAG_BODY_INFER)),
            Some(body) => step_value_with(db, &Bodies, body, Step::Infer),
        },
        DescribeFact::LocationMacros(body) => match resolve_body(db, body)? {
            None => Some(absent(TAG_LOCATION_MACROS)),
            Some(body) => {
                if !hir_ty_mir::mir::location::location_macros(db, body).is_empty()
                    || !hir_ty_mir::mir::location::located_concats(db, body).is_empty()
                {
                    // A body calling `file!()` depends on build file-path naming; refuse.
                    return None;
                }
                Some(Hasher::new(FACT_LOC_MACROS_DOMAIN).update(&[0]).finish())
            }
        },
        DescribeFact::LineLiterals(body) => match resolve_body(db, body)? {
            None => Some(absent(TAG_LINE_LITERALS)),
            Some(body) => {
                let literals = hir_ty_mir::mir::location::line_literals(db, body);
                let mut raw: Vec<u32> =
                    literals.iter().map(|it| it.into_raw().into_u32()).collect(); // alloc: per body with `line!()`, usually empty
                raw.sort_unstable();
                let mut h = Hasher::new(FACT_LINE_LITERALS_DOMAIN);
                h.update(&(raw.len() as u64).to_le_bytes());
                for id in raw {
                    h.update(&id.to_le_bytes());
                }
                Some(h.finish())
            }
        },
        DescribeFact::ServedImage(krate_key) => match item_keys::resolve_crate(db, &krate_key) {
            None => Some(absent(TAG_SERVED_IMAGE)),
            Some(krate) => {
                if !hir_def::deps::sealed(db, krate) {
                    return None;
                }
                let image = hir_def::deps::image_of(db, krate).as_ref()?.key();
                Some(Hasher::new(FACT_SERVED_IMAGE_DOMAIN).id(&image).finish())
            }
        },
    }
}

fn absent(tag: u8) -> ContentId {
    Hasher::new(FACT_ABSENT_DOMAIN).update(&[tag]).finish()
}

fn absent_item_hash(kind: u8) -> ContentId {
    Hasher::new(FACT_ABSENT_DOMAIN).update(&[TAG_ITEM_HASH_KIND, kind]).finish()
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

fn attr_owner(resolved: Resolved) -> Option<AttrDefId> {
    Some(match resolved {
        Resolved::Module(it) => AttrDefId::ModuleId(it),
        Resolved::Variant(it) => AttrDefId::EnumVariantId(it),
        Resolved::Item(ItemId::Function(it)) => AttrDefId::FunctionId(it),
        Resolved::Item(ItemId::Adt(it)) => AttrDefId::AdtId(it),
        Resolved::Item(ItemId::Trait(it)) => AttrDefId::TraitId(it),
        Resolved::Item(ItemId::Impl(it)) => AttrDefId::ImplId(it),
        Resolved::Item(ItemId::Const(it)) => AttrDefId::ConstId(it),
        Resolved::Item(ItemId::Static(it)) => AttrDefId::StaticId(it),
        Resolved::Item(ItemId::Alias(it)) => AttrDefId::TypeAliasId(it),
        Resolved::Item(ItemId::Macro(it)) => AttrDefId::MacroId(it),
        _ => return None,
    })
}

fn attr_subject(db: &Db, owner: AttrDefId) -> Option<ItemKey> {
    Some(match owner {
        AttrDefId::ModuleId(it) => item_keys::module_key(db, it),
        AttrDefId::EnumVariantId(it) => item_keys::variant_key(db, it),
        AttrDefId::AdtId(it) => item_keys::item_key(db, ItemId::Adt(it)),
        AttrDefId::FunctionId(it) => item_keys::item_key(db, ItemId::Function(it)),
        AttrDefId::StaticId(it) => item_keys::item_key(db, ItemId::Static(it)),
        AttrDefId::ConstId(it) => item_keys::item_key(db, ItemId::Const(it)),
        AttrDefId::TraitId(it) => item_keys::item_key(db, ItemId::Trait(it)),
        AttrDefId::TypeAliasId(it) => item_keys::item_key(db, ItemId::Alias(it)),
        AttrDefId::MacroId(it) => item_keys::item_key(db, ItemId::Macro(it)),
        AttrDefId::ImplId(it) => item_keys::item_key(db, ItemId::Impl(it)),
        AttrDefId::ExternBlockId(_) | AttrDefId::ExternCrateId(_) | AttrDefId::UseId(_) => {
            return None;
        }
    })
}

fn codegen_attrs_digest(db: &Db, owner: AttrDefId) -> ContentId {
    let flags = AttrFlags::query(db, owner);
    let mut h = Hasher::new(FACT_CODEGEN_ATTRS_DOMAIN);
    h.update(&flags.bits().to_le_bytes());
    let opt_sym = |h: &mut Hasher, sym: Option<intern::Symbol>| match sym {
        Some(s) => {
            h.update(&[1]).part(s.as_str().as_bytes());
        }
        None => {
            h.update(&[0]);
        }
    };
    if flags.contains(AttrFlags::HAS_EXPORT_NAME) {
        opt_sym(&mut h, AttrFlags::export_name(db, owner));
    }
    if flags.contains(AttrFlags::HAS_LINK_NAME) {
        opt_sym(&mut h, AttrFlags::link_name(db, owner));
    }
    if flags.contains(AttrFlags::HAS_LINKAGE) {
        opt_sym(&mut h, AttrFlags::linkage(db, owner));
    }
    if flags.contains(AttrFlags::HAS_LINK_SECTION) {
        opt_sym(&mut h, AttrFlags::link_section(db, owner));
    }
    opt_sym(&mut h, flags.unstable_feature(db, owner));
    opt_sym(&mut h, flags.lang_item_with_attrs(db, owner));
    if let AttrDefId::AdtId(adt) = owner {
        if flags.contains(AttrFlags::HAS_REPR) {
            h.part(format!("{:?}", AttrFlags::repr_assume_has(db, adt)).as_bytes());
        }
        h.part(format!("{:?}", AttrFlags::rustc_layout_scalar_valid_range(db, adt)).as_bytes());
    }
    if let Some(bits) = AttrFlags::blaze_bits(db, owner) {
        h.part(format!("{bits:?}").as_bytes());
    }
    if let Some(pure) = AttrFlags::pure_attr(db, owner) {
        h.part(format!("{pure:?}").as_bytes());
    }
    if let AttrDefId::FunctionId(func) = owner {
        let mut features: Vec<&str> =
            AttrFlags::target_features(db, func).iter().map(|it| it.as_str()).collect(); // alloc: target features on one fn
        features.sort_unstable();
        h.update(&(features.len() as u64).to_le_bytes());
        for feature in features {
            h.part(feature.as_bytes());
        }
    }
    h.finish()
}

/// Classification of one captured read during `HirFrontend::described`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WalkClass {
    Covered,
    Fact(DescribeFact),
    Through,
    Refused,
}

fn ends_with_path(file: &str, at: &str) -> bool {
    let mut actual = file.rsplit(['/', '\\']);
    at.rsplit('/').all(|part| actual.next() == Some(part))
}

fn strip_generics(name: &str) -> &str {
    match name.find('<') {
        Some(open) if name.ends_with('>') => name[..open].trim_end(),
        _ => name,
    }
}

fn arg<T: FromIdIn>(db: &Db, key: Id) -> Option<T> {
    T::from_id_in(db.storage(), key)
}

/// Resolves the body owner of a `mir_body*` or `infer_body_query` read key.
fn body_of_step_key(db: &Db, own: Option<DefWithBodyId>, key: Id) -> StepTarget {
    let of = |body: InferBodyId<'_>| match body {
        InferBodyId::DefWithBodyId(body) => StepTarget::Body(body),
        InferBodyId::AnonConstId(it) => match (own, it.loc(db).owner) {
            (Some(def), ExpressionStoreOwnerId::Body(body)) if body == def => StepTarget::OwnConst,
            _ => StepTarget::Unknown,
        },
    };
    if let Some(body) = arg::<DefWithBodyId>(db, key) {
        return StepTarget::Body(body);
    }
    if let Some(body) = arg::<InferBodyId<'_>>(db, key) {
        return of(body);
    }
    if let Some(closure) = arg::<InternedClosureId<'_>>(db, key) {
        let loc = closure.loc(db);
        if matches!(
            loc.kind,
            ClosureKind::Closure | ClosureKind::CoroutineClosure(CoroutineKind::Async)
        ) {
            return of(loc.owner);
        }
        return StepTarget::Unknown;
    }
    if let Some(coroutine) = arg::<InternedCoroutineId<'_>>(db, key) {
        let loc = coroutine.loc(db);
        if matches!(loc.kind, ClosureKind::Coroutine { kind: CoroutineKind::Async, .. }) {
            return of(loc.owner);
        }
        return StepTarget::Unknown;
    }
    StepTarget::Unknown
}

enum StepTarget {
    Body(DefWithBodyId),
    OwnConst,
    Unknown,
}

/// Classifies one database read made during `HirFrontend::described` of an instance homed in
/// `home` (optional body `def`).
fn classify_read(
    db: &Db,
    home: Crate,
    def: Option<DefWithBodyId>,
    read: DatabaseKeyIndex,
    kind: ReadKind,
    raw_name: &'static str,
) -> WalkClass {
    if kind == ReadKind::Interned {
        return WalkClass::Covered;
    }
    let storage = db.storage();
    let file = storage.ingredient_file(read.ingredient_index());
    let name = strip_generics(raw_name);
    let key = read.key_index();
    let def_krate = def.map(|it| it.krate(db));

    // 1. Codegen & MIR derived queries descended through even on warm memo hits.
    if ends_with_path(file, "hir-ty-codegen/v2/refs.rs")
        && matches!(name, "code_walk" | "start_walk")
    {
        #[cfg(test)]
        if name == "code_walk" && planted::DROP_WALK_READS.get() {
            return WalkClass::Covered;
        }
        return WalkClass::Through;
    }
    if (ends_with_path(file, "hir-ty-codegen/v2/devirt.rs") && name == "has_sites")
        || (ends_with_path(file, "hir-ty-codegen/mod.rs")
            && matches!(name, "always_inlinable" | "inlinable" | "body_types"))
        || (ends_with_path(file, "hir-ty-codegen/v2/frontend.rs") && name == "reaches_local")
        || (ends_with_path(file, "hir-ty-codegen/v2/hashes.rs") && name == "anchors")
        || (ends_with_path(file, "hir-ty-codegen/fncache.rs") && name == "cached_closure_of")
        || (ends_with_path(file, "hir-ty-mir/src/mir/transform.rs")
            && name == "runtime_promoted_mir_body_query")
        || (ends_with_path(file, "hir-ty-mir/src/mir/lower.rs")
            && name == "promoted_mir_body_query")
        || (ends_with_path(file, "hir-ty-mir/src/mir/monomorphization.rs")
            && name == "monomorphized_promoted_mir_body_query")
        || (ends_with_path(file, "hir-ty-mir/src/mir/optimize/inline.rs")
            && matches!(name, "cross_crate_inlinable" | "written_cross_crate_inlinable"))
        || (ends_with_path(file, "hir-ty-mir/src/mir/optimize/inline/cycle.rs")
            && matches!(
                name,
                "inliner_callees_of_fn"
                    | "inliner_callees_of_closure"
                    | "callgraph_cyclic_fn"
                    | "callgraph_cyclic_closure"
            ))
        || (ends_with_path(file, "hir-ty-mir/src/mir/optimize/specialize.rs")
            && matches!(name, "specialized_mir_body" | "plan" | "saves"))
        || (ends_with_path(file, "hir-ty-mir/src/mir/home.rs")
            && matches!(name, "home_over" | "stands_for"))
        || (ends_with_path(file, "hir-ty-mir/src/mir/eval/unwind.rs") && name == "panic_handler")
        || (ends_with_path(file, "hir-ty-share/src/code.rs")
            && matches!(
                name,
                "of_item" | "of_closure" | "of_coroutine" | "of_coroutine_by_move"
            ))
        || (ends_with_path(file, "hir-ty-share/src/fact.rs") && name == "fact")
        || (ends_with_path(file, "hir-ty-share/src/identity.rs") && name == "adt")
        || (ends_with_path(file, "hir-ty-identity/src/instance.rs")
            && matches!(name, "identity_of" | "sites"))
        || (ends_with_path(file, "blaze-items/src/hash.rs")
            && matches!(name, "closure_code_of" | "coroutine_code_of"))
        || (ends_with_path(file, "blaze-items/src/key.rs")
            && matches!(name, "store_key" | "enum_variant_keys"))
        || (ends_with_path(file, "hir-ty/src/fn_cache.rs") && name == "uses_fn_cache")
        || (ends_with_path(file, "hir-ty/src/method_resolution.rs") && name == "crates_that_name")
        || (ends_with_path(file, "hir-ty-print/src/def.rs") && name == "closures_around_query")
    {
        return WalkClass::Through;
    }

    // 2. MIR provider queries (`hir-ty/src/providers.rs`): built MIR maps to `BodyMir`,
    //    optimized/runtime/monomorphized wrappers descend through to capture inlined callees.
    if ends_with_path(file, "hir-ty/src/providers.rs") {
        match name {
            "mir_body_query"
            | "mir_body_for_closure_query"
            | "mir_body_for_coroutine_query" => {
                return match body_of_step_key(db, def, key) {
                    StepTarget::Body(body) => {
                        WalkClass::Fact(DescribeFact::BodyMir(item_values::body_key(db, body)))
                    }
                    StepTarget::OwnConst => WalkClass::Through,
                    StepTarget::Unknown => WalkClass::Refused,
                };
            }
            "runtime_mir_body_query"
            | "runtime_mir_body_for_closure_query"
            | "runtime_mir_body_for_coroutine_query" => {
                // When a crate's runtime MIR is served from its stored pages, the query row
                // reports a stored read (`RowRead::Stored`), so stop at its sealed image or
                // body MIR fact instead of descending.
                if let StepTarget::Body(body) = body_of_step_key(db, def, key) {
                    let krate = body.krate(db);
                    if hir_ty::check_cache::runtime::is_served(db, krate) {
                        if hir_def::deps::sealed(db, krate)
                            && hir_def::deps::image_of(db, krate).is_some()
                        {
                            return WalkClass::Fact(DescribeFact::ServedImage(
                                item_keys::crate_key(db, krate),
                            ));
                        }
                        return WalkClass::Fact(DescribeFact::BodyMir(
                            item_values::body_key(db, body),
                        ));
                    }
                }
                return WalkClass::Through;
            }
            "runtime_mir_body_for_coroutine_by_move_query"
            | "optimized_mir_body_query"
            | "optimized_mir_body_for_closure_query"
            | "optimized_mir_body_for_coroutine_query"
            | "optimized_mir_body_for_coroutine_by_move_query"
            | "monomorphized_mir_body_query"
            | "monomorphized_mir_body_for_closure_query"
            | "monomorphized_mir_body_for_coroutine_query"
            | "monomorphized_mir_body_for_coroutine_by_move_query"
            | "monomorphized_runtime_mir_body_query"
            | "monomorphized_runtime_mir_body_for_closure_query"
            | "monomorphized_runtime_mir_body_for_coroutine_query"
            | "monomorphized_runtime_mir_body_for_coroutine_by_move_query"
            | "monomorphized_optimized_mir_body_query"
            | "monomorphized_optimized_mir_body_for_closure_query"
            | "monomorphized_optimized_mir_body_for_coroutine_query"
            | "monomorphized_optimized_mir_body_for_coroutine_by_move_query"
            | "coroutine_witnesses_query" => return WalkClass::Through,
            _ => {}
        }
    }

    // 3. Inference step: direct `BodyInfer` fact (works with or without an installed body store).
    if ends_with_path(file, "hir-ty/src/infer.rs") && name == "infer_body_query" {
        return match body_of_step_key(db, def, key) {
            StepTarget::Body(body) => {
                WalkClass::Fact(DescribeFact::BodyInfer(item_values::body_key(db, body)))
            }
            StepTarget::OwnConst => WalkClass::Through,
            StepTarget::Unknown => WalkClass::Refused,
        };
    }

    // 4. Location macros & line literals (`hir-ty-mir/src/mir/location.rs`).
    if ends_with_path(file, "hir-ty-mir/src/mir/location.rs") {
        match name {
            "location_macros" | "located_concats" => {
                return match arg::<DefWithBodyId>(db, key) {
                    Some(owner) => WalkClass::Fact(DescribeFact::LocationMacros(
                        item_values::body_key(db, owner),
                    )),
                    None => WalkClass::Refused,
                };
            }
            "line_literals" => {
                return match arg::<DefWithBodyId>(db, key) {
                    Some(owner) => WalkClass::Fact(DescribeFact::LineLiterals(
                        item_values::body_key(db, owner),
                    )),
                    None => WalkClass::Refused,
                };
            }
            _ => {}
        }
    }

    // 5. `blaze-items` hashes, keys and proc-macro guard.
    if ends_with_path(file, "blaze-items/src/hash.rs") {
        let kind = match name {
            "interface_of" => Some(HASH_INTERFACE),
            "signature_of" => Some(HASH_SIGNATURE),
            "layout_of" => Some(HASH_LAYOUT),
            "code_of" => Some(HASH_CODE),
            "deep_of" => Some(HASH_DEEP),
            _ => None,
        };
        if let Some(kind) = kind {
            return match arg::<ItemId>(db, key) {
                Some(id) => WalkClass::Fact(DescribeFact::ItemHashKind {
                    kind,
                    item: item_keys::item_key(db, id),
                }),
                None => WalkClass::Refused,
            };
        }
    }
    if ends_with_path(file, "blaze-items/src/bound.rs") && name == "bound_of" {
        return match arg::<ItemId>(db, key) {
            Some(id) => WalkClass::Fact(DescribeFact::ItemHashKind {
                kind: HASH_BOUND,
                item: item_keys::item_key(db, id),
            }),
            None => WalkClass::Refused,
        };
    }
    if ends_with_path(file, "blaze-items/src/key.rs") {
        match name {
            "item_key" => {
                return match arg::<ItemId>(db, key) {
                    Some(id) => WalkClass::Fact(DescribeFact::ItemKey(item_keys::item_key(db, id))),
                    None => WalkClass::Refused,
                };
            }
            "module_key_in" => {
                return match arg::<ModuleIdLt<'_>>(db, key) {
                    Some(m) => {
                        WalkClass::Fact(DescribeFact::ModuleKey(item_keys::module_key(db, m.into())))
                    }
                    None => WalkClass::Refused,
                };
            }
            "crate_key" => {
                return match arg::<Crate>(db, key) {
                    Some(krate) if krate == home || Some(krate) == def_krate => WalkClass::Covered,
                    Some(krate) => {
                        WalkClass::Fact(DescribeFact::CrateInputs(item_keys::crate_key(db, krate)))
                    }
                    None => WalkClass::Refused,
                };
            }
            _ => {}
        }
    }
    if ends_with_path(file, "blaze-items/src/form.rs") && name == "pending_proc_macro" {
        return match arg::<Crate>(db, key) {
            Some(krate) => {
                WalkClass::Fact(DescribeFact::MacrosBuilt(item_keys::crate_key(db, krate)))
            }
            None => WalkClass::Refused,
        };
    }

    // 6. Crate settings and cache-delivery slots (`base-db/src/input.rs`,
    //    `blaze-item-hash/src/identity/inputs.rs`).
    if ends_with_path(file, "base-db/src/input.rs") {
        match name {
            "data" | "cfg_options" | "extra_data" | "workspace_data" => {
                return match arg::<Crate>(db, key) {
                    Some(krate) if krate == home || Some(krate) == def_krate => WalkClass::Covered,
                    Some(krate) => {
                        WalkClass::Fact(DescribeFact::CrateInputs(item_keys::crate_key(db, krate)))
                    }
                    None => WalkClass::Refused,
                };
            }
            // `Crate::given` (`slots`, `CrateSlot::value`) delivers cached pages/images whose
            // semantic inputs are already captured by the facts above.
            "slots" | "value" => return WalkClass::Covered,
            _ => {}
        }
    }
    if ends_with_path(file, "blaze-item-hash/src/identity/inputs.rs") {
        match name {
            "build" => return WalkClass::Covered,
            "crate_inputs" => {
                return match arg::<Crate>(db, key) {
                    Some(krate) if krate == home || Some(krate) == def_krate => WalkClass::Covered,
                    Some(krate) => {
                        WalkClass::Fact(DescribeFact::CrateInputs(item_keys::crate_key(db, krate)))
                    }
                    None => WalkClass::Refused,
                };
            }
            _ => {}
        }
    }

    // 7. Codegen attribute queries (`hir-def/src/attrs.rs`).
    if ends_with_path(file, "hir-def/src/attrs.rs")
        && matches!(
            name,
            "export_name"
                | "link_name"
                | "linkage"
                | "link_section"
                | "lang_item_with_attrs"
                | "pure_attr"
                | "rustc_layout_scalar_valid_range"
                | "target_features"
        )
    {
        let owner = arg::<AttrDefId>(db, key)
            .or_else(|| arg::<FunctionId>(db, key).map(AttrDefId::FunctionId))
            .or_else(|| arg::<AdtId>(db, key).map(AttrDefId::AdtId));
        return match owner.and_then(|o| attr_subject(db, o)) {
            Some(subject) => WalkClass::Fact(DescribeFact::CodegenAttrs(subject)),
            None => WalkClass::Refused,
        };
    }

    // 8. Own body lowering rows (`Body::of`, `Body::has_lowering_errors`, `closure_exprs`,
    //    `lowering`): descend through instead of relying on `STEP_LOWER`, which needs an
    //    installed `body_store`.
    if let Some(own) = def {
        let is_own_lowering = (ends_with_path(file, "hir-def/src/expr_store/body.rs")
            && matches!(name, "Body::of" | "Body::has_lowering_errors"))
            || (ends_with_path(file, "hir-ty/src/body_store/lower.rs") && name == "lowering");
        if is_own_lowering
            && (arg::<DefWithBodyId>(db, key) == Some(own)
                || arg::<InferBodyId<'_>>(db, key) == Some(InferBodyId::DefWithBodyId(own)))
        {
            return WalkClass::Through;
        }
        if ends_with_path(file, "hir-ty/src/db.rs")
            && name == "closure_exprs"
            && hir_ty::db::closure_exprs::arguments(db, key)
                == Some((ExpressionStoreOwnerId::Body(own), ()))
        {
            return WalkClass::Through;
        }
    }

    // 9. Delegate to `blaze-item-hash`'s battle-tested classifier when we have a body `def`,
    //    else classify shim-relevant `hir-ty` / `hir-def` reads against `home`.
    if let Some(own) = def {
        return match item_reads::classify(db, own, Step::Borrowck, read, kind, raw_name) {
            Classified::Covered => WalkClass::Covered,
            Classified::Fact(fact) | Classified::Scan(fact) => {
                WalkClass::Fact(DescribeFact::ItemHash(fact))
            }
            Classified::Through => WalkClass::Through,
            Classified::Refused => WalkClass::Refused,
        };
    }

    classify_shim_read(db, home, read, kind, raw_name, name, file)
}

/// Fallback classification for bodyless shims (`DropGlue`, `CallOnceShim`, `FnPointerShim`,
/// `ReifyShim`): covers layouts, solver queries, impls, signatures, attrs, and crate root facts.
fn classify_shim_read(
    db: &Db,
    home: Crate,
    read: DatabaseKeyIndex,
    kind: ReadKind,
    raw_name: &'static str,
    name: &str,
    file: &str,
) -> WalkClass {
    let key = read.key_index();
    // Pure layout / solver / drop queries that `blaze-item-hash` marks `Through`.
    if (ends_with_path(file, "hir-ty/src/layout.rs")
        && matches!(name, "layout_of_ty_query" | "struct_flags" | "struct_tail_may_be_unsized"))
        || (ends_with_path(file, "hir-ty/src/layout/adt.rs") && name == "layout_of_adt_query")
        || (ends_with_path(file, "hir-ty/src/layout/bits.rs")
            && matches!(name, "bit_width_of" | "bits_layout_query"))
        || (ends_with_path(file, "hir-ty/src/layout/field_order.rs") && name == "field_ranks")
        || (ends_with_path(file, "hir-ty/src/consteval/discriminants.rs")
            && matches!(name, "enum_discriminants" | "explicit_discriminant_indices"))
        || (ends_with_path(file, "hir-ty/src/method_resolution.rs")
            && name == "lookup_impl_method_stored")
        || (ends_with_path(file, "hir-ty/src/next_solver/global_goals/shape.rs")
            && matches!(name, "auto_trait_depth" | "copy_clone_impl"))
        || (ends_with_path(file, "hir-ty/src/next_solver/util.rs")
            && name == "impl_super_outlives")
        || (ends_with_path(file, "hir-ty/src/arbitrary_ints.rs") && name == "int_gates")
        || (ends_with_path(file, "hir-ty/src/consteval.rs") && name == "anon_const_eval_query")
    {
        return WalkClass::Through;
    }
    if ends_with_path(file, "hir-ty/src/layout/field_order.rs") && name == "plan" {
        return WalkClass::Fact(DescribeFact::ItemHash(item_values::field_order()));
    }
    if ends_with_path(file, "hir-ty/src/drop.rs") && name == "destructor" {
        return match arg::<AdtId>(db, key) {
            Some(adt) => WalkClass::Fact(DescribeFact::ItemHash(FactRef {
                kind: blaze_items::kinds::DROP_CHECK,
                subject: item_keys::item_key(db, ItemId::Adt(adt)).0,
                object: FactObject::None,
            })),
            None => WalkClass::Refused,
        };
    }
    if ends_with_path(file, "hir-def/src/attrs.rs") && name == "AttrFlags::query" {
        return match arg::<AttrDefId>(db, key).and_then(|o| item_values::attrs(db, o)) {
            Some(fact) => WalkClass::Fact(DescribeFact::ItemHash(fact)),
            None => WalkClass::Refused,
        };
    }
    if ends_with_path(file, "hir-def/src/lang_item.rs") && name == "lang_items" {
        return match arg::<Crate>(db, key) {
            Some(krate) if krate == home => WalkClass::Covered,
            Some(krate) => WalkClass::Fact(DescribeFact::ItemHash(item_values::crate_root(db, krate))),
            None => WalkClass::Refused,
        };
    }
    if ends_with_path(file, "hir-ty/src/method_resolution.rs") && name == "loaded_crates" {
        return match arg::<Crate>(db, key) {
            Some(krate) if krate == home => WalkClass::Covered,
            Some(krate) => WalkClass::Fact(DescribeFact::ItemHash(item_values::crate_root(db, krate))),
            None => WalkClass::Refused,
        };
    }
    if let Some(fact) = Goals.fact_of(db, Some(home), read, raw_name) {
        return WalkClass::Fact(DescribeFact::ItemHash(fact));
    }
    if kind == ReadKind::Function
        && ends_with_path(file, "hir-def/src/nameres.rs")
        && let Some(hir_def::nameres::NameRead::Handle) = hir_def::nameres::name_read(db, read, kind)
    {
        return WalkClass::Covered;
    }
    WalkClass::Refused
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
    // Bodies naming files via `file!()` depend on the build's path naming; never cached here.
    if names_files(db, &instance.0) {
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

/// Extracts every portable [`DescribeFact`] from a captured `Reads` (descending through
/// `code_walk` and other derived memos via `for_each_read_through`). Returns `Err(read_name)`
/// when any read cannot be represented as a portable fact.
pub(crate) fn capture_facts(
    db: &Db,
    home: Crate,
    def: Option<DefWithBodyId>,
    reads: blaze_query::db::Reads,
) -> Result<Vec<DescribeFact>, &'static str> {
    let storage = db.storage();
    let mut facts = Vec::new(); // alloc: per describe miss, the captured facts
    let mut refused: Option<&'static str> = None;
    let asked: Cell<Option<(DatabaseKeyIndex, WalkClass)>> = Cell::new(None);
    let classify = |read: DatabaseKeyIndex, kind: ReadKind| {
        let name = storage.read_name(read, kind);
        (name, classify_read(db, home, def, read, kind, name))
    };
    let through = |&Read { key: read, kind }: &Read| {
        let (_, class) = classify(read, kind);
        asked.set(Some((read, class)));
        class == WalkClass::Through
    };
    let _ = reads.for_each_read_through(db, through, |row| {
        let Read { key: read, kind } = match row {
            RowRead::Read(read) => read,
            RowRead::Sealed(read, group) => {
                asked.set(None);
                let found = std::iter::once(&home).chain(home.transitive_deps(db)).find(|&&it| {
                    it.seal_group_of(db) == Some(group) || it.seal_root_group_of(db) == Some(group)
                });
                let Some(&krate) = found else {
                    refused = Some(storage.read_name(read.key, read.kind));
                    return ControlFlow::Break(());
                };
                facts.push(DescribeFact::ItemHash(FactRef {
                    kind: blaze_items::kinds::CRATE,
                    subject: item_keys::crate_key(db, krate),
                    object: FactObject::None,
                }));
                facts.push(DescribeFact::ItemHash(item_values::field_order()));
                match item_values::setting("borrowck_debug") {
                    Some(setting) => facts.push(DescribeFact::ItemHash(setting)),
                    None => {
                        refused = Some(storage.read_name(read.key, read.kind));
                        return ControlFlow::Break(());
                    }
                }
                return ControlFlow::Continue(());
            }
            RowRead::Stored(read) | RowRead::Unsettled(read) => {
                refused = Some(storage.read_name(read.key, read.kind));
                return ControlFlow::Break(());
            }
        };
        if kind == ReadKind::Interned {
            return ControlFlow::Continue(());
        }
        let (name, class) = match asked.take() {
            Some((of, class)) if of == read => (storage.read_name(read, kind), class),
            _ => classify(read, kind),
        };
        match class {
            WalkClass::Covered => ControlFlow::Continue(()),
            WalkClass::Fact(fact) => {
                facts.push(fact);
                ControlFlow::Continue(())
            }
            WalkClass::Through | WalkClass::Refused => {
                refused = Some(name);
                ControlFlow::Break(())
            }
        }
    });
    if let Some(name) = refused {
        return Err(name);
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
    //    Wrap the lookup in `witnesses::witnessed` so that if a traced record hits, every
    //    database read made to compute the base key and validate the read-list is posted to
    //    `witnesses.describes` for subsequent warm edits in the same daemon.
    let world_active = front.devirt.world().is_some();
    let base_and_hit = match &front.witnesses {
        Some(witnesses) => {
            let mut hit_info: Option<(
                Base<'db>,
                Result<Option<Described<HirInstance, HirStatic>>, CodegenError>,
            )> = None;
            let mut lookup_res = None;
            let run = || {
                let Some(base) = base_of(front, db, instance, requester) else {
                    return None;
                };
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
                let decoded = match found {
                    Ok(RecordFound::Hit { answer, key, .. }) => {
                        let res = open_answer(&answer, &key)
                            .and_then(|payload| {
                                decode_described(db, requester, payload, |callee, c| {
                                    // Only populate `found.counted` for sealed callees whose count
                                    // cannot change on a later workspace edit in this daemon.
                                    if let Kind::Code(_, env) = &callee.0
                                        && hir_def::deps::sealed(db, env.krate)
                                        && let Some(found) = &front.found
                                    {
                                        found.counted.pin().insert(callee.clone(), c);
                                    }
                                })
                            })
                            .map_err(|why| unread(key, why));
                        match res {
                            // When a closed devirt world is active, a `world = None` record is
                            // valid iff `takes_world == false` (the world has no effect on it).
                            Ok(desc) if world_active && desc.takes_world => Ok(None),
                            Ok(desc) => Ok(Some(desc)),
                            Err(err) => Err(err),
                        }
                    }
                    Ok(RecordFound::Miss { .. }) => Ok(None),
                    Err(err) => Err(unread(base.base, err.to_string())),
                };
                Some((base, decoded))
            };
            let note = |res: &Option<(
                Base<'db>,
                Result<Option<Described<HirInstance, HirStatic>>, CodegenError>,
            )>,
                        reads: &mut [u64],
                        complete: bool| {
                if let Some((_, Ok(Some(desc)))) = res {
                    let key = (instance.clone(), *requester, front.facing(None));
                    let value = witnesses::digest(&Ok::<_, &CodegenError>(desc));
                    witnesses.describes.note(&key, reads, complete, value);
                }
            };
            let res = witnesses::witnessed(db, run, note);
            if let Some((base, decoded)) = res {
                match decoded {
                    Ok(Some(desc)) => return Ok((desc, true)),
                    Ok(None) => hit_info = Some((base, Ok(None))),
                    Err(err) => lookup_res = Some(err),
                }
            }
            if let Some(err) = lookup_res {
                return Err(err);
            }
            hit_info.map(|(b, _)| b)
        }
        None => {
            let base = base_of(front, db, instance, requester);
            if let Some(base) = base {
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
                            .and_then(|payload| decode_described(db, requester, payload, |_, _| {}))
                            .map_err(|why| unread(key, why))?;
                        if !(world_active && desc.takes_world) {
                            return Ok((desc, true));
                        }
                    }
                    Ok(RecordFound::Miss { .. }) => {}
                    Err(err) => return Err(unread(base.base, err.to_string())),
                }
                Some(base)
            } else {
                None
            }
        }
    };

    // 2. Miss: describe live while capturing all reads (including `HIGH` reads and memo edges).
    let (made, captured) = describe_and_capture(front, db, instance, requester);
    let described = made?;

    // 3. If eligible, not world-dependent, and all captured reads classify into portable facts,
    //    file the read-list and answer via `blaze_record`.
    let Some(base) = base_and_hit else {
        return Ok((described, false));
    };
    if world_active && described.takes_world {
        return Ok((described, false));
    }
    let Some(reads) = captured else {
        return Ok((described, false));
    };
    let Ok(facts) = capture_facts(db, base.home, base.def, reads) else {
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

/// Runs `HirFrontend::described` inside both `witnesses::witnessed` (so warm-edit witnesses
/// stay populated) and `capture_reads` (so every read, including `HIGH` reads and memo edges,
/// is captured for the traced record).
fn describe_and_capture(
    front: &HirFrontend<'_>,
    db: &Db,
    instance: &HirInstance,
    requester: &Origin,
) -> (Result<Described<HirInstance, HirStatic>, CodegenError>, Option<blaze_query::db::Reads>) {
    let run = || {
        let names = names_files(db, &instance.0);
        let key_world = front.key_world(db, instance);
        let world = if names { front.devirt.world() } else { key_world };
        let (made, captured) =
            capture_reads(db, || front.described(db, instance, requester, world));
        (names, key_world, made, captured)
    };
    let Some(witnesses) = &front.witnesses else {
        let (_, _, made, captured) = run();
        return (made, captured);
    };
    type Made = (
        bool,
        Option<hir_ty_mir::mir::devirt::DevirtWorld>,
        Result<Described<HirInstance, HirStatic>, CodegenError>,
        Option<blaze_query::db::Reads>,
    );
    let note = |(names, key_world, made, _): &Made, reads: &mut [u64], complete: bool| {
        let key = (instance.clone(), *requester, front.facing(*key_world));
        let value = witnesses::digest(made);
        witnesses.describes.note(&key, reads, complete && !*names, value);
    };
    let (_, _, made, captured) = witnesses::witnessed(db, run, note);
    (made, captured)
}
