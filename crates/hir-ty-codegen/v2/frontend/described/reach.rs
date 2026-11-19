//! What sealed code reaches, as one store record a place the walk enters it
//! (docs/v2/plan/design/store.md, "Describe records"; backlog B11).
//!
//! A describe record ([`super`]) saves a describe, never the walk: a second project on a warm
//! home, a restarted daemon and a new home with the machine's layer installed each made the
//! record key of every function of the standard library the program reaches (its instance
//! ported, its home's closure and image looked up, hashed) and read the store once for each:
//! 4.6 s of `codegen walk` for hello world's 5,225 functions (`notes/lanes/mir.md`), with no
//! describe run.
//!
//! **The record.** For a sealed function `entry` asked by `requester`, every describe the walk
//! reaches from it through sealed code that a describe record can hold: one ported buffer
//! for all of them, then each describe with the place of the one that first refers to it.
//! A function another reaches it by is asked by that one's origin, as the walk asks it, so a
//! describe's requester is its parent's origin and the entry's is `requester`: nothing of a
//! requester's name is written, and two programs whose entries are asked alike write the same
//! bytes.
//!
//! **The key** ([`key_of`]) is of the entry's describe record key, under this schema. That key
//! covers the entry's home's image (so every crate below it, which is every crate a describe
//! reached from it may read, by content), the stage with what the units give `requester`, and
//! the entry: what each describe it reaches reads beside that is its own requester, which is
//! `requester` or an origin of its own, whose units the stage holds by content (rule 21).
//!
//! **Read before the walk visits.** The walk reads it once, at the entry; every describe in it
//! is then the front end's ([`State::seen`]) and is given when the walk visits it, with no key
//! made and no store read. The walk still visits each function: it decides what is reached,
//! the record only says what each describe is.
//!
//! **Made once the walk ends** ([`HirFrontend::reach_records_in`]), for each entry the walk
//! asked of the store and found none for: a function a describe outside sealed code refers to,
//! or one no sealed describe does (a root). Not made where some sealed function it reaches has
//! no describe this walk read or made (past the recursion limit, or taken from a kept walk):
//! the record would hold less than the reach, and another builder of the same key more.

use std::sync::Arc;

use blaze_codegen::driver::{Put, RECORD_KIND};

use super::*;

/// The domain of a reach record's schema.
const REACH_DOMAIN: &str = "blaze v2 sealed reach record 1";

/// The version of a reach record's own bytes.
const REACH_LAYOUT: u64 = 1;

/// The first bytes of a reach record: one of another layout is refused by name.
const REACH_MAGIC: &[u8; 8] = b"bzrch001";

/// The schema of a reach record: of its own layout and of the describe records' (whose body it
/// holds) and the ports' (whose buffer it holds).
const REACH_SCHEMA: SchemaHash = schema_of(&[
    Part::Str(REACH_DOMAIN),
    Part::U64(REACH_LAYOUT),
    Part::Schema(SCHEMA),
    Part::Schema(port::SCHEMA),
]);

/// The most describes one record holds (rule 18): the standard library's reach from any one
/// place is about 6,000 for hello world; a reach past this is made no record of.
const MOST: usize = 1 << 18;

/// The parent of the entry, which none refers to.
const NO_PARENT: u32 = u32::MAX;

/// The key of the reach record of the function whose describe record is under `describe`.
pub(super) fn key_of(producer: ContentId, describe: &Key) -> Key {
    Key::of(REACH_SCHEMA, producer, &[describe.0])
}

/// What one front end's walks read and made of sealed code, for the life of the front end
/// (one build).
pub(crate) struct State {
    /// Each sealed describe a record can hold that this front end read (from a reach record or
    /// a describe record) or made, by the instance and who asked: given to the walk in place of
    /// a lookup, and what the reach records made at the walk's end hold. Never one made against
    /// a program's dyn facts.
    seen: SharedMap<(HirInstance, Origin), Arc<Described<HirInstance, HirStatic>>>,
    /// The sealed functions whose reach record the store did not have, with the key of their
    /// describe record, in the order asked: what a reach record may be made for.
    missed: Lock<Vec<((HirInstance, Origin), Key)>>,
    /// The sealed functions a describe outside sealed code refers to, as the walk asks them:
    /// where it enters sealed code.
    entered: blaze_hash::SharedSet<(HirInstance, Origin)>,
    /// The describe records of sealed code this front end made, for the machine's layer.
    made: Lock<Vec<Put>>,
}

impl Default for State {
    fn default() -> Self {
        State {
            seen: SharedMap::default(),
            missed: Lock::new("codegen.reach.missed", Vec::new()),
            entered: blaze_hash::SharedSet::default(),
            made: Lock::new("codegen.reach.made", Vec::new()),
        }
    }
}

impl State {
    /// The describe of `asked` this front end read or made, if it has it.
    pub(super) fn seen(
        &self,
        asked: &(HirInstance, Origin),
    ) -> Option<Arc<Described<HirInstance, HirStatic>>> {
        self.seen.pin().get(asked).cloned() // clone: a reference count
    }

    /// Keeps `described`, the world-free describe of `asked`, for the walk and the records.
    pub(super) fn saw(&self, asked: (HirInstance, Origin), described: Described<HirInstance, HirStatic>) {
        // alloc: once per sealed function a walk reads or makes, its describe shared
        self.seen.pin().get_or_insert_with(asked, || Arc::new(described));
    }

    /// That the store had no reach record of `asked`, whose describe record is under `key`.
    pub(super) fn missed(&self, asked: (HirInstance, Origin), key: Key) {
        self.missed.lock().push((asked, key));
    }

    /// That a describe outside sealed code, of `origin`, refers to `refs`.
    pub(super) fn entered(&self, origin: Origin, refs: &[FrontRef<HirInstance, HirStatic>]) {
        let entered = self.entered.pin();
        for it in refs {
            if let FrontRef::Function(callee) = it {
                // clone: the set's key, a few `Copy` ids in a `Clone`-only type
                entered.insert((callee.clone(), origin));
            }
        }
    }

    /// A describe record of sealed code made, for the machine's layer.
    pub(super) fn made(&self, put: Put) {
        self.made.lock().push(put);
    }
}

impl<'db> HirFrontend<'db> {
    /// Reads the reach record of `entry` asked by `requester`, whose describe record is under
    /// `describe`, into [`State::seen`]: each describe it holds that the front end has not.
    /// Whether the store had one; `Err` names why what it had does not read, which is the
    /// build's error (a record that does not read under its key is a key that leaves an input
    /// out, rule 21, never a reason to walk without it).
    pub(super) fn read_reach(
        &self,
        db: &'db Db,
        // dyn: the store's verified reader, one lookup per place the walk enters sealed code
        records: &dyn blaze_codegen::driver::Records,
        producer: ContentId,
        describe: &Key,
        requester: &Origin,
    ) -> R<bool> {
        let key = key_of(producer, describe);
        let mut read: Option<R> = None;
        let had = records.read(&key, &mut |bytes| read = Some(self.reach_read(db, requester, bytes)))?;
        match read {
            Some(Err(why)) => {
                // alloc: the reason of a refusal
                Err(format!("the reach record under the store key {:x}: {why}", key.0))
            }
            _ => Ok(had),
        }
    }

    /// [`Self::read_reach`] of the bytes the store gave.
    fn reach_read(&self, db: &'db Db, requester: &Origin, record: &[u8]) -> R {
        let mut bytes = Reader::new(record);
        let magic = bytes.array::<8>()?;
        if magic != REACH_MAGIC {
            // alloc: the reason of a refusal
            return Err(format!("its first bytes are {magic:?}, not `bzrch001`: a record of another layout"));
        }
        let ported = Aligned::copy_from(bytes.bytes_u32()?);
        let mut ported = port::Reader::open(
            db,
            DbInterner::new_no_crate(db),
            &ported,
            &mut |name| item_named(db, name),
        )?;
        let count = bytes.u32()? as usize;
        if count == 0 || count > MOST {
            // alloc: the reason of a refusal
            return Err(format!("it holds {count} describes, not 1 to {MOST}"));
        }
        let found = self.found.as_ref();
        // The origin each describe gives what it refers to, by place: what the next one's
        // requester is read by.
        // alloc: per reach record read, an origin a describe
        let mut origins: Vec<Origin> = Vec::with_capacity(count);
        for at in 0..count {
            let parent = bytes.u32()?;
            let asked_by = match parent {
                NO_PARENT if at == 0 => *requester,
                parent if (parent as usize) < at => origins[parent as usize],
                // alloc: the reason of a refusal
                parent => return Err(format!("describe {at} has the parent {parent}, not one before it")),
            };
            let tag = bytes.u8()?;
            let instance = get_instance(db, &mut ported, &mut bytes, tag)?;
            let body = bytes.bytes_u32()?;
            let asked = (instance, asked_by);
            if let Some(have) = self.reach.seen(&asked) {
                origins.push(have.origin);
                continue;
            }
            let mut body = Reader::new(body);
            let described = decode_body(db, &asked_by, &mut ported, &mut body, |callee, counted| {
                if let Some(found) = found {
                    // clone: the map's key, once per reference of a describe read
                    found.counted.pin().insert(callee.clone(), counted);
                }
            })?;
            body.finish()?;
            origins.push(described.origin);
            self.reach.saw(asked, described);
        }
        bytes.finish()?;
        Ok(())
    }

    /// The records of [`State`] for the machine's layer ([`Frontend::walk_records`]): the
    /// describe records made, then a reach record of each entry the store had none of.
    pub(crate) fn reach_records_in(&self, db: &'db Db, shared: &mut Vec<Put>) {
        shared.append(&mut *self.reach.made.lock());
        let missed = std::mem::take(&mut *self.reach.missed.lock());
        if missed.is_empty() {
            return;
        }
        let Some((producer, stage)) = self.record_stage_for_trace() else { return };
        // What sealed describes refer to: a function only these reach is entered through them,
        // and a record of it would be a part of theirs.
        // alloc: once a walk that missed a reach record, a key per sealed reference
        let mut fed = blaze_hash::HashSet::new_in(Global);
        for (_, described) in self.reach.seen.pin().iter() {
            for it in &described.refs {
                if let FrontRef::Function(callee) = it {
                    // clone: the set's key, a few `Copy` ids in a `Clone`-only type
                    fed.insert((callee.clone(), described.origin));
                }
            }
        }
        let entered = self.reach.entered.pin();
        for (asked, describe) in missed {
            if fed.contains(&asked) && !entered.contains(&asked) {
                continue;
            }
            if let Some(bytes) = self.reach_written(db, &asked, Some((producer, stage))) {
                shared.push(Put { key: key_of(producer, &describe), kind: RECORD_KIND, bytes, of: None });
            }
        }
    }

    /// The reach record of `entry` from [`State::seen`]; `None` where it has no describe of
    /// `entry`, where a sealed function it reaches that a record could hold has none (the
    /// record would hold less than the reach), where some part has no portable form, or past
    /// [`MOST`].
    fn reach_written(
        &self,
        db: &'db Db,
        entry: &(HirInstance, Origin),
        stage: Option<(ContentId, ContentId)>,
    ) -> Option<Vec<u8>> {
        let (_, closure) = Self::sealed(db, &entry.0)?;
        // The reach, in the order a breadth-first walk from the entry first finds each, with
        // the place of the describe it was found by.
        // alloc: per reach record made, its describes and their places
        let mut order: Vec<((HirInstance, Origin), u32, Arc<Described<HirInstance, HirStatic>>)> =
            Vec::new();
        let mut place = blaze_hash::HashMap::new_in(Global);
        // clone: the walk's handle of the entry
        order.push((entry.clone(), NO_PARENT, self.reach.seen(entry)?));
        place.insert(entry.clone(), 0u32); // clone: as above
        let mut at = 0;
        while at < order.len() {
            let described = order[at].2.clone(); // clone: a reference count
            for it in &described.refs {
                let FrontRef::Function(callee) = it else { continue };
                // clone: the map's key, a few `Copy` ids in a `Clone`-only type
                let asked = (callee.clone(), described.origin);
                if place.contains_key(&asked) {
                    continue;
                }
                match self.reach.seen(&asked) {
                    Some(it) => {
                        place.insert(asked.clone(), order.len() as u32); // clone: as above
                        order.push((asked, at as u32, it));
                    }
                    // One a describe record could hold and none was read or made: the walk
                    // did not describe it here.
                    None if self.sealed_key_with_stage(db, &asked.0, &asked.1, stage).is_some() => {
                        return None;
                    }
                    None => {}
                }
            }
            if order.len() > MOST {
                return None;
            }
            at += 1;
        }
        let mut writer = port::Writer::new(db, DbInterner::new_no_crate(db));
        // alloc: per reach record made, its describes' bytes
        let mut out = Vec::with_capacity(order.len() * 512);
        // alloc: per reach record made, one describe's bytes at a time
        let mut body = Vec::with_capacity(512);
        for ((instance, asked_by), parent, described) in &order {
            let own = self.own_origin(db, instance);
            if described.origin != own.unwrap_or(*asked_by) {
                return None;
            }
            out.put_u32(*parent);
            put_instance(&closure, &mut writer, &mut out, instance)?;
            body.clear();
            encode_body(db, &closure, &mut writer, &mut body, own.as_ref(), described)?;
            out.put_bytes_u32(&body);
        }
        let ported = writer.finish(&mut |item| closure.name(item)).ok()?;
        // alloc: per reach record made, its bytes
        let mut record = Vec::with_capacity(REACH_MAGIC.len() + 8 + ported.len() + out.len());
        record.put_bytes(REACH_MAGIC);
        record.put_bytes_u32(&ported);
        record.put_u32(u32::try_from(order.len()).ok()?);
        record.extend_from_slice(&out);
        Some(record)
    }
}
