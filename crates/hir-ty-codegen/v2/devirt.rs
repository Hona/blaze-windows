//! The whole program's trait objects, for `hir-ty-mir`'s `Devirtualize`
//! (docs/v2/plan/design/devirt.md). Each walked body lists what it does with trait
//! objects ([`Facts`], found by [`super::refs`] beside its references); once the walk of a
//! final binary has reached everything, it hands what it reached to [`State::closed`], which
//! makes the program's [`World`] of them, and the walk runs again (`blaze_codegen::driver`)
//! with the bodies that call through a `dyn` built against it, whose new references (the
//! direct callees) it then lists.
//!
//! What makes an object's list of types closed: the program is an executable or a test (a
//! `cdylib`'s every object is open: a program that loads it may make more), no code of a
//! crate other than the library's names a dynamic loader (`dlopen`, `LoadLibrary`), no
//! signature at the program's edge (a foreign function, a definition with another ABI than
//! Rust's, or a static of an `extern` block) carries the object type, and every place that
//! makes a vtable is visited: the walk's IR resolution makes each vtable the code of any
//! reached instance or static can point to (`FunctionCx::vtable`), so its requests are all of
//! them. An upcast hands the supertrait's object the subtrait's types, which may point to the
//! subtrait's vtable (`Upcast::Same`), so the supertrait's list takes the subtrait's, and its
//! openness.

use std::{
    alloc::Global,
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use base_db::{Crate, Db};
use blaze_codegen::{
    CodegenError, InstanceKey, Owner,
    backend::{FrontRef, WorldChange, WorldPatch},
    driver::support::{self, ALL},
    plan::Origin,
    slot::Slot,
};
use blaze_core::lock::Lock;
use blaze_ids::{ContentId, Hasher};
use blaze_items::{ItemId, ItemKey};
use hir_def::{CallableDefId, HasModule, ItemContainerId, TraitId, signatures::TraitSignature};
use hir_ty::{
    next_solver::{
        GenericArgs, ParamEnv, StoredGenericArgs, StoredTy, Ty, TyKind, infer::InferCtxt,
    },
    traits::StoredParamEnvAndCrate,
};
use hir_ty_mir::mir::{
    MirBody, TerminatorKind,
    devirt::{self, DevirtWorld, Held, Object, ObjectKey, Target, World},
};
use rustc_type_ir::inherent::IntoKind as _;

use super::{Hashes as _, HirFrontend, HirInstance, HirStatic, Kind, RootKind, build::Build, refs};
use crate::{Instance, InstanceDef};

const ARGS_DOMAIN: &str = "blaze v2 devirt object args 1";
const CODE_DOMAIN: &str = "blaze v2 devirt code 1";

/// The symbols that load code at run time: a program that calls one may get objects whose
/// vtables it never made.
const LOADERS: &[&str] =
    &["dlopen", "dlmopen", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"];

/// What one walked body does with trait objects, each once, in the order found.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub(crate) struct Facts {
    /// The vtables its IR makes: the type and the object type.
    pub(crate) vtables: Vec<(StoredTy, ObjectKey)>,
    /// The upcasts its IR makes, of the first object type to the second.
    pub(crate) upcasts: Vec<(ObjectKey, ObjectKey)>,
    /// The object types a signature at the program's edge carries, or the type of a static
    /// of an `extern` block it reads: code outside the program may make or take them.
    pub(crate) foreign: Vec<ObjectKey>,
}

impl Facts {
    pub(crate) fn is_empty(&self) -> bool {
        self.vtables.is_empty() && self.upcasts.is_empty() && self.foreign.is_empty()
    }

    /// A vtable request of the IR ([`crate::fragment::DataRequest::Vtable`]), whose trait
    /// reference holds Self first.
    pub(crate) fn vtable(&mut self, ty: &StoredTy, trait_: TraitId, args: &StoredGenericArgs) {
        let after_self = GenericArgs::new_from_slice(&args.as_ref().as_slice()[1..]);
        let key = ObjectKey { trait_, args: after_self.store() };
        if !self.vtables.iter().any(|(theirs, their_key)| theirs == ty && *their_key == key) {
            // clone: a reference count, once per vtable a body makes
            self.vtables.push((ty.clone(), key));
        }
    }

    /// An upcast of a `from` object to a `to` one, which both have a principal: the walk's
    /// `unsize_metadata`.
    pub(crate) fn upcast<'db>(
        &mut self,
        infcx: &InferCtxt<'db>,
        env: ParamEnv<'db>,
        (from, to): (Ty<'db>, Ty<'db>),
    ) {
        let interner = infcx.interner;
        let key = |ty| {
            devirt::principal_of(interner, ty, ty).map(|it| devirt::object_key(infcx, env, it))
        };
        let (Some(from), Some(to)) = (key(from), key(to)) else { return };
        if from != to && !self.upcasts.contains(&(from, to)) {
            self.upcasts.push((from, to));
        }
    }

    /// The object types `ty` names, as a signature at the program's edge carries them.
    pub(crate) fn foreign<'db>(&mut self, infcx: &InferCtxt<'db>, env: ParamEnv<'db>, ty: Ty<'db>) {
        let interner = infcx.interner;
        for inner in ty.walk().filter_map(|it| it.ty()) {
            if !matches!(inner.kind(), TyKind::Dynamic(..)) {
                continue;
            }
            let Some(principal) = devirt::principal_of(interner, inner, inner) else { continue };
            let key = devirt::object_key(infcx, env, principal);
            if !self.foreign.contains(&key) {
                self.foreign.push(key);
            }
        }
    }
}

/// The walk of an instance's body with the program's world (`refs::Walking`): `world` where
/// the body takes it ([`takes_world`]); else the walk without one, so a body with nothing to
/// devirtualize is walked and keyed as it is in every program.
pub(crate) fn walking(
    db: &Db,
    world: Option<DevirtWorld>,
    instance: &HirInstance,
    inlined: bool,
    owner: impl FnOnce() -> Owner,
) -> Result<refs::Walking, String> {
    let plain = refs::Walking::plain(inlined);
    let Some(world) = world else { return Ok(plain) };
    match takes_world(db, instance, inlined, owner)? {
        true => Ok(refs::Walking { inlined, world: Some(world) }),
        false => Ok(plain),
    }
}

/// Whether a body of `instance` is built against the program's world, the one rule for it:
/// both what a walk takes ([`walking`]) and whether a program has a world to build at all
/// ([`world_of`]). It is so when `inlined` (only a body at MIR level 2 with the inliner on is
/// devirtualized), the instance is a function or closure of a crate other than the library's
/// (whose bodies are one for every program), it is the workspace's (`owner`, asked only
/// then: the dependency image's code is one for every program its dependencies build, and
/// built against the world a call through a `dyn` made direct to the program's one type,
/// hashbrown's `resize_inner` calling the `reserve_rehash` closure of a map keyed by a
/// member's type, would refer to the workspace's code from the image; a build that links no
/// image owns every crate but the library's), and its body calls through a `dyn`
/// ([`has_sites`]).
pub(crate) fn takes_world(
    db: &Db,
    instance: &HirInstance,
    inlined: bool,
    owner: impl FnOnce() -> Owner,
) -> Result<bool, String> {
    let Kind::Code(code, env) = &instance.0 else { return Ok(false) };
    let ours = inlined
        && matches!(code.def, InstanceDef::Fn(_) | InstanceDef::Closure(_))
        && super::frontend::crate_of(db, &instance.0)
            .is_some_and(|it| !it.data(db).origin.is_lang());
    if !ours || owner() != Owner::Workspace {
        return Ok(false);
    }
    // clone: the query's keys by value, each a few `Copy` ids in a `Clone`-only type
    has_sites(db, code.clone(), env.clone()).clone()
}

/// Whether the body of `instance` as any of [`Build::WALKS_INLINED`] builds it calls a trait
/// method through a `dyn`: what `Devirtualize` looks at.
#[blaze_query::tracked]
pub(crate) fn has_sites(
    db: &Db,
    instance: Instance,
    env: StoredParamEnvAndCrate,
) -> Result<bool, String> {
    for build in Build::WALKS_INLINED {
        // clone: the query's keys by value, two `Copy` ids in a `Clone`-only type
        let body = crate::instance_body(db, &instance, env.clone(), Some(build))
            .map_err(|it| it.to_string())?;
        if sites(db, &body) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sites(db: &Db, body: &MirBody<'_>) -> bool {
    body.basic_blocks.iter().any(|(_, block)| {
        let Some(TerminatorKind::Call { func, .. }) = block.terminator.as_ref().map(|it| &it.kind)
        else {
            return false;
        };
        let Some((CallableDefId::FunctionId(method), args)) = func.fn_def() else { return false };
        matches!(method.loc(db).container, ItemContainerId::TraitId(_))
            && args
                .as_slice()
                .first()
                .and_then(|it| it.ty())
                .is_some_and(|it| matches!(it.kind(), TyKind::Dynamic(..)))
    })
}

/// `code`, the code hash of an instance's body, with the facts its body read of the world
/// (`MirBody::inlined.devirtualized`, as [`refs::read`] lists them): the key of what was
/// built against them (rule 21). A body that read none keeps its code.
pub(crate) fn code(code: blaze_items::CodeHash, read: &[[u8; 32]]) -> blaze_items::CodeHash {
    if read.is_empty() {
        return code;
    }
    let mut hasher = Hasher::new(CODE_DOMAIN);
    hasher.id(&code.0).update(&(read.len() as u64).to_le_bytes());
    for digest in read {
        hasher.update(digest);
    }
    blaze_items::CodeHash(hasher.finish())
}

/// What a build's front end knows of the program it walks, for its world: written once
/// ([`Slot`]) and read with no lock, as every describe of the walk reads the world on every
/// core at once. What the walk reached is the walk's own, handed to [`State::closed`] whole
/// and in the walk's order when it ends.
pub(crate) struct State {
    /// What the unit makes, from its roots ([`HirFrontend::roots`]): unset before.
    makes: Slot<(RootKind, Crate)>,
    /// The world the program's bodies are built against, held from the end of its first walk
    /// ([`State::closed`]): unset before, and for a program that has none.
    held: Slot<Held>,
    plain: Slot<Arc<WorldSet>>,
    closed_members: Slot<Arc<WorldSet>>,
    closed_consumers: Slot<Arc<ConsumerIndex>>,
    /// Lock-free world handle installed by [`Self::resume`] for worker threads reading
    /// [`Self::world`].
    resumed_world: Slot<Held>,
    /// Mutable working checkpoint held only between [`Self::resume`], [`Self::finish_patch`]
    /// and [`Self::checkpoint`] on the single build patching a kept walk.
    resumed_state: Lock<Option<ResumedState>>,
    using_resumed: AtomicBool,
}

impl Default for State {
    fn default() -> Self {
        State {
            makes: Slot::default(),
            held: Slot::default(),
            plain: Slot::default(),
            closed_members: Slot::default(),
            closed_consumers: Slot::default(),
            resumed_world: Slot::default(),
            resumed_state: Lock::new("codegen.devirt.resumed", None),
            using_resumed: AtomicBool::new(false),
        }
    }
}

/// The exact inputs of the two successful closures, plus the per-object consumer index and
/// incremental plain-walk reachability graph, scoped to the kept walk's database.
#[derive(Clone)]
pub struct Checkpoint {
    makes: (RootKind, Crate),
    program: Box<str>,
    held: Held,
    plain: Arc<WorldSet>,
    plain_graph: Option<Arc<PlainGraph>>,
    closed: Arc<WorldSet>,
    consumers: Arc<ConsumerIndex>,
}

#[cfg(test)]
impl Checkpoint {
    pub(super) fn closed_functions_for_test(&self) -> Vec<(HirInstance, Origin)> {
        self.closed.functions.keys().cloned().collect()
    }
}

struct ResumedState {
    checkpoint: Checkpoint,
    world_changed: bool,
    /// Functions in `kept.closed` whose `contribution` query changed since the kept view.
    changed_closed_fns: Vec<(HirInstance, Origin)>,
    /// Statics in `kept.closed` whose `static_contribution` query changed since the kept view.
    changed_closed_statics: Vec<HirStatic>,
    /// Consumers asked to re-verify because an object they read changed.
    reverified_consumers: Vec<(HirInstance, Origin)>,
}

/// One round's reached items and an index of only those that contribute trait-object facts or
/// consume the world: updating a few items and recomputing the world costs the contributors,
/// not the whole program.
#[derive(Clone, Default, PartialEq, Eq)]
struct WorldSet {
    functions: HashMap<(HirInstance, Origin), Arc<Contribution>>,
    statics: HashMap<HirStatic, Arc<StaticContribution>>,
    fn_contributors: HashMap<(HirInstance, Origin), Arc<Contribution>>,
    static_contributors: HashMap<HirStatic, Arc<StaticContribution>>,
    site_count: usize,
}

impl WorldSet {
    fn from_maps(
        functions: HashMap<(HirInstance, Origin), Arc<Contribution>>,
        statics: HashMap<HirStatic, Arc<StaticContribution>>,
    ) -> WorldSet {
        let mut fn_contributors = HashMap::new();
        let mut site_count = 0;
        for (asked, c) in &functions {
            if c.sites {
                site_count += 1;
            }
            if c.contributes() {
                fn_contributors.insert(asked.clone(), c.clone());
            }
        }
        let mut static_contributors = HashMap::new();
        for (s, c) in &statics {
            if c.contributes() {
                static_contributors.insert(*s, c.clone());
            }
        }
        WorldSet { functions, statics, fn_contributors, static_contributors, site_count }
    }

    /// Inserts or replaces a function's contribution. Returns `true` if any world-relevant
    /// input (`sites`, `facts`, `loader`, `foreign`, `objects`) changed.
    fn insert_fn(&mut self, asked: (HirInstance, Origin), now: Arc<Contribution>) -> bool {
        let was = self.functions.insert(asked.clone(), now.clone());
        let had_sites = was.as_ref().is_some_and(|it| it.sites);
        if had_sites && !now.sites {
            self.site_count = self.site_count.saturating_sub(1);
        } else if !had_sites && now.sites {
            self.site_count += 1;
        }
        let dirty = match &was {
            Some(old) => !old.same_world_inputs(&now),
            None => now.sites || now.contributes(),
        };
        if now.contributes() {
            self.fn_contributors.insert(asked, now);
        } else {
            self.fn_contributors.remove(&asked);
        }
        dirty
    }

    fn remove_fn(&mut self, asked: &(HirInstance, Origin)) -> bool {
        let Some(old) = self.functions.remove(asked) else {
            return false;
        };
        if old.sites {
            self.site_count = self.site_count.saturating_sub(1);
        }
        self.fn_contributors.remove(asked);
        old.sites || old.contributes()
    }

    fn insert_static(&mut self, s: HirStatic, now: Arc<StaticContribution>) -> bool {
        let was = self.statics.insert(s, now.clone());
        let dirty = match &was {
            Some(old) => !old.same_world_inputs(&now),
            None => now.contributes(),
        };
        if now.contributes() {
            self.static_contributors.insert(s, now);
        } else {
            self.static_contributors.remove(&s);
        }
        dirty
    }

    fn remove_static(&mut self, s: &HirStatic) -> bool {
        let Some(old) = self.statics.remove(s) else {
            return false;
        };
        self.static_contributors.remove(s);
        old.contributes()
    }
}

/// Which closed-walk consumer functions read each [`ObjectKey`] (including `ABSENT` lookups),
/// so a change to one trait object re-verifies only the consumers that read it.
#[derive(Clone, Default, PartialEq, Eq)]
struct ConsumerIndex {
    by_fn: HashMap<(HirInstance, Origin), Vec<ObjectKey>>,
    by_object: HashMap<ObjectKey, Vec<(HirInstance, Origin)>>,
}

impl ConsumerIndex {
    fn set(&mut self, asked: (HirInstance, Origin), keys: Vec<ObjectKey>) {
        if let Some(old) = self.by_fn.get(&asked)
            && *old == keys
        {
            return;
        }
        self.remove(&asked);
        if keys.is_empty() {
            return;
        }
        for &key in &keys {
            self.by_object.entry(key).or_default().push(asked.clone());
        }
        self.by_fn.insert(asked, keys);
    }

    fn remove(&mut self, asked: &(HirInstance, Origin)) {
        let Some(old) = self.by_fn.remove(asked) else {
            return;
        };
        for key in old {
            if let Some(list) = self.by_object.get_mut(&key) {
                list.retain(|it| it != asked);
                if list.is_empty() {
                    self.by_object.remove(&key);
                }
            }
        }
    }

    fn consumers_of(
        &self,
        changed: &blaze_hash::HashSet<ObjectKey, Global>,
    ) -> Vec<(HirInstance, Origin)> {
        let mut out = Vec::new();
        let mut seen = blaze_hash::HashSet::new_in(Global);
        for key in changed {
            if let Some(list) = self.by_object.get(key) {
                for asked in list {
                    if seen.insert(asked.clone()) {
                        out.push(asked.clone());
                    }
                }
            }
        }
        out
    }
}

#[derive(Clone)]
enum PlainNode {
    Function((HirInstance, Origin)),
    Static(HirStatic),
}

/// Incremental DRed reachability graph for the plain walk (Round 1, `world = None`), built
/// lazily on the first edit that changes plain edges and reused across subsequent edits.
#[derive(Clone)]
struct PlainGraph {
    graph: support::Graph,
    nodes: Vec<Option<PlainNode>>,
    functions: HashMap<(HirInstance, Origin), u32>,
    statics: HashMap<HirStatic, u32>,
}

/// Cap on newly reached plain-walk items discovered inside one incremental `resume_world`
/// update (rule 18): a runaway monomorphization edit falls back to the whole walk and its
/// full recursion-limit check.
const PLAIN_GROWTH_CAP: usize = 4096;

impl PlainGraph {
    fn place(&mut self) -> u32 {
        let item = self.graph.add();
        if self.nodes.len() <= item as usize {
            self.nodes.resize_with(item as usize + 1, || None);
        }
        item
    }

    fn build(
        plain: &WorldSet,
        fn_roots: &[(HirInstance, Origin)],
        static_roots: &[HirStatic],
    ) -> Result<PlainGraph, &'static str> {
        let total = plain.functions.len() + plain.statics.len();
        let mut pg = PlainGraph {
            graph: support::Graph::default(),
            nodes: Vec::with_capacity(total),
            functions: HashMap::with_capacity(plain.functions.len()),
            statics: HashMap::with_capacity(plain.statics.len()),
        };
        for asked in plain.functions.keys() {
            let item = pg.place();
            pg.functions.insert(asked.clone(), item);
            pg.nodes[item as usize] = Some(PlainNode::Function(asked.clone()));
        }
        for &s in plain.statics.keys() {
            let item = pg.place();
            pg.statics.insert(s, item);
            pg.nodes[item as usize] = Some(PlainNode::Static(s));
        }
        for (asked, c) in &plain.functions {
            let item = pg.functions[asked];
            let mut outs = Vec::with_capacity(c.edges.len());
            for r in &c.edges {
                match r {
                    FrontRef::Function(callee) => {
                        let target = pg
                            .functions
                            .get(&(callee.clone(), c.origin))
                            .copied()
                            .ok_or("a kept plain edge target is absent from the plain checkpoint")?;
                        outs.push(target);
                    }
                    FrontRef::Static(s) => {
                        let target = pg
                            .statics
                            .get(s)
                            .copied()
                            .ok_or("a kept plain static edge is absent from the plain checkpoint")?;
                        outs.push(target);
                    }
                    FrontRef::Extern(_) | FrontRef::Weak(_) => {}
                }
            }
            pg.graph.set_outs(item, outs);
        }
        for (s, c) in &plain.statics {
            let item = pg.statics[s];
            let mut outs = Vec::with_capacity(c.edges.len());
            for r in &c.edges {
                match r {
                    FrontRef::Function(callee) => {
                        let target = pg
                            .functions
                            .get(&(callee.clone(), c.origin))
                            .copied()
                            .ok_or("a kept static edge target is absent from the plain checkpoint")?;
                        outs.push(target);
                    }
                    FrontRef::Static(target_s) => {
                        let target = pg
                            .statics
                            .get(target_s)
                            .copied()
                            .ok_or("a kept static-to-static edge is absent from the plain checkpoint")?;
                        outs.push(target);
                    }
                    FrontRef::Extern(_) | FrontRef::Weak(_) => {}
                }
            }
            pg.graph.set_outs(item, outs);
        }
        for root in fn_roots {
            let item = pg
                .functions
                .get(root)
                .copied()
                .ok_or("a plain root function is absent from the plain checkpoint")?;
            pg.graph.root(ALL, item);
        }
        for root in static_roots {
            let item = pg
                .statics
                .get(root)
                .copied()
                .ok_or("a plain root static is absent from the plain checkpoint")?;
            pg.graph.root(ALL, item);
        }
        pg.graph.settle();
        for item in 0..pg.nodes.len() as u32 {
            if pg.nodes[item as usize].is_some() && !pg.graph.is_member(ALL, item) {
                return Err("the plain checkpoint holds an item unreachable from its roots");
            }
        }
        Ok(pg)
    }

    fn outs_for(
        &mut self,
        edges: &[super::places::Ref],
        origin: Origin,
        fresh_fns: &mut Vec<(u32, (HirInstance, Origin))>,
        fresh_statics: &mut Vec<(u32, HirStatic)>,
    ) -> Vec<u32> {
        let mut outs = Vec::with_capacity(edges.len());
        for r in edges {
            match r {
                FrontRef::Function(callee) => {
                    let asked = (callee.clone(), origin);
                    let item = match self.functions.get(&asked).copied() {
                        Some(item) => item,
                        None => {
                            let item = self.place();
                            self.functions.insert(asked.clone(), item);
                            self.nodes[item as usize] = Some(PlainNode::Function(asked.clone()));
                            fresh_fns.push((item, asked));
                            item
                        }
                    };
                    outs.push(item);
                }
                FrontRef::Static(s) => {
                    let item = match self.statics.get(s).copied() {
                        Some(item) => item,
                        None => {
                            let item = self.place();
                            self.statics.insert(*s, item);
                            self.nodes[item as usize] = Some(PlainNode::Static(*s));
                            fresh_statics.push((item, *s));
                            item
                        }
                    };
                    outs.push(item);
                }
                FrontRef::Extern(_) | FrontRef::Weak(_) => {}
            }
        }
        outs
    }

    fn apply_edits(
        &mut self,
        plain: &mut WorldSet,
        db: &Db,
        facing: super::frontend::Facing,
        changed_fns: &[((HirInstance, Origin), Arc<Contribution>)],
        changed_statics: &[(HirStatic, Arc<StaticContribution>)],
    ) -> Result<bool, &'static str> {
        let mut world_dirty = false;
        let mut fresh_fns = Vec::new();
        let mut fresh_statics = Vec::new();
        for (asked, now) in changed_fns {
            let Some(&item) = self.functions.get(asked) else { continue };
            let edges_changed = plain
                .functions
                .get(asked)
                .is_none_or(|was| was.edges != now.edges || was.origin != now.origin);
            if edges_changed {
                let outs =
                    self.outs_for(&now.edges, now.origin, &mut fresh_fns, &mut fresh_statics);
                self.graph.set_outs(item, outs);
            }
            world_dirty |= plain.insert_fn(asked.clone(), now.clone());
        }
        for (s, now) in changed_statics {
            let Some(&item) = self.statics.get(s) else { continue };
            let edges_changed = plain
                .statics
                .get(s)
                .is_none_or(|was| was.edges != now.edges || was.origin != now.origin);
            if edges_changed {
                let outs =
                    self.outs_for(&now.edges, now.origin, &mut fresh_fns, &mut fresh_statics);
                self.graph.set_outs(item, outs);
            }
            world_dirty |= plain.insert_static(*s, now.clone());
        }
        let mut added = 0usize;
        while !fresh_fns.is_empty() || !fresh_statics.is_empty() {
            for (item, asked) in std::mem::take(&mut fresh_fns) {
                added += 1;
                if added > PLAIN_GROWTH_CAP {
                    return Err("the plain walk grew past the incremental update cap");
                }
                let now = contribution(db, asked.0.clone(), asked.1, facing)
                    .as_ref()
                    .map_err(|_| "a newly reached function's world contribution failed")?
                    .clone();
                let outs =
                    self.outs_for(&now.edges, now.origin, &mut fresh_fns, &mut fresh_statics);
                self.graph.set_outs(item, outs);
                world_dirty |= plain.insert_fn(asked, now);
            }
            for (item, s) in std::mem::take(&mut fresh_statics) {
                added += 1;
                if added > PLAIN_GROWTH_CAP {
                    return Err("the plain walk grew past the incremental update cap");
                }
                let now = static_contribution(db, s, facing)
                    .as_ref()
                    .map_err(|_| "a newly reached static's world contribution failed")?
                    .clone();
                let outs =
                    self.outs_for(&now.edges, now.origin, &mut fresh_fns, &mut fresh_statics);
                self.graph.set_outs(item, outs);
                world_dirty |= plain.insert_static(s, now);
            }
        }
        let settled = self.graph.settle();
        for item in settled.left[ALL].iter().copied() {
            match self.nodes[item as usize].take() {
                Some(PlainNode::Function(asked)) => {
                    self.functions.remove(&asked);
                    world_dirty |= plain.remove_fn(&asked);
                }
                Some(PlainNode::Static(s)) => {
                    self.statics.remove(&s);
                    world_dirty |= plain.remove_static(&s);
                }
                None => {}
            }
        }
        Ok(world_dirty)
    }
}

impl State {
    pub(super) fn checkpoint(&self) -> Option<Checkpoint> {
        if self.using_resumed.load(Ordering::Acquire) {
            return self.resumed_state.lock().as_ref().map(|it| it.checkpoint.clone());
        }
        let held = self.held.get()?;
        Some(Checkpoint {
            makes: *self.makes.get()?,
            program: held.world().program.clone(), // clone: the program's name, once a build
            held: held.clone(),                    // clone: one reference, kept with its walk
            plain: self.plain.get()?.clone(),
            plain_graph: None,
            closed: self.closed_members.get()?.clone(),
            consumers: self.closed_consumers.get()?.clone(),
        })
    }

    pub(super) fn abandon(&self) {
        self.using_resumed.store(false, Ordering::Release);
        *self.resumed_state.lock() = None;
    }

    pub(super) fn resume(
        &self,
        front: &HirFrontend<'_>,
        kept: &Checkpoint,
        view: u64,
        fn_roots: &[(HirInstance, Origin)],
        static_roots: &[HirStatic],
    ) -> Result<WorldChange<HirInstance>, &'static str> {
        use blaze_query::db::{Changed, View};
        let (checkpoint, world_changed, changed_closed_fns, changed_closed_statics, consumers) =
            front.with(|db| {
                if self.makes.get() != Some(&kept.makes)
                    || program_name(db, kept.makes.0, kept.makes.1) != kept.program
                {
                    return Err("another program made the world checkpoint");
                }
                let since = View::from_u64(view);
                let facing = front.facing(None);
                let Changed::Keys(changed_fn_ids) = contribution::changed_since(db, since) else {
                    return Err("the changed set of world contributions is unknown");
                };
                let mut changed_plain_fns: Vec<((HirInstance, Origin), Arc<Contribution>)> =
                    Vec::new();
                let mut changed_closed_fns: Vec<(HirInstance, Origin)> = Vec::new();
                let mut plain_edges_changed = false;
                for id in changed_fn_ids {
                    let Some((i, o, id_facing)) = contribution::arguments(db, id) else {
                        return Err("a changed world contribution has no arguments");
                    };
                    if id_facing != facing {
                        continue;
                    }
                    let asked = (i, o);
                    if kept.closed.functions.contains_key(&asked) {
                        changed_closed_fns.push(asked.clone());
                    }
                    if let Some(was) = kept.plain.functions.get(&asked) {
                        let now = contribution(db, asked.0.clone(), o, facing)
                            .as_ref()
                            .map_err(|_| "a function's world contribution failed")?;
                        if !Arc::ptr_eq(now, was) && now != was {
                            if now.edges != was.edges || now.origin != was.origin {
                                plain_edges_changed = true;
                            }
                            changed_plain_fns.push((asked, now.clone()));
                        }
                    }
                }
                let Changed::Keys(changed_st_ids) = static_contribution::changed_since(db, since)
                else {
                    return Err("the changed set of static world contributions is unknown");
                };
                let mut changed_plain_statics: Vec<(HirStatic, Arc<StaticContribution>)> =
                    Vec::new();
                let mut changed_closed_statics: Vec<HirStatic> = Vec::new();
                for id in changed_st_ids {
                    let Some((s, id_facing)) = static_contribution::arguments(db, id) else {
                        return Err("a changed static world contribution has no arguments");
                    };
                    if id_facing != facing {
                        continue;
                    }
                    if kept.closed.statics.contains_key(&s) {
                        changed_closed_statics.push(s);
                    }
                    if let Some(was) = kept.plain.statics.get(&s) {
                        let now = static_contribution(db, s, facing)
                            .as_ref()
                            .map_err(|_| "a static's world contribution failed")?;
                        if !Arc::ptr_eq(now, was) && now != was {
                            if now.edges != was.edges || now.origin != was.origin {
                                plain_edges_changed = true;
                            }
                            changed_plain_statics.push((s, now.clone()));
                        }
                    }
                }

                // Fast path 0: no plain-walk contribution changed at all.
                if changed_plain_fns.is_empty() && changed_plain_statics.is_empty() {
                    return Ok((
                        kept.clone(),
                        false,
                        changed_closed_fns,
                        changed_closed_statics,
                        Vec::new(),
                    ));
                }

                // Update `plain` (and its DRed reachability graph if any edge changed).
                let mut plain = (*kept.plain).clone();
                let (world_dirty, plain_graph) = if plain_edges_changed {
                    let mut pg = match &kept.plain_graph {
                        Some(existing) => (**existing).clone(),
                        None => PlainGraph::build(&kept.plain, fn_roots, static_roots)?,
                    };
                    let dirty = pg.apply_edits(
                        &mut plain,
                        db,
                        facing,
                        &changed_plain_fns,
                        &changed_plain_statics,
                    )?;
                    (dirty, Some(Arc::new(pg)))
                } else {
                    let mut dirty = false;
                    for (asked, now) in changed_plain_fns {
                        dirty |= plain.insert_fn(asked, now);
                    }
                    for (s, now) in changed_plain_statics {
                        dirty |= plain.insert_static(s, now);
                    }
                    (dirty, kept.plain_graph.clone())
                };

                // Fast path 1: edges or non-world fields changed, but no contributor or consumer
                // status changed, so the closed world is guaranteed unchanged.
                if !world_dirty {
                    let mut next = kept.clone();
                    next.plain = Arc::new(plain);
                    next.plain_graph = plain_graph;
                    return Ok((
                        next,
                        false,
                        changed_closed_fns,
                        changed_closed_statics,
                        Vec::new(),
                    ));
                }

                // Fast path 2: rebuild the world from only the contributing items and diff per
                // object key.
                if plain.site_count == 0 {
                    return Err("no reached function takes the program's dyn facts");
                }
                let Some(new_world) = world_from_set(
                    front,
                    db,
                    (kept.makes.0, kept.program.clone()),
                    &plain,
                )?
                else {
                    return Err("no reached function takes the program's dyn facts");
                };
                if new_world.id == kept.held.world().id {
                    let mut next = kept.clone();
                    next.plain = Arc::new(plain);
                    next.plain_graph = plain_graph;
                    return Ok((
                        next,
                        false,
                        changed_closed_fns,
                        changed_closed_statics,
                        Vec::new(),
                    ));
                }
                let changed_objects = diff_objects(kept.held.world(), &new_world);
                let consumers = kept.consumers.consumers_of(&changed_objects);
                let held = devirt::give(new_world)
                    .map_err(|_| "giving the updated dyn world failed")?;
                let next = Checkpoint {
                    makes: kept.makes,
                    program: kept.program.clone(),
                    held,
                    plain: Arc::new(plain),
                    plain_graph,
                    closed: kept.closed.clone(),
                    consumers: kept.consumers.clone(),
                };
                Ok((next, true, changed_closed_fns, changed_closed_statics, consumers))
            })?;

        self.resumed_world
            .set(checkpoint.held.clone())
            .map_err(|_| "the front end already resumed a world")?;
        *self.resumed_state.lock() = Some(ResumedState {
            checkpoint,
            world_changed,
            changed_closed_fns,
            changed_closed_statics,
            reverified_consumers: consumers.clone(),
        });
        self.using_resumed.store(true, Ordering::Release);
        Ok(if world_changed {
            WorldChange::Updated { consumers }
        } else {
            WorldChange::Unchanged
        })
    }

    pub(super) fn finish_patch(
        &self,
        front: &HirFrontend<'_>,
        patch: WorldPatch<'_, HirInstance, HirStatic>,
    ) -> Result<(), &'static str> {
        let mut guard = self.resumed_state.lock();
        let Some(state) = guard.as_mut() else {
            return Err("no resumed world checkpoint to finish");
        };
        let nothing_moved = patch.changed_functions.is_empty()
            && patch.entered_functions.is_empty()
            && patch.left_functions.is_empty()
            && patch.changed_statics.is_empty()
            && patch.entered_statics.is_empty()
            && patch.left_statics.is_empty()
            && state.changed_closed_fns.is_empty()
            && state.changed_closed_statics.is_empty()
            && state.reverified_consumers.is_empty()
            && !state.world_changed;
        if nothing_moved {
            return Ok(());
        }
        let world_id = state.checkpoint.held.world().id;
        let makes = state.checkpoint.makes;
        let program = state.checkpoint.program.clone();
        let facing = front.facing(None);
        let mut closed = (*state.checkpoint.closed).clone();
        let mut consumers = (*state.checkpoint.consumers).clone();
        let mut closed_world_dirty = state.world_changed;

        let mut left_fn_set = blaze_hash::HashSet::new_in(Global);
        for asked in patch.left_functions {
            left_fn_set.insert(asked.clone());
            closed_world_dirty |= closed.remove_fn(asked);
            consumers.remove(asked);
        }
        let mut left_st_set = blaze_hash::HashSet::new_in(Global);
        for &s in patch.left_statics {
            left_st_set.insert(s);
            closed_world_dirty |= closed.remove_static(&s);
        }

        let mut refresh_fns: Vec<(HirInstance, Origin)> = Vec::new();
        let mut seen_fn = blaze_hash::HashSet::new_in(Global);
        for asked in patch
            .entered_functions
            .iter()
            .chain(patch.changed_functions.iter())
            .chain(state.changed_closed_fns.iter().filter(|it| closed.functions.contains_key(*it)))
            .chain(state.reverified_consumers.iter().filter(|it| closed.functions.contains_key(*it)))
        {
            if !left_fn_set.contains(asked) && seen_fn.insert(asked.clone()) {
                refresh_fns.push(asked.clone());
            }
        }
        let mut refresh_statics: Vec<HirStatic> = Vec::new();
        let mut seen_st = blaze_hash::HashSet::new_in(Global);
        for &s in patch
            .entered_statics
            .iter()
            .chain(patch.changed_statics.iter())
            .chain(state.changed_closed_statics.iter().filter(|it| closed.statics.contains_key(*it)))
        {
            if !left_st_set.contains(&s) && seen_st.insert(s) {
                refresh_statics.push(s);
            }
        }

        front.with(|db| {
            for asked in refresh_fns {
                let c = contribution(db, asked.0.clone(), asked.1, facing)
                    .as_ref()
                    .map_err(|_| "a closed-walk function's world contribution failed")?
                    .clone();
                closed_world_dirty |= closed.insert_fn(asked.clone(), c.clone());
                if c.sites {
                    let inlined = front
                        .inlines_for(db, &asked.0, &asked.1)
                        .map_err(|_| "a closed-walk consumer's inline policy failed")?;
                    let keys = refs::read_objects(
                        db,
                        &asked.0,
                        refs::Walking { inlined, world: Some(world_id) },
                    )
                    .map_err(|_| "a closed-walk consumer's read objects failed")?;
                    consumers.set(asked, keys.to_vec());
                } else {
                    consumers.remove(&asked);
                }
            }
            for s in refresh_statics {
                let c = static_contribution(db, s, facing)
                    .as_ref()
                    .map_err(|_| "a closed-walk static's world contribution failed")?
                    .clone();
                closed_world_dirty |= closed.insert_static(s, c);
            }
            if closed_world_dirty {
                let made = world_from_set(front, db, (makes.0, program), &closed)?;
                if !made.as_ref().is_some_and(|w| w.id == world_id) {
                    return Err("the patched closed walk's dyn facts differ from the plain walk's");
                }
            }
            Ok(())
        })?;

        state.checkpoint.closed = Arc::new(closed);
        state.checkpoint.consumers = Arc::new(consumers);
        Ok(())
    }
}

impl State {
    /// The unit makes `krate` as `kind`: said once, by its roots. A front end is of one
    /// program, so another program is refused, naming both; the first stays.
    pub(crate) fn makes(&self, db: &Db, kind: RootKind, krate: Crate) -> Result<(), CodegenError> {
        match self.makes.put((kind, krate)) {
            Ok(_) => Ok(()),
            Err(refused) => {
                let (kept_kind, kept_crate) = *refused.kept;
                Err(refused_of(
                    db,
                    krate,
                    kind,
                    // alloc: the error's message
                    format!(
                        "its front end already walks {}; a front end's dyn facts are one \
                         program's",
                        program_name(db, kept_kind, kept_crate)
                    ),
                ))
            }
        }
    }

    /// The world the walk's bodies are built against: `None` before the first walk ends, and
    /// for a program that has none. One acquire load.
    pub(crate) fn world(&self) -> Option<DevirtWorld> {
        if self.using_resumed.load(Ordering::Acquire) {
            return self.resumed_world.get().map(|it| it.world().id);
        }
        self.held.get().map(|it| it.world().id)
    }

    /// Called when a walk has reached everything, with every function (and whose code asked
    /// for it) and static it reached, in the walk's order, which is the same whatever the
    /// schedule of its describes: the program's world from them, `true` when it is a new one
    /// the bodies are to be built against (the walk then runs again), `false` when there is
    /// none or it is the one the bodies were built against. A second walk that finds other
    /// facts than the first is an error naming the program: the bodies built against the
    /// first would be keyed by facts that are not the program's.
    pub(crate) fn closed(
        &self,
        frontend: &HirFrontend<'_>,
        functions: &[(HirInstance, Origin)],
        statics: &[HirStatic],
    ) -> Result<bool, CodegenError> {
        let Some(&(kind, krate)) = self.makes.get().filter(|it| it.0 != RootKind::Library) else {
            return Ok(false);
        };
        let made = frontend.with(|db| {
            let program = program_name(db, kind, krate);
            let _span =
                tracing::info_span!(target: "blaze", "devirt world", program = &*program).entered();
            world_of(frontend, db, (kind, program), functions, statics)
                .map_err(|what| refused_of(db, krate, kind, what))
        })?;
        let held = self.held.get().map(|it| it.world().id);
        if made.is_some() && made.as_ref().is_some_and(|it| held.is_none_or(|id| it.id == id)) {
            let slot = if held.is_none() { &self.plain } else { &self.closed_members };
            if slot.get().is_none() {
                // alloc: one membership + contributor index for this round; changes are probed by item.
                let (members, consumers) = frontend.with(|db| {
                    let facing = frontend.facing(None);
                    let fail = |s: &String| refused_of(db, krate, kind, s);
                    let mut fn_map = HashMap::with_capacity(functions.len());
                    let mut consumers = ConsumerIndex::default();
                    for (i, o) in functions {
                        let c = contribution(db, i.clone(), *o, facing)
                            .as_ref()
                            .map_err(fail)?
                            .clone();
                        if held.is_some() && c.sites {
                            let inlined = frontend.inlines_for(db, i, o).map_err(|s| fail(&s))?;
                            let keys = refs::read_objects(
                                db,
                                i,
                                refs::Walking { inlined, world: held },
                            )
                            .map_err(|s| fail(&s))?;
                            consumers.set((i.clone(), *o), keys.to_vec());
                        }
                        fn_map.insert((i.clone(), *o), c);
                    }
                    let mut st_map = HashMap::with_capacity(statics.len());
                    for s in statics {
                        let c = static_contribution(db, *s, facing)
                            .as_ref()
                            .map_err(fail)?
                            .clone();
                        st_map.insert(*s, c);
                    }
                    Ok::<_, CodegenError>((
                        Arc::new(WorldSet::from_maps(fn_map, st_map)),
                        Arc::new(consumers),
                    ))
                })?;
                if slot.put(members).is_err() {
                    return Err(frontend.with(|db| {
                        refused_of(
                            db,
                            krate,
                            kind,
                            "two walks gave different members for the same closure",
                        )
                    }));
                }
                if held.is_some() && self.closed_consumers.get().is_none() {
                    let _ = self.closed_consumers.put(consumers);
                }
            }
        }
        let others = |id: DevirtWorld, found: String| {
            frontend.with(|db| {
                refused_of(
                    db,
                    krate,
                    kind,
                    // alloc: the error's message
                    format!(
                        "the walk of the program against its dyn facts {id:?} found others \
                         ({found}); the facts may not change with what is built against them"
                    ),
                )
            })
        };
        match (made, held) {
            (None, None) => Ok(false),
            (Some(world), None) => {
                let id = world.id;
                let given = devirt::give(world)
                    .map_err(|what| frontend.with(|db| refused_of(db, krate, kind, what)))?;
                match self.held.set(given) {
                    Ok(_) => Ok(true),
                    // Another walk over this front end closed its facts meanwhile: the same
                    // ones are the ones the bodies are now built against, and this walk runs
                    // again over them as it would over its own; others are refused.
                    Err(refused) if refused.kept.world().id == id => Ok(true),
                    // alloc: the error's message
                    Err(refused) => Err(others(refused.kept.world().id, format!("{id:?}"))),
                }
            }
            (Some(world), Some(id)) if world.id == id => Ok(false),
            (made, Some(id)) => {
                // alloc: the error's message
                Err(others(id, made.map_or_else(|| "none".to_owned(), |it| format!("{:?}", it.id))))
            }
        }
    }
}

fn program_name(db: &Db, kind: RootKind, krate: Crate) -> Box<str> {
    let what = match kind {
        RootKind::Executable => "the executable",
        RootKind::Test => "the test",
        RootKind::Shared => "the cdylib",
        RootKind::Library => "the library",
    };
    // alloc: once a program, its name in messages
    format!("{what} of crate `{}`", krate.named(db)).into_boxed_str()
}

fn refused_of(db: &Db, krate: Crate, kind: RootKind, what: impl std::fmt::Display) -> CodegenError {
    CodegenError {
        unit: InstanceKey(ContentId::default()),
        item: ItemKey(ContentId::default()),
        // alloc: the error's message
        what: format!("the dyn facts of {}: {what}", program_name(db, kind, krate)),
        front: None,
    }
}

/// One object type's types and why its list is open, while the world is made.
#[derive(Default)]
struct Found {
    tys: Vec<StoredTy>,
    open: Option<String>,
}

// The projection must backdate when a literal changes but no edge or world input does.
// The graph is ordered: the first loader or foreign signature supplies the open reason.
#[derive(PartialEq, Eq, Debug)]
struct Contribution {
    origin: Origin,
    edges: Vec<super::places::Ref>,
    count: blaze_codegen::backend::Counted,
    sites: bool,
    facts: Facts,
    loader: Option<String>,
    foreign: Option<String>,
    objects: Vec<ContentId>,
}

impl Contribution {
    fn contributes(&self) -> bool {
        !self.facts.is_empty() || self.loader.is_some()
    }

    fn same_world_inputs(&self, other: &Contribution) -> bool {
        self.sites == other.sites
            && self.facts == other.facts
            && self.loader == other.loader
            && self.foreign == other.foreign
            && self.objects == other.objects
    }
}

/// DB handles alone don't prove that an object's content identity has not changed. Read
/// the same type, principal and argument digests the world writer uses for each key.
fn object_inputs(
    front: &HirFrontend<'_>,
    db: &Db,
    facts: &Facts,
) -> Result<Vec<ContentId>, String> {
    let mut ids = Vec::new(); // alloc: only an item that contributes an object
    for &(ref ty, key) in &facts.vtables {
        let (tr, args) = key_id(front, db, key)?;
        ids.extend([tr, args]);
        ids.push(front.hashes.ty(db, ty.as_ref())?);
    }
    for &key in facts.foreign.iter().chain(facts.upcasts.iter().flat_map(|(a, b)| [a, b])) {
        let (tr, args) = key_id(front, db, key)?;
        ids.extend([tr, args]);
    }
    Ok(ids)
}

#[blaze_query::tracked(returns(ref))]
fn contribution(
    db: &Db,
    i: HirInstance,
    o: Origin,
    facing: super::frontend::Facing,
) -> Result<Arc<Contribution>, String> {
    let front = facing.front(db)?;
    let origin = front.compiled_for(db, &i, &o);
    let inlined = front.inlines_for(db, &i, &o)?;
    let owner = front.owner(db, &i.0);
    let sites = takes_world(db, &i, inlined, || owner)?;
    let walking = refs::Walking::plain(inlined);
    let facts = refs::facts(db, &i, walking)?.cloned().unwrap_or_default();
    let mut edges = refs::walk(db, &i, walking)?;
    super::frontend::asked_by(owner, &mut edges);
    let ours = super::frontend::crate_of(db, &i.0).is_some_and(|it| !it.data(db).origin.is_lang());
    let loader = ours
        .then(|| {
            edges.iter().find_map(|r| match r {
                FrontRef::Extern(name) if LOADERS.contains(&name.as_str()) => {
                    Some(format!("{} loads code at run time (`{name}`)", super::Named(db, &i)))
                }
                _ => None,
            })
        })
        .flatten();
    edges.retain(|r| matches!(r, FrontRef::Function(_) | FrontRef::Static(_)));
    let foreign = (!facts.foreign.is_empty())
        .then(|| format!("{} carries it across the program's edge", super::Named(db, &i)));
    let objects = object_inputs(&front, db, &facts)?;
    Ok(Arc::new(Contribution {
        origin,
        edges,
        count: super::frontend::counted(db, &i.0),
        sites,
        facts,
        foreign,
        loader,
        objects,
    }))
}

#[derive(PartialEq, Eq, Debug)]
struct StaticContribution {
    facts: Facts,
    origin: Origin,
    edges: Vec<super::places::Ref>,
    objects: Vec<ContentId>,
}

impl StaticContribution {
    fn contributes(&self) -> bool {
        !self.facts.is_empty()
    }

    fn same_world_inputs(&self, other: &StaticContribution) -> bool {
        self.facts == other.facts && self.objects == other.objects
    }
}

#[blaze_query::tracked(returns(ref))]
fn static_contribution(
    db: &Db,
    value: HirStatic,
    facing: super::frontend::Facing,
) -> Result<Arc<StaticContribution>, String> {
    let front = facing.front(db)?;
    let mut facts = Facts::default();
    if let super::statics::Source::Compiled(compiled) = super::statics::source(db, value.0)? {
        for request in &compiled.requests.datas {
            if let crate::fragment::DataRequest::Vtable {
                ty,
                trait_ref: Some((trait_, args)),
                ..
            } = request
            {
                facts.vtable(ty, *trait_, args);
            }
        }
    }
    let mut edges = super::statics::value(db, &front.hashes, value.0)?.refs;
    super::frontend::asked_by(front.static_owner(db, &value), &mut edges);
    edges.retain(|r| matches!(r, FrontRef::Function(_) | FrontRef::Static(_)));
    let objects = object_inputs(&front, db, &facts)?;
    let origin = front.origin(db, value.0.krate(db));
    Ok(Arc::new(StaticContribution { facts, edges, origin, objects }))
}

/// Builds the program's [`World`] from only the contributing items in `set` (a small fraction
/// of the program). Refuses to guess when two distinct loader or foreign open-reason strings
/// could depend on BFS walk order (rule 25), letting the caller fall back to a whole walk.
fn world_from_set(
    frontend: &HirFrontend<'_>,
    db: &Db,
    (kind, program): (RootKind, Box<str>),
    set: &WorldSet,
) -> Result<Option<World>, &'static str> {
    if set.site_count == 0 {
        return Ok(None);
    }
    let mut objects: blaze_hash::HashMap<ObjectKey, Found, Global> =
        blaze_hash::HashMap::new_in(Global);
    let mut upcasts: Vec<(ObjectKey, ObjectKey)> = Vec::new();
    let mut loads: Option<String> = None;
    let mut by_instance: blaze_hash::HashMap<&HirInstance, &Contribution, Global> =
        blaze_hash::HashMap::new_in(Global);
    for ((instance, _), c) in &set.fn_contributors {
        if let Some(prev) = by_instance.insert(instance, c.as_ref()) {
            if !prev.same_world_inputs(c) {
                return Err("two origins of one instance contribute different dyn facts");
            }
            continue;
        }
        let facts = &c.facts;
        for (ty, key) in &facts.vtables {
            objects.entry(*key).or_default().tys.push(ty.clone());
        }
        for &upcast in &facts.upcasts {
            if !upcasts.contains(&upcast) {
                upcasts.push(upcast);
            }
        }
        for key in &facts.foreign {
            let found = objects.entry(*key).or_default();
            if let Some(reason) = &c.foreign {
                match &found.open {
                    None => found.open = Some(reason.clone()),
                    Some(existing) if existing == reason => {}
                    Some(_) => {
                        return Err("multiple foreign signatures open one trait object");
                    }
                }
            }
        }
        if let Some(reason) = &c.loader {
            match &loads {
                None => loads = Some(reason.clone()),
                Some(existing) if existing == reason => {}
                Some(_) => {
                    return Err("multiple dynamic loaders open the program's dyn facts");
                }
            }
        }
    }
    for c in set.static_contributors.values() {
        for (ty, key) in &c.facts.vtables {
            objects.entry(*key).or_default().tys.push(ty.clone());
        }
    }
    let bound = objects.values().map(|it| it.tys.len() + 1).sum::<usize>() + upcasts.len() + 1;
    let mut rounds = 0;
    loop {
        let mut changed = false;
        for &(from, to) in &upcasts {
            let (tys, open) = match objects.get(&from) {
                Some(found) => (found.tys.clone(), found.open.clone()),
                None => continue,
            };
            let into = objects.entry(to).or_default();
            for ty in tys {
                if !into.tys.contains(&ty) {
                    into.tys.push(ty);
                    changed = true;
                }
            }
            if let Some(open) = open {
                match &into.open {
                    None => {
                        into.open = Some(open);
                        changed = true;
                    }
                    Some(existing) if *existing == open => {}
                    Some(_) => {
                        return Err("upcasts merge multiple open reasons for one trait object");
                    }
                }
            }
        }
        rounds += 1;
        if !changed {
            break;
        }
        if rounds > bound {
            return Err("the upcasts of the program did not settle");
        }
    }
    let everything = match kind {
        RootKind::Shared => Some(
            "the program is a cdylib: a program that loads it may make objects of its traits"
                .to_owned(),
        ),
        _ => loads,
    };
    let mut made = Vec::with_capacity(objects.len());
    for (key, found) in objects {
        made.push(
            object(frontend, db, key, found, everything.as_deref())
                .map_err(|_| "building an object's dyn facts failed")?,
        );
    }
    made.sort_unstable_by(|a, b| a.digest.cmp(&b.digest));
    World::new(program, made).map(Some).map_err(|_| "building the updated dyn world failed")
}

/// The object keys added, removed, or given another digest between `old` and `new`.
fn diff_objects(old: &World, new: &World) -> blaze_hash::HashSet<ObjectKey, Global> {
    let mut changed = blaze_hash::HashSet::new_in(Global);
    for obj in old.objects() {
        if new.object(&obj.key).is_none_or(|now| now.digest != obj.digest) {
            changed.insert(obj.key);
        }
    }
    for obj in new.objects() {
        if old.object(&obj.key).is_none() {
            changed.insert(obj.key);
        }
    }
    changed
}

/// The program's world from what its walk reached; `None` where no reached body calls through
/// a `dyn`, so nothing is built against one.
fn world_of(
    frontend: &HirFrontend<'_>,
    db: &Db,
    (kind, program): (RootKind, Box<str>),
    functions: &[(HirInstance, Origin)],
    statics: &[HirStatic],
) -> Result<Option<World>, String> {
    let mut objects: blaze_hash::HashMap<ObjectKey, Found, Global> =
        blaze_hash::HashMap::new_in(Global);
    // alloc: once a program, the upcasts its bodies make
    let mut upcasts = Vec::new();
    let mut loads = None;
    let mut sites = false;
    // No consumer: no world, and therefore no checkpoint or projections to maintain.
    let mut any = false;
    for (i, o) in functions {
        if takes_world(db, i, frontend.inlines_for(db, i, o)?, || frontend.owner(db, &i.0))? {
            any = true;
            break;
        }
    }
    if !any {
        return Ok(None);
    }
    let mut seen = blaze_hash::HashSet::new_in(Global);
    for (instance, requester) in functions {
        let c = contribution(db, instance.clone(), *requester, frontend.facing(None))
            .as_ref()
            .map_err(Clone::clone)?;
        if !seen.insert(instance) {
            continue;
        }
        sites |= c.sites;
        let facts = &c.facts;
        for (ty, key) in &facts.vtables {
            // clone: a reference count, once per vtable the program makes
            objects.entry(*key).or_default().tys.push(ty.clone());
        }
        upcasts.extend_from_slice(&facts.upcasts);
        for key in &facts.foreign {
            let found = objects.entry(*key).or_default();
            if found.open.is_none() {
                // alloc: the reason, once an object
                found.open = c.foreign.clone();
            }
        }
        if loads.is_none() {
            loads.clone_from(&c.loader);
        }
    }
    if !sites {
        return Ok(None);
    }
    for value in statics {
        // An `extern_weak` static holds a foreign symbol's address: no vtable of its value.
        let c = static_contribution(db, *value, frontend.facing(None))
            .as_ref()
            .map_err(Clone::clone)?;
        for (ty, key) in &c.facts.vtables {
            objects.entry(*key).or_default().tys.push(ty.clone());
        }
    }
    // An upcast object holds the types of the one it is upcast from: propagated to a fixpoint,
    // each round adding at least one type or reason, so at most one round more than there
    // are objects times their types.
    let bound = objects.values().map(|it| it.tys.len() + 1).sum::<usize>() + upcasts.len() + 1;
    let mut rounds = 0;
    loop {
        let mut changed = false;
        for (from, to) in &upcasts {
            let (tys, open) = match objects.get(from) {
                // clone: a few reference counts, once an upcast a round
                Some(found) => (found.tys.clone(), found.open.clone()),
                None => continue,
            };
            let into = objects.entry(*to).or_default();
            for ty in tys {
                if !into.tys.contains(&ty) {
                    into.tys.push(ty);
                    changed = true;
                }
            }
            if into.open.is_none()
                && let Some(open) = open
            {
                into.open = Some(open);
                changed = true;
            }
        }
        rounds += 1;
        if !changed {
            break;
        }
        if rounds > bound {
            // alloc: the error's message
            return Err(format!("the upcasts of the program did not settle in {bound} rounds"));
        }
    }
    let everything = match kind {
        RootKind::Shared => Some(
            "the program is a cdylib: a program that loads it may make objects of its traits"
                .to_owned(),
        ),
        _ => loads,
    };
    // alloc: once a program, its objects
    let mut made = Vec::with_capacity(objects.len());
    for (key, found) in objects {
        made.push(object(frontend, db, key, found, everything.as_deref())?);
    }
    made.sort_unstable_by(|a, b| a.digest.cmp(&b.digest));
    World::new(program, made).map(Some)
}

/// The facts of one object type: its types by content, in order, each once.
fn key_id(
    frontend: &HirFrontend<'_>,
    db: &Db,
    key: ObjectKey,
) -> Result<(ContentId, ContentId), String> {
    let hashes = &frontend.hashes;
    let trait_id = hashes.item(db, ItemId::Trait(key.trait_))?.0;
    let mut args = Hasher::new(ARGS_DOMAIN);
    let after_self = key.args.as_ref();
    args.update(&(after_self.len() as u64).to_le_bytes());
    for arg in after_self.iter() {
        match (arg.ty(), arg.konst()) {
            (Some(ty), _) => args.update(&[0]).id(&hashes.ty(db, ty)?),
            (None, Some(konst)) => args.update(&[1]).id(&hashes.konst(db, konst)?),
            // A region, which the key has erased.
            (None, None) => args.update(&[2]),
        };
    }
    Ok((trait_id, args.finish()))
}

fn object(
    frontend: &HirFrontend<'_>,
    db: &Db,
    key: ObjectKey,
    found: Found,
    everything: Option<&str>,
) -> Result<Object, String> {
    let hashes = &frontend.hashes;
    let after_self = key.args.as_ref();
    let (trait_id, args_id) = key_id(frontend, db, key)?;
    // alloc: once an object, its types
    let mut targets = Vec::with_capacity(found.tys.len());
    for ty in found.tys {
        let id = hashes.ty(db, ty.as_ref())?;
        targets.push(Target { ty, id, count: None });
    }
    targets.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    let mut kept: Vec<Target> = Vec::with_capacity(targets.len()); // alloc: as above
    for target in targets {
        match kept.last() {
            Some(last) if last.id == target.id && last.ty == target.ty => {}
            Some(last) if last.id == target.id => {
                // alloc: the error's message
                return Err(blaze_query::db::attach(db, || {
                    format!("{:?} and {:?} have one content ID {:?}", last.ty, target.ty, target.id)
                }));
            }
            _ => kept.push(target),
        }
    }
    let open = found.open.as_deref().or(everything);
    let digest = devirt::object_digest(&trait_id, &args_id, &kept, open);
    let name = blaze_query::db::attach(db, || {
        let trait_name = TraitSignature::of(db, key.trait_).name.as_str().to_owned();
        match after_self.is_empty() {
            true => format!("dyn {trait_name}"),
            false => format!("dyn {trait_name}{:?}", after_self),
        }
    });
    Ok(Object {
        key,
        name: name.into_boxed_str(),
        targets: kept.into_boxed_slice(),
        open: open.map(Into::into),
        digest,
    })
}
