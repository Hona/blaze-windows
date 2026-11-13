//! What a crate keeps by name ([`kept`]): rustc's `linked_symbols` of it, which every program
//! that links the crate keeps though no code of it names them. A function with a C-level
//! symbol (`#[no_mangle]`, `#[export_name]`) or one of the standard library's linked by name
//! (`#[rustc_std_internal_symbol]`, `#[panic_handler]`, the personality); a static that is
//! `#[used]` or exported; either with a `#[linkage]` other than `internal`. Items declared in bodies count, as rustc's collector finds them
//! there: `const _: () = { #[used] static .. };` is how a constructor is registered.

use base_db::{Crate, Db};
use hir_def::{AssocItemId, AttrDefId, FunctionId, ModuleDefId, StaticId, attrs::AttrFlags};

use crate::{exported_static, exported_symbol, linked_symbol};

/// The functions and statics of a crate that are kept by name, in the order found.
#[derive(PartialEq, Eq, Debug, Default)]
pub(super) struct Kept {
    pub(super) functions: Box<[FunctionId]>,
    pub(super) statics: Box<[StaticId]>,
}

/// Once per crate and revision of it: the standard library's is found once a daemon.
#[blaze_query::tracked(returns(ref))]
pub(super) fn kept(db: &Db, krate: Crate) -> Kept {
    // alloc: once a crate a revision, the memo's lists
    let (mut functions, mut statics) = (Vec::new(), Vec::new());
    for &module in super::super::modules::declaring_modules(db, krate) {
        let data = module.def_map(db).module(db, module);
        let scope = data.scope(db);
        for def in scope.declarations() {
            match def {
                ModuleDefId::FunctionId(func) if keeps_function(db, func) => functions.push(func),
                ModuleDefId::StaticId(value) if keeps_static(db, value) => statics.push(value),
                _ => {}
            }
        }
        for imp in scope.impls() {
            for &(_, item) in imp.impl_items(db).items.iter() {
                if let AssocItemId::FunctionId(func) = item
                    && keeps_function(db, func)
                {
                    functions.push(func);
                }
            }
        }
    }
    Kept { functions: functions.into(), statics: statics.into() }
}

/// A generic one is left out, as rustc leaves it (`no_mangle_generic_items`).
fn keeps_function(db: &Db, func: FunctionId) -> bool {
    super::compiled(db, func)
        && (exported_symbol(db, func).or_else(|| linked_symbol(db, func)).is_some()
            || custom_linkage(db, func.into()))
}

fn keeps_static(db: &Db, value: StaticId) -> bool {
    exported_static(db, value).is_some()
        || AttrFlags::query(db, value.into()).contains(AttrFlags::USED)
        || custom_linkage(db, value.into())
}

/// rustc's `contains_extern_indicator` of `#[linkage = ..]` (feature `linkage`): any linkage but
/// `internal`.
fn custom_linkage(db: &Db, owner: AttrDefId) -> bool {
    AttrFlags::linkage(db, owner).is_some_and(|it| it.as_str() != "internal")
}
