//! The scopes that can declare an item of a link: module items and item-declaring blocks,
//! whether or not the enclosing function is ever called. All link collectors use the same
//! list. An edit that changes only an expression leaves the list equal.

use base_db::{Crate, Db};
use hir_def::{
    ModuleId,
    nameres::{
        crate_def_map,
        demand::{crate_body_owners, walk_bodies},
    },
};

#[blaze_query::tracked(returns(ref))]
pub(super) fn declaring_modules(db: &Db, krate: Crate) -> Box<[ModuleId]> {
    // alloc: the memo's result, shared by the native library, kept symbol and assembly queries
    let mut modules: Vec<_> = crate_def_map(db, krate).modules(db).map(|(id, _)| id).collect();
    walk_bodies(
        db,
        crate_body_owners(db, krate),
        |_| true,
        |_, blocks| {
            for &(_, map) in &blocks.blocks {
                modules.extend(map.modules(db).map(|(id, _)| id));
            }
        },
    );
    modules.into_boxed_slice()
}
