//! A cold MIR profile of one *real* function: no daemon image, shared store, codegen or link.

use std::path::Path;

use hir_def::{ModuleDefId, nameres::crate_def_map};
use hir_expand::name::Name;
use hir_ty::db::HirDatabase as _;
use hir_ty_mir::mir::{MirOptLevel, MirOptions};

use super::*;

fn read(root: &Path, dir: &Path, files: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            read(root, &path, files);
        } else {
            let name = path.strip_prefix(root).unwrap().to_str().unwrap().replace('\\', "/");
            files.push((name, std::fs::read(path).unwrap()));
        }
    }
}

#[test]
#[ignore = "profiles the pinned library from a checkout"]
fn optimize_fmaf128() {
    hir_ty_pure::facts::linked_here();
    let library = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../library");
    let mut files = Vec::new();
    for dir in [
        "core/src",
        "stdarch/crates/core_arch/src",
        "portable-simd/crates/core_simd/src",
        "compiler-builtins/compiler-builtins/src",
        "compiler-builtins/libm/src",
    ] {
        read(&library, &library.join(dir), &mut files);
    }
    let tree = MemTree::default();
    let root = view(&tree);
    let lib = tree.root(&files.iter().map(|(p, b)| (p.as_str(), b.as_slice())).collect::<Vec<_>>());
    let mut config = config(root, lib);
    config.host = "x86_64-pc-windows-msvc".to_owned();
    let mut units = units();
    units.graph.units.truncate(1);
    units.plans.truncate(1);
    units.packages.retain(|p| p.name == "core");
    let dir = format!("{LIBRARY}/compiler-builtins/compiler-builtins");
    let id = format!("path+file://{dir}#0.1.160");
    units.packages.push(package(
        &id,
        "compiler_builtins",
        &format!("{dir}/Cargo.toml"),
        None,
        false,
    ));
    units.graph.units.push(unit(
        &id,
        target("lib", "compiler_builtins", &format!("{dir}/src/lib.rs"), "2024"),
        Mode::Build,
        true,
        vec![dep(0, "core", false)],
    ));
    units.plans.push(plan(
        &["f128_enabled", "f16_enabled", "feature=\"compiler-builtins\""],
        &[],
        None,
    ));
    units.graph.roots = vec![1];
    let lowered =
        lower(Lower { units: &units, config: &config, files: &tree, root, host_cpu: None })
            .unwrap();
    let db = lowered.db();
    blaze_query::db::attach(db, || {
        let mut module = crate_def_map(db, lowered.krate(1).unwrap()).root_module_id();
        for segment in ["math", "full_availability", "fmaf128"] {
            let data = module.to_db(db).def_map(db).module(db, module);
            let found = data.name_in_scope(db, &Name::new_symbol_root(Symbol::intern(segment)));
            if let Some(ModuleDefId::ModuleId(child)) = found.take_types() {
                module = child;
            } else if let Some(ModuleDefId::FunctionId(f)) = found.take_values() {
                let body = db
                    .optimized_mir_body(
                        f.into(),
                        MirOptions { inline: true, ..MirOptions::at(MirOptLevel::Release) },
                    )
                    .unwrap();
                assert!(!body.basic_blocks.is_empty());
                return;
            } else {
                panic!("no `{segment}` in {module:?}");
            }
        }
        panic!("fmaf128 is not a function");
    });
}
