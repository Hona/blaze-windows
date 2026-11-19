fn main() {
    println!("cargo:rerun-if-changed=csrc/math.c");
    cc::Build::new()
        .file("csrc/math.c")
        .compile("native_math");
}
