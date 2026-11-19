unsafe extern "C" {
    fn native_add_mul(a: i32, b: i32, scale: i32) -> i32;
}

fn banner() -> &'static str {
    "cc-native 0.1.0"
}

fn compute(a: i32, b: i32, scale: i32) -> i32 {
    // SAFETY: `native_add_mul` is a pure C function with no pointer arguments.
    unsafe { native_add_mul(a, b, scale) }
}

fn main() {
    let sum = compute(10, 11, 2);
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("{} (sum={sum})", banner());
        return;
    }
    println!("sum={sum}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_msvc_compiled_c_static_lib() {
        assert_eq!(compute(10, 11, 2), 42);
        assert_eq!(compute(-3, 7, 5), 20);
    }
}
