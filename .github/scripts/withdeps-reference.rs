use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Point {
    x: i32,
    y: i32,
    name: String,
}

fn pid() -> u32 {
    // SAFETY: GetCurrentProcessId has no preconditions.
    unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() }
}

fn run() -> anyhow::Result<()> {
    let p = Point { x: 1, y: -2, name: "origin".into() };
    let s = serde_json::to_string(&p)?;
    let back: Point = serde_json::from_str(&s)?;
    anyhow::ensure!(back == p, "round trip changed {p:?} into {back:?}");
    println!("{s} pid={}", pid() != 0);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        run().unwrap();
    }

    #[test]
    fn json_shape() {
        let p = Point { x: 3, y: 4, name: "a".into() };
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"x":3,"y":4,"name":"a"}"#);
    }
}
