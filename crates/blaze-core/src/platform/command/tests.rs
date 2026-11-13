use super::*;

/// The invariant: a tool blaze runs has no console window, whatever console blaze has: its
/// `GetConsoleWindow` is null (a console of its own, hidden, which `CREATE_NO_WINDOW` gives).
/// Only the command blaze makes is run: a control run without the flag would open the window
/// on the desktop the test runs on.
#[cfg(windows)]
#[test]
fn a_tool_blaze_runs_has_no_console_window() {
    let script = "(Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")] public static extern \
                  IntPtr GetConsoleWindow();' -Name W -Namespace B -PassThru)::GetConsoleWindow()";
    let out = command("powershell.exe", &std::env::temp_dir())
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "0", "the tool's console window");
}

#[cfg(unix)]
#[test]
fn a_command_is_std_s() {
    assert!(command("true", &std::env::temp_dir()).status().unwrap().success());
}
