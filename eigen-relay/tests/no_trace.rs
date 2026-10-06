//! While serving traffic, the relay must not produce output or write to disk.

#[test]
fn self_test_passes() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_eigen-relay"))
        .arg("--self-test")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("PASS"));
}

#[test]
fn serving_code_has_no_output_or_fs_calls() {
    for (name, src) in [
        ("lib.rs", include_str!("../src/lib.rs")),
        ("store.rs", include_str!("../src/store.rs")),
    ] {
        for bad in [
            "println!",
            "eprintln!",
            "print!",
            "eprint!",
            "dbg!",
            "std::fs",
            "File::",
            "log::",
            "tracing",
        ] {
            assert!(!src.contains(bad), "{name} contains {bad}");
        }
    }
}
