//! The client refuses clear-net relays without explicit consent.

#[test]
fn refuses_clear_net_without_consent() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_eigen"))
        .args(["--relay", "127.0.0.1:7777"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("refusing clear-net relay"));
}

#[test]
fn unknown_flags_print_usage() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_eigen"))
        .arg("--nope")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("RAM-only"));
}
