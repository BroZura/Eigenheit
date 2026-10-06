//! The client refuses unprotected relays unless --i-accept-the-risk is given.

#[test]
fn refuses_clear_net_without_consent() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_eigen"))
        .args(["--relay", "127.0.0.1:7777"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Relay 127.0.0.1:7777 refused."));
}

#[test]
fn unknown_flags_print_usage() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_eigen"))
        .arg("--nope")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).contains("RAM only"));
}

#[test]
fn vpn_needs_an_existing_tunnel() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_eigen"))
        .args(["--vpn", "eigen-nope0", "--relay", "10.0.0.1:7778#aaaa"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
