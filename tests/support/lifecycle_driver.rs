// SPDX-License-Identifier: GPL-3.0-or-later
// Shared required/absent policy for the explicit pre-thread actual-source driver.
pub(crate) fn run_connector_driver(case: &str) {
    if std::env::var("OSSLSCOPE_CONNECTOR_TEST").as_deref() == Ok("force-absent") {
        assert!(
            std::env::var("OSSLSCOPE_REQUIRE_CONNECTOR").as_deref() != Ok("1"),
            "required connector coverage cannot use the HOST absent fixture"
        );
        eprintln!("HOST absent fixture only: {case}; CONNECTOR remains unqualified");
        return;
    }
    let path = std::env::var_os("OSSL_LIFECYCLE_TEST_DRIVER")
        .expect("explicit current Cargo lifecycle driver path required before connector tests");
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(&path).expect("lifecycle test driver metadata");
    assert!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "lifecycle driver must be executable"
    );
    let mut child = std::process::Command::new(path)
        .arg(case)
        .spawn()
        .expect("explicit lifecycle driver spawn");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().expect("driver wait") {
            assert!(status.success(), "{case}: {status}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("owned driver kill");
            let status = child.wait().expect("owned driver reap");
            panic!("{case}: driver deadline ({status})")
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}
