// SPDX-License-Identifier: GPL-3.0-or-later
use osslscope::package::{PackageError, trusted::executing_host};

// This integration test exercises the fixed production policy. Positive fixtures
// with a test-only ownership policy live in package::trusted unit tests.
#[test]
fn development_test_binary_cannot_become_an_installed_host() {
    let host = executing_host();
    assert!(matches!(
        host,
        Err(PackageError::Untrusted { .. } | PackageError::Invalid { .. })
    ));
}
