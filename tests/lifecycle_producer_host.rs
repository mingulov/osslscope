// SPDX-License-Identifier: GPL-3.0-or-later
// Compile the actual owning seams before libtest creates any threads.
extern crate self as osslscope;
#[expect(
    dead_code,
    unused_imports,
    reason = "libtest does not retain the existing test bodies in this explicit pre-thread driver"
)]
#[path = "../src/lib.rs"]
mod app;
pub use app::*;
pub(crate) use app::{capture_setup, count_owner, policy_config};
#[expect(
    dead_code,
    unused_imports,
    reason = "only existing connector bodies are dispatched by this pre-thread driver"
)]
#[path = "capture_controller.rs"]
mod capture_controller;
#[expect(
    dead_code,
    unused_imports,
    reason = "only existing connector bodies are dispatched by this pre-thread driver"
)]
#[path = "target_lifecycle.rs"]
mod target_lifecycle;
fn main() {
    let case = std::env::args().nth(1).unwrap_or_default();
    if !case.starts_with("connector-") {
        app::lifecycle_producer::tests::host_main();
        return;
    }
    // Safety: this main has only decoded its case name, before any test effects.
    let runtime = unsafe {
        lifecycle_producer::LifecycleRuntime::bootstrap_early(
            std::time::Instant::now() + std::time::Duration::from_secs(2),
            None,
        )
    }
    .expect("explicit connector driver bootstrap");
    let installed = runtime
        .install()
        .expect("explicit connector driver installation");
    let result = std::panic::catch_unwind(|| {
        if case.starts_with("connector-target:") {
            target_lifecycle::connector_dispatch(&case)
        } else if case.starts_with("connector-controller:") {
            capture_controller::connector_dispatch(&case)
        } else {
            match case.as_str() {
                "connector-lib:kernel_concurrent_subscribes_use_distinct_tokens" => {
                    capture::tests::connector_body_kernel_concurrent_subscribes_use_distinct_tokens(
                    )
                }
                "connector-lib:kernel_select_uses_signals_or_falls_back_loud" => {
                    capture::tests::connector_body_kernel_select_uses_signals_or_falls_back_loud()
                }
                _ => panic!("unknown connector driver case"),
            }
            0
        }
    });
    drop(installed);
    let receipt = runtime.shutdown(std::time::Instant::now() + std::time::Duration::from_secs(2));
    assert_eq!(
        receipt.state,
        lifecycle_producer::ProducerShutdownState::Complete,
        "{receipt:?}"
    );
    match result {
        Ok(code) => std::process::exit(code),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
