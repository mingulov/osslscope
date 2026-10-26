// SPDX-License-Identifier: GPL-3.0-or-later
//! Descriptor-free canonical development-admission producer.
use std::path::Path;
fn main() -> std::process::ExitCode {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if osslscope::package::embedded::contract_bytes().is_some() {
        eprintln!("development admission helper must be built descriptor-free");
        return std::process::ExitCode::from(4);
    }
    let result = match a.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["contract", "--inputs", input, "--root", root] => {
            osslscope::package::dev::produce_contract(Path::new(input), Path::new(root))
        }
        ["finalize", "--root", root] => osslscope::package::dev::finalize(Path::new(root)),
        _ => {
            eprintln!(
                "usage: osslscope-dev-admission contract --inputs FILE --root DIR | finalize --root DIR"
            );
            return std::process::ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::from(4)
        }
    }
}
