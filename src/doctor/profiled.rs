// SPDX-License-Identifier: GPL-3.0-or-later
//! Preflight for the enrolled count-only foreground workflow.

use super::{Check, Status};
use crate::package::commands::PackageRoleProvenance;
use crate::package::records::Digest;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str =
    "usage: osslscope doctor --libcrypto PATH [--count-object PATH] [--format human|json]";

struct Args {
    libcrypto: PathBuf,
    count_object: Option<PathBuf>,
    json: bool,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut libcrypto = None;
    let mut count_object = None;
    let mut json = false;
    let mut args = argv.iter();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("doctor flag needs a value")?;
        match flag.as_str() {
            "--libcrypto" if libcrypto.is_none() => libcrypto = Some(PathBuf::from(value)),
            "--count-object" if count_object.is_none() => count_object = Some(PathBuf::from(value)),
            "--format" if matches!(value.as_str(), "human" | "json") => json = value == "json",
            _ => return Err("unsupported or repeated doctor option for the v0.2 preview".into()),
        }
    }
    Ok(Args {
        libcrypto: libcrypto.ok_or("doctor requires --libcrypto PATH")?,
        count_object,
        json,
    })
}

fn capabilities_present(effective: u64) -> bool {
    super::has_cap(effective, 21)
        || (super::has_cap(effective, 39) && super::has_cap(effective, 38))
}

pub(crate) fn run(argv: &[String]) -> ExitCode {
    if argv.iter().any(|s| matches!(s.as_str(), "--help" | "-h")) {
        println!("{USAGE}");
        println!(
            "  checks the exact library/kernel profile, PID namespace, Count ABI and capability bits"
        );
        println!(
            "  runtime BPF permissions and attachment are checked by report/check before releasing the child"
        );
        return ExitCode::SUCCESS;
    }
    let args = match parse(argv) {
        Ok(args) => args,
        Err(error) => {
            crate::report::err_line(&format!("osslscope doctor: {error}\n{USAGE}"));
            return ExitCode::from(2);
        }
    };
    let mut checks = Vec::new();
    let profile_id = match crate::profile::admit(&args.libcrypto) {
        Ok(profile) => {
            checks.push(Check::pass(
                "profile",
                format!(
                    "{}: exact stock library and kernel admitted",
                    profile.profile_id
                ),
            ));
            Some(profile.profile_id)
        }
        Err(error) => {
            checks.push(Check::fail(
                "profile",
                crate::report::normalize_fatal_detail(&format!("{error:#}")),
                "select the enrolled stock library and kernel; see profiles/README.md".into(),
            ));
            None
        }
    };
    match crate::profile::admit_initial_pid_namespaces() {
        Ok(()) => checks.push(Check::pass(
            "pid-namespace",
            "observer and children use the initial PID namespace and matching procfs".into(),
        )),
        Err(error) => checks.push(Check::fail(
            "pid-namespace",
            crate::report::normalize_fatal_detail(&format!("{error:#}")),
            "run in the enrolled host PID namespace with matching procfs".into(),
        )),
    }
    let count_object = match crate::package::commands::resolve_profiled_count(
        args.count_object.as_deref(),
    ) {
        Ok(count) => {
            checks.push(Check::pass(
                "count-object",
                format!(
                    "Count role/ABI compatible; sha256={}",
                    Digest(count.object_sha256)
                ),
            ));
            Some(PackageRoleProvenance {
                selection: count.selection,
                sha256: Digest(count.object_sha256),
                bytes: count.object_bytes.len() as u64,
                build_input_id: None,
            })
        }
        Err(error) => {
            checks.push(Check::fail("count-object", error.to_string(), "build Count with the documented source recipe, then pass --count-object or install it in a trusted prefix".into()));
            None
        }
    };
    let caps = super::read_trimmed("/proc/self/status").and_then(|s| super::parse_capeff(&s));
    if caps.is_some_and(capabilities_present) {
        checks.push(Check::pass(
            "capabilities",
            "CAP_BPF and CAP_PERFMON bits (or CAP_SYS_ADMIN) are present".into(),
        ));
    } else {
        checks.push(Check::fail("capabilities", "required effective BPF/perf capability bits are absent or unreadable".into(), "use the documented capability/root setup; doctor changes no privileges or system settings".into()));
    }
    checks.push(Check::info(
        "lockdown",
        format!("active mode: {}", super::lockdown_mode()),
    ));
    checks.push(Check::degraded("runtime-permissions", "this preflight loads no BPF; capability bits do not prove runtime permission or attachment".into(), "report/check validate Count load and every enrolled attachment before child release".into()));
    checks.push(Check::info(
        "coverage",
        "enrolled callbacks only; captures remain PARTIAL and absence is inconclusive".into(),
    ));
    let failed = checks.iter().any(|c| c.status == Status::Fail);
    if args.json {
        let document = serde_json::json!({ "profile":profile_id, "count_object":count_object, "target":null,
            "checks":checks.iter().map(Check::json).collect::<Vec<_>>(), "verdict":if failed {"fail-closed"} else {"ok"}, "exit":if failed {4} else {0} });
        println!(
            "{}",
            serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".into())
        );
    } else {
        for check in checks {
            println!(
                "[{}] {}: {}",
                check.status.as_str(),
                check.id,
                check.message
            );
            if let Some(remediation) = check.remediation {
                println!("  remediate: {remediation}");
            }
        }
        println!(
            "verdict: {}",
            if failed {
                "FAIL-CLOSED"
            } else {
                "ok (preflight only)"
            }
        );
    }
    ExitCode::from(if failed { 4 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_doctor_requires_library_and_rejects_deferred_modes() {
        assert!(parse(&[]).is_err());
        for unsupported in [
            "--pid",
            "--exe",
            "--object",
            "--members-object",
            "--table",
            "--provider-table",
        ] {
            let args = ["--libcrypto", "lib", unsupported, "value"].map(String::from);
            assert!(parse(&args).is_err());
        }
        let args = [
            "--libcrypto",
            "lib",
            "--count-object",
            "count",
            "--format",
            "json",
        ]
        .map(String::from);
        let args = parse(&args).unwrap();
        assert_eq!(args.libcrypto, std::path::PathBuf::from("lib"));
        assert_eq!(args.count_object, Some(std::path::PathBuf::from("count")));
        assert!(args.json);
    }

    #[test]
    fn preview_capabilities_require_bpf_and_perfmon_or_admin() {
        assert!(!capabilities_present(0));
        assert!(!capabilities_present(1u64 << 39));
        assert!(!capabilities_present(1u64 << 38));
        assert!(capabilities_present((1u64 << 39) | (1u64 << 38)));
        assert!(capabilities_present(1u64 << 21));
    }
}
