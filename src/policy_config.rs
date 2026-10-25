//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded policy-file admission and additive rule merging.
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Parsed rule set (repeatable flags accumulate).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RuleSet {
    pub require_provider: Vec<String>,
    pub deny_provider: Vec<String>,
    pub deny_engine: bool,
    pub deny_algorithm: Vec<String>,
    pub deny_weak: bool,
    pub require_executed: Vec<String>,
}

impl RuleSet {
    pub(crate) fn is_empty(&self) -> bool {
        self.require_provider.is_empty()
            && self.deny_provider.is_empty()
            && !self.deny_engine
            && self.deny_algorithm.is_empty()
            && !self.deny_weak
            && self.require_executed.is_empty()
    }
}

const MAX_BYTES: usize = 65_536;
const MAX_RULES: usize = 1_024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct FileRules {
    version: i64,
    #[serde(default)]
    require_provider: Vec<String>,
    #[serde(default)]
    deny_provider: Vec<String>,
    #[serde(default)]
    deny_engine: bool,
    #[serde(default)]
    deny_algorithm: Vec<String>,
    #[serde(default)]
    deny_weak: bool,
    #[serde(default)]
    require_executed: Vec<String>,
}

/// Never format a TOML error: it can contain source excerpts or rejected values.
fn admit(bytes: &[u8]) -> Result<RuleSet, String> {
    if bytes.len() > MAX_BYTES {
        return Err("policy file exceeds 65536 bytes".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "policy file must be UTF-8")?;
    let file: FileRules = toml::from_str(text).map_err(|error| {
        let offset = error.span().map_or(0, |span| span.start.min(bytes.len()));
        let prefix = &bytes[..offset];
        let line = prefix.iter().filter(|&&b| b == b'\n').count() + 1;
        let column = prefix
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(offset + 1, |i| offset - i);
        format!("invalid policy TOML at line {line}, column {column}")
    })?;
    if file.version != 1 {
        return Err("policy version must be integer 1".into());
    }
    let rules = RuleSet {
        require_provider: file.require_provider,
        deny_provider: file.deny_provider,
        deny_engine: file.deny_engine,
        deny_algorithm: file.deny_algorithm,
        deny_weak: file.deny_weak,
        require_executed: file.require_executed,
    };
    validate_names(&rules)?;
    if rules.is_empty() {
        return Err("policy file needs at least one active rule".into());
    }
    Ok(rules)
}

/// Read the opened object once; replacement of the path cannot redirect this read.
pub(crate) fn load(path: &Path) -> Result<RuleSet, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "cannot open policy file")?;
    let metadata = file.metadata().map_err(|_| "cannot inspect policy file")?;
    if !metadata.is_file() {
        return Err("policy file must be a regular file".into());
    }
    let mut bytes = Vec::with_capacity(MAX_BYTES + 1);
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read policy file")?;
    admit(&bytes)
}

fn validate_names(rules: &RuleSet) -> Result<(), String> {
    for (field, names) in [
        ("require-provider", &rules.require_provider),
        ("deny-provider", &rules.deny_provider),
    ] {
        for (index, name) in names.iter().enumerate() {
            if name.is_empty() {
                return Err(format!("policy {field}[{index}] must be nonempty"));
            }
        }
    }
    for (field, names) in [
        ("deny-algorithm", &rules.deny_algorithm),
        ("require-executed", &rules.require_executed),
    ] {
        for (index, name) in names.iter().enumerate() {
            if !crate::kinds::is_known_alg(name) {
                return Err(format!(
                    "policy {field}[{index}] must name a frozen-registry algorithm"
                ));
            }
        }
    }
    Ok(())
}

/// File-mode constraints are additive. CLI-only parsing does not call this.
pub(crate) fn merge(mut file: RuleSet, cli: RuleSet) -> Result<RuleSet, String> {
    file.require_provider.extend(cli.require_provider);
    file.deny_provider.extend(cli.deny_provider);
    file.deny_engine |= cli.deny_engine;
    file.deny_algorithm.extend(cli.deny_algorithm);
    file.deny_weak |= cli.deny_weak;
    file.require_executed.extend(cli.require_executed);
    let count = file.require_provider.len()
        + file.deny_provider.len()
        + file.deny_algorithm.len()
        + file.require_executed.len()
        + usize::from(file.deny_engine)
        + usize::from(file.deny_weak);
    if count > MAX_RULES {
        return Err("merged policy exceeds 1024 rule instances".into());
    }
    validate_names(&file)?;
    for required in &file.require_provider {
        if file.deny_provider.contains(required) {
            return Err("contradictory policy: require-provider and deny-provider".into());
        }
        if file.deny_engine && required == crate::policy::ENGINE_PROVIDER_CLASS {
            return Err("contradictory policy: require-provider and deny-engine".into());
        }
    }
    for required in &file.require_executed {
        if file.deny_algorithm.iter().any(|denied| {
            required == denied || matches!(
                (crate::kinds::algorithm_semantic_id(required), crate::kinds::algorithm_semantic_id(denied)),
                (Some(a), Some(b)) if a == b
            )
        }) {
            return Err("contradictory policy: require-executed and deny-algorithm".into());
        }
        if file.deny_weak && crate::kinds::is_weak_alg(required) {
            return Err("contradictory policy: require-executed and deny-weak".into());
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIX: &str = r#"version = 1
require-provider = ["default"]
deny-provider = ["legacy"]
deny-engine = true
deny-algorithm = ["MD5"]
deny-weak = true
require-executed = ["SHA2-256"]
"#;

    #[test]
    fn literal_six_rules_and_opaque_provider() {
        assert_eq!(
            admit(SIX.as_bytes()).unwrap(),
            RuleSet {
                require_provider: vec!["default".into()],
                deny_provider: vec!["legacy".into()],
                deny_engine: true,
                deny_algorithm: vec!["MD5".into()],
                deny_weak: true,
                require_executed: vec!["SHA2-256".into()],
            }
        );
        assert_eq!(
            admit(b"version=1\nrequire-provider=['third-party:opaque']")
                .unwrap()
                .require_provider,
            vec!["third-party:opaque"]
        );
    }

    #[test]
    fn malformed_schema_values_and_encoding_reject() {
        for text in [
            "deny-weak=true",
            "version=2\ndeny-weak=true",
            "version=1.0\ndeny-weak=true",
            "version=1\nprivate-canary=true",
            "version=1\nversion=1\ndeny-weak=true",
            "version=1\nrequire-provider='default'",
            "version=1\ndeny-engine=1",
            "version=1\nrequire-provider=['']",
            "version=1\ndeny-algorithm=['private-canary']",
            "version=1",
            "version=1\ndeny-weak=false",
            "version=1\nrequire-executed=[1]",
            "version=1\n[private-canary]\na=1",
            "version=1\ndeny-provider=['x']\ndeny-provider=['y']",
        ] {
            let error = admit(text.as_bytes()).unwrap_err();
            assert!(!error.contains("private-canary"), "{error}");
        }
        assert!(admit(&[0xff]).is_err());
    }

    #[test]
    fn byte_limit_is_inclusive() {
        let mut bytes = b"version=1\ndeny-weak=true\n#".to_vec();
        bytes.resize(65_536, b' ');
        assert!(admit(&bytes).is_ok());
        bytes.push(b' ');
        assert!(admit(&bytes).is_err());
    }

    #[test]
    fn merge_preserves_repeats_order_and_boolean_or() {
        let file = admit(SIX.as_bytes()).unwrap();
        let cli = RuleSet {
            require_provider: vec!["default".into(), "third-party:x".into()],
            deny_provider: vec!["legacy".into(), "fips".into()],
            deny_algorithm: vec!["DES".into()],
            require_executed: vec!["SHA256".into()],
            ..RuleSet::default()
        };
        assert_eq!(
            merge(file, cli).unwrap(),
            RuleSet {
                require_provider: vec!["default".into(), "default".into(), "third-party:x".into()],
                deny_provider: vec!["legacy".into(), "legacy".into(), "fips".into()],
                deny_engine: true,
                deny_algorithm: vec!["MD5".into(), "DES".into()],
                deny_weak: true,
                require_executed: vec!["SHA2-256".into(), "SHA256".into()],
            }
        );
        let merged = merge(
            RuleSet::default(),
            RuleSet {
                deny_engine: true,
                deny_weak: true,
                ..RuleSet::default()
            },
        )
        .unwrap();
        assert!(merged.deny_engine && merged.deny_weak);
        for (a, b, expected) in [
            (false, false, false),
            (false, true, true),
            (true, false, true),
            (true, true, true),
        ] {
            let merged = merge(
                RuleSet {
                    deny_engine: a,
                    deny_weak: a,
                    ..RuleSet::default()
                },
                RuleSet {
                    deny_engine: b,
                    deny_weak: b,
                    ..RuleSet::default()
                },
            )
            .unwrap();
            assert_eq!((merged.deny_engine, merged.deny_weak), (expected, expected));
        }
    }

    #[test]
    fn effective_rule_limit_counts_repetitions_and_booleans() {
        let file = RuleSet {
            deny_engine: true,
            deny_weak: true,
            deny_provider: vec!["legacy".into(); 1_021],
            ..RuleSet::default()
        };
        assert!(
            merge(
                file.clone(),
                RuleSet {
                    deny_provider: vec!["legacy".into()],
                    ..RuleSet::default()
                }
            )
            .is_ok()
        );
        assert!(
            merge(
                file,
                RuleSet {
                    deny_provider: vec!["legacy".into(); 2],
                    ..RuleSet::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn impossible_conjunctions_reject_but_distinct_requirements_pass() {
        for (file, cli) in [
            ("require-provider=['default']", "deny-provider=['default']"),
            ("require-provider=['engine']", "deny-engine=true"),
            (
                "require-executed=['SHA2-256']",
                "deny-algorithm=['SHA2-256']",
            ),
            ("require-executed=['SHA256']", "deny-algorithm=['SHA2-256']"),
            ("require-executed=['MD5']", "deny-weak=true"),
        ] {
            let a = admit(format!("version=1\n{file}").as_bytes()).unwrap();
            let b = admit(format!("version=1\n{cli}").as_bytes()).unwrap();
            assert!(merge(a.clone(), b.clone()).is_err());
            assert!(merge(b, a).is_err());
        }
        assert!(
            merge(
                admit(b"version=1\nrequire-provider=['default','fips']").unwrap(),
                RuleSet::default()
            )
            .is_ok()
        );
    }
    #[test]
    fn loader_reads_regular_symlink_snapshot_and_rejects_nonfiles() {
        let dir =
            std::env::temp_dir().join(format!("osslscope-policy-loader-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("policy.toml");
        let link = dir.join("policy-link.toml");
        std::fs::write(&file, SIX).unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let rules = load(&link).unwrap();
        std::fs::write(&file, "version=2").unwrap();
        assert_eq!(rules.require_executed, vec!["SHA2-256"]);
        assert!(load(&link).is_err());
        assert!(load(&dir).is_err());
        assert!(load(&dir.join("missing")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
