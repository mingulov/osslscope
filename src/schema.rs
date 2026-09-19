//! SPDX-License-Identifier: GPL-3.0-or-later
//! `observed-crypto-v1` reader contract (P3 exit-3).
//!
//! The schema file lives at `schemas/observed-crypto-v1.json`.
//! Readers accept v1.x documents and reject other majors or
//! garbage (`check_version`); producers emit `observed-crypto-v1.0`
//! today. Minor versions add OPTIONAL keys only — readers must
//! ignore unknown keys.

/// True iff a v1.x reader accepts this `schema_version`: accepts
/// `observed-crypto-v1` (implicit .0) and `observed-crypto-v1.<minor>`;
/// rejects other majors and anything unparseable.
pub fn check_version(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("observed-crypto-v") else {
        return false;
    };
    let (major, minor) = match rest.split_once('.') {
        Some((maj, min)) => (maj, Some(min)),
        None => (rest, None),
    };
    if major != "1" {
        return false;
    }
    match minor {
        None => true,
        Some(m) => !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()),
    }
}

/// Assert a document carries every `required` key in the schema
/// (recursive over properties/items; nulls and absent optionals
/// skipped). Structural pin for goldens — external consumers use
/// real JSON-Schema validators against the schema file.
#[cfg(test)]
pub(crate) fn assert_required_keys(schema: &serde_json::Value, doc: &serde_json::Value) {
    fn walk(schema: &serde_json::Value, doc: &serde_json::Value, path: &str) {
        if let Some(req) = schema.get("required").and_then(|v| v.as_array()) {
            let obj = doc
                .as_object()
                .unwrap_or_else(|| panic!("{path}: not an object"));
            for k in req {
                let k = k.as_str().unwrap();
                assert!(obj.contains_key(k), "{path}: missing required key '{k}'");
            }
        }
        if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
            for (k, sub) in props {
                if let Some(d) = doc.get(k) {
                    if d.is_null() {
                        continue;
                    }
                    walk(sub, d, &format!("{path}.{k}"));
                }
            }
        }
        if let Some(items) = schema.get("items") {
            if let Some(arr) = doc.as_array() {
                for (i, d) in arr.iter().enumerate() {
                    walk(items, d, &format!("{path}[{i}]"));
                }
            }
        }
    }
    walk(schema, doc, "$");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_matrix() {
        assert!(check_version("observed-crypto-v1.0"));
        assert!(check_version("observed-crypto-v1.9"));
        assert!(check_version("observed-crypto-v1"));
        assert!(!check_version("observed-crypto-v2.0"));
        assert!(!check_version("observed-crypto-v0.9"));
        assert!(!check_version("0.2-provisional"));
        assert!(!check_version(""));
        assert!(!check_version("observed-crypto-v1.x"));
        assert!(!check_version("observed-crypto-vX"));
        assert!(!check_version("1.0"));
    }

    #[test]
    fn goldens_conform_to_schema() {
        let dir = format!("{}/tests/goldens", env!("CARGO_MANIFEST_DIR"));
        let schema: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/schemas/observed-crypto-v1.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap();
        let mut n = 0;
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().to_string())
            .filter(|f| f.starts_with("report-") && f.ends_with(".json"))
            .collect();
        entries.sort();
        for f in entries {
            let doc: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{f}")).unwrap())
                    .unwrap();
            let v = doc["schema_version"].as_str().unwrap();
            assert!(check_version(v), "{f}: reader rejects {v}");
            assert_required_keys(&schema, &doc);
            n += 1;
        }
        assert!(n >= 8, "expected report goldens, found {n}");
    }
}
