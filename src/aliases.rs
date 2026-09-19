//! SPDX-License-Identifier: GPL-3.0-or-later
//! `alias-audit` — group harvest rows by shared implementation address
//! (P1 exit 2 alias audit). Pure post-processor: reads a harvest
//! document, groups rows by `addr_hash`, and reports multi-member
//! groups (one address claimed by several (op, alg-class, funcid)
//! triples — e.g. shared SHA2/SHA3 callbacks or a global GETTABLE).
//! Group key is the hash, never a raw address (golden-safe).
use std::collections::BTreeMap;
use std::process::ExitCode;

/// Build the alias report for a harvest document.
pub fn audit(doc: &serde_json::Value) -> serde_json::Value {
    let mut groups: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    let mut total = 0u64;
    let mut skipped = 0u64;
    for r in doc
        .get("rows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
    {
        total += 1;
        let Some(hash) = r.get("addr_hash").and_then(|h| h.as_str()) else {
            skipped += 1;
            continue;
        };
        groups
            .entry(hash.to_string())
            .or_default()
            .push(serde_json::json!({
                "op": r.get("op").cloned().unwrap_or(serde_json::Value::Null),
                "alg_class": r.get("alg_class").cloned().unwrap_or(serde_json::Value::Null),
                "funcid": r.get("funcid").cloned().unwrap_or(serde_json::Value::Null),
            }));
    }
    let mut out = Vec::new();
    let mut grouped_rows = 0u64;
    for (hash, mut members) in groups {
        if members.len() < 2 {
            continue;
        }
        members.sort_by(|a, b| {
            (
                a["op"].as_u64(),
                a["alg_class"].as_str(),
                a["funcid"].as_u64(),
            )
                .cmp(&(
                    b["op"].as_u64(),
                    b["alg_class"].as_str(),
                    b["funcid"].as_u64(),
                ))
        });
        grouped_rows += members.len() as u64;
        out.push(serde_json::json!({"addr_hash": hash, "members": members}));
    }
    let mut report = serde_json::json!({
        "provider": doc.get("provider").cloned().unwrap_or(serde_json::Value::Null),
        "total_rows": total,
        "grouped_rows": grouped_rows,
        "group_count": out.len(),
        "groups": out,
    });
    if skipped > 0 {
        report["skipped_rows"] = skipped.into();
    }
    report
}

pub fn run(args: &[String]) -> ExitCode {
    let mut input: Option<std::path::PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--in" => match it.next() {
                Some(p) => input = Some(p.into()),
                None => {
                    eprintln!("osslscope alias-audit: missing value for --in");
                    return ExitCode::from(2);
                }
            },
            "--help" | "-h" => {
                println!("usage: osslscope alias-audit [--in FILE] < doc.json");
                println!("  groups a harvest doc's rows by shared addr_hash,");
                println!("  reporting addresses claimed by several triples.");
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("usage: osslscope alias-audit [--in FILE] < doc.json");
                return ExitCode::from(2);
            }
        }
    }
    let text = match &input {
        Some(path) => std::fs::read_to_string(path),
        None => {
            use std::io::Read as _;
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).map(|_| s)
        }
    };
    let text = match text {
        Ok(t) => t,
        Err(e) => {
            eprintln!("osslscope alias-audit: read: {e}");
            return ExitCode::FAILURE;
        }
    };
    if text.trim().is_empty() {
        eprintln!("osslscope alias-audit: empty input (want a harvest doc)");
        eprintln!("usage: osslscope alias-audit [--in FILE] < doc.json");
        return ExitCode::from(2);
    }
    let doc: serde_json::Value = match serde_json::from_str(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("osslscope alias-audit: parse: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("{}", serde_json::to_string_pretty(&audit(&doc)).unwrap());
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(op: u64, class: &str, funcid: u64, hash: &str) -> serde_json::Value {
        serde_json::json!({"provider":"t","op":op,"alg_class":class,"funcid":funcid,
                           "addr":1,"addr_hash":hash,"addr_backed":true})
    }

    #[test]
    fn groups_shared_hash_only() {
        let doc = serde_json::json!({"provider":"t","rows":[
            row(1, "B", 1, "h1"),
            row(1, "A", 1, "h1"),
            row(1, "C", 2, "h2"),
        ]});
        let r = audit(&doc);
        assert_eq!(r["total_rows"], 3);
        assert_eq!(r["grouped_rows"], 2);
        assert_eq!(r["group_count"], 1);
        assert_eq!(r["groups"][0]["addr_hash"], "h1");
        // Members sorted by (op, alg_class, funcid) regardless of input.
        assert_eq!(r["groups"][0]["members"][0]["alg_class"], "A");
        assert_eq!(r["groups"][0]["members"][1]["alg_class"], "B");
        assert!(r.get("skipped_rows").is_none());
    }

    #[test]
    fn empty_and_missing_hash() {
        let doc = serde_json::json!({"provider":"t","rows":[]});
        let r = audit(&doc);
        assert_eq!(r["group_count"], 0);
        assert_eq!(r["total_rows"], 0);
        let doc = serde_json::json!({"provider":"t","rows":[
            serde_json::json!({"op":1}),
            row(1, "A", 1, "h1"),
            row(1, "B", 1, "h1"),
        ]});
        let r = audit(&doc);
        assert_eq!(r["skipped_rows"], 1);
        assert_eq!(r["group_count"], 1);
    }
}
