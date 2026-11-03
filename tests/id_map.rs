//! SPDX-License-Identifier: GPL-3.0-or-later
//! Phase 4 ID map: `docs/id-map.md` generated from the frozen
//! `kinds` registries (P1-0 freeze, `REGISTRY_VERSION = 1`).
//!
//! The markdown is never hand-edited: `regenerate_id_map` (env-gated,
//! single writer) rebuilds it, and `id_map_matches_frozen_registries`
//! fails loudly on drift. Labels are non-authoritative display aids;
//! unknown ids render numeric (`OPnn`/`FUNCnn`) in human output.

use osslscope::kinds;
use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn since(version: kinds::Version) -> String {
    format!("{}.{}", version.0, version.1)
}

fn engine_class(class: kinds::EngineClass) -> &'static str {
    match class {
        kinds::EngineClass::Tripwire => "tripwire",
        kinds::EngineClass::Register => "register",
        kinds::EngineClass::Interception => "interception",
        kinds::EngineClass::Other => "other",
    }
}

fn render_id_map() -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# osslscope ID map (registry v{})\n\n",
        kinds::REGISTRY_VERSION
    ));
    out.push_str(
        "Operation, function, and API entry-point ids from the frozen\n\
         registries (`src/kinds.rs`, P1-0 freeze). Sources: `OSSL_OP_*` /\n\
         `OSSL_FUNC_*` from `openssl/core_dispatch.h` (3.0.22, 3.5.8,\n\
         3.6.0, 4.0.2); `ENGINE_*` from `openssl/engine.h` (3.x; 4.x\n\
         ships deprecation stubs only); fetch/SKEY from `evp.h`,\n\
         `kdf.h`, `encoder.h`, `decoder.h`.\n\n\
         Labels are NON-AUTHORITATIVE display aids for human output.\n\
         Identity decisions use exact (object, digest) pairs, never\n\
         these names. Unknown ids stay numeric and explicit in human\n\
         output (`OPnn`, `FUNCnn`); JSON always carries exact numbers.\n\n\
         Do not hand-edit: regenerate with\n\
         `OSSL_REGENERATE_ID_MAP=1 cargo test --test id_map\n\
         regenerate_id_map`, review the diff, then commit.\n\n",
    );
    out.push_str("## Operations (`OSSL_OP_*`)\n\n| id | name | since |\n|----|------|-------|\n");
    for op in kinds::OPS {
        out.push_str(&format!(
            "| {} | {} | {} |\n",
            op.id,
            op.name,
            since(op.since)
        ));
    }
    out.push_str("\n## Functions (`OSSL_FUNC_*`)\n\n| op | id | name | since |\n|----|----|------|-------|\n");
    for func in kinds::FUNCS {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            func.op.unwrap_or("core"),
            func.id,
            func.name,
            since(func.since)
        ));
    }
    out.push_str("\n## ENGINE symbols (3.x only)\n\n| name | class |\n|------|-------|\n");
    for engine in kinds::ENGINE {
        out.push_str(&format!(
            "| {} | {} |\n",
            engine.name,
            engine_class(engine.class)
        ));
    }
    out.push_str("\n## Fetch entry points (`EVP_*_fetch`, `OSSL_*_fetch`)\n\n| name | since |\n|------|-------|\n");
    for fetch in kinds::FETCH {
        out.push_str(&format!("| {} | {} |\n", fetch.name, since(fetch.since)));
    }
    out.push_str("\n## SKEY entry points (`EVP_SKEY_*`, absent in 3.0)\n\n| name | since |\n|------|-------|\n");
    for skey in kinds::SKEY {
        out.push_str(&format!("| {} | {} |\n", skey.name, since(skey.since)));
    }
    out
}

#[test]
fn regenerate_id_map() {
    // Single writer: run filtered
    // (`OSSL_REGENERATE_ID_MAP=1 cargo test --test id_map
    // regenerate_id_map`), review the diff, then commit. Without
    // the env var this is a no-op.
    if std::env::var("OSSL_REGENERATE_ID_MAP").is_err() {
        return;
    }
    let path = manifest_dir().join("docs/id-map.md");
    std::fs::write(&path, render_id_map()).unwrap();
}

#[test]
fn id_map_matches_frozen_registries() {
    let path = manifest_dir().join("docs/id-map.md");
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing {} (regenerate explicitly)", path.display()));
    assert_eq!(want, render_id_map(), "id-map drift: regenerate explicitly");
}
