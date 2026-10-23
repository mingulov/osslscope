// SPDX-License-Identifier: GPL-3.0-or-later
// Independent literal wire fixtures. No resolver or projection builds expected values.
use serde_json::{Value, json};
pub fn package() -> Value {
    json!({
        "selection":"installed-matched",
        "installed_base":{
            "bundle_id":"1111111111111111111111111111111111111111111111111111111111111111",
            "payload_id":"2222222222222222222222222222222222222222222222222222222222222222",
            "input_id":"3333333333333333333333333333333333333333333333333333333333333333",
            "source":{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inventory_sha256":"4444444444444444444444444444444444444444444444444444444444444444"},
            "product_version":"0.2.0", "host_profile":{"target":"x86_64-unknown-linux-gnu","abi_profile":"linux-x86_64-gnu","abi_floor":"GLIBC_2.34"},
            "locks":{"host_sha256":"5555555555555555555555555555555555555555555555555555555555555555","bpf_sha256":"6666666666666666666666666666666666666666666666666666666666666666"},
            "recipe":{"recipe_sha256":"7777777777777777777777777777777777777777777777777777777777777777","config_sha256":"8888888888888888888888888888888888888888888888888888888888888888"},
            "tools":{"host_sha256":"9999999999999999999999999999999999999999999999999999999999999999","bpf_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","linker_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","llvm_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","builder_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","components_sha256":["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]}
        },
        "roles":{
            "harvest":{"selection":"installed-matched","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":17,"build_input_id":"3333333333333333333333333333333333333333333333333333333333333333"},
            "count":{"selection":"installed-matched","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","bytes":19,"build_input_id":"3333333333333333333333333333333333333333333333333333333333333333"},
            "members":{"selection":"installed-matched","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","bytes":23,"build_input_id":"3333333333333333333333333333333333333333333333333333333333333333"}
        }
    })
}
pub fn selection() -> Value {
    json!({"harvest":{"path":"/observer/harvest","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"count":{"path":"/observer/count","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"members":{"path":"/observer/members","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}})
}

// Public v2.2 report fixture captured at 72f55991, before this extension.
pub const HISTORICAL_V2_2: &str = r#"{
  "completeness": {
    "counters": [],
    "fatal_kind": {
      "detail": null,
      "kind": "recycled"
    },
    "reasons": [
      {
        "kind": "startup-gap",
        "missing_ns": 30000
      }
    ],
    "status": "FATAL"
  },
  "context": {
    "kernel_release": "6.9.0-test",
    "wall_end_unix_ns": 1700000030000000000,
    "wall_start_unix_ns": 1700000000000000000
  },
  "coverage": [],
  "fenced": [],
  "legacy_partition": {
    "legacy_exclusive_calls": 0,
    "non_legacy_exclusive_calls": 0,
    "shared_ambiguous_calls": 0,
    "unfenced_tail_calls": 0
  },
  "objects": [],
  "openssl": {
    "state": "unknown",
    "version": null
  },
  "schema_version": "observed-crypto-v2.2",
  "sites": [],
  "target": {
    "argv_redacted": true,
    "comm": "gone",
    "container_id": "",
    "image_digest": "",
    "pid": 11
  },
  "window": {
    "effective_end_ns": 31000,
    "effective_start_ns": 31000,
    "requested_end_ns": 31000,
    "requested_start_ns": 1000,
    "signal_cut": false
  }
}
"#;
