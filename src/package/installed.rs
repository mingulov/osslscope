// SPDX-License-Identifier: GPL-3.0-or-later
//! Current prefix receipt, separate from historical embedded bundle contracts.
//! Filesystem ownership is the trust root; hashes bind the installed set.
use serde::Deserialize;
use std::path::Path;

pub(crate) const CURRENT_NAMES: [&str; 6] = [
    "osslscope",
    "osslscope-harvest",
    "osslscope-count",
    "osslscope-members",
    "osslscope-provider-observation",
    "osslscope-focused-count",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledReceipt {
    schema: String,
    prefix: String,
    product_ref: String,
    product_dirty: bool,
    artifacts: Vec<InstalledArtifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledArtifact {
    role: String,
    #[serde(default)]
    bin: Option<String>,
    dest: String,
    bytes: u64,
    sha256: String,
    product_ref: String,
}

fn hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
impl InstalledReceipt {
    pub(crate) fn parse(bytes: &[u8], prefix: &Path) -> Option<Self> {
        if bytes.len() > 1 << 20 {
            return None;
        }
        let receipt: Self = serde_json::from_slice(bytes).ok()?;
        if receipt.schema != "osslscope-install-manifest-v2"
            || Path::new(&receipt.prefix) != prefix
            || !hex(&receipt.product_ref, 40)
            || receipt.product_dirty
            || receipt.artifacts.len() != CURRENT_NAMES.len()
        {
            return None;
        }
        for name in CURRENT_NAMES {
            let mut entries = receipt.artifacts.iter().filter(|entry| {
                if name == "osslscope" {
                    entry.role == "host-binary" && entry.bin.is_none()
                } else {
                    entry.role == "bpf-object" && entry.bin.as_deref() == Some(name)
                }
            });
            let entry = entries.next()?;
            let relative = if name == "osslscope" {
                "bin/osslscope".to_string()
            } else {
                format!("lib/osslscope/{name}")
            };
            if entries.next().is_some()
                || entry.product_ref != receipt.product_ref
                || entry.bytes == 0
                || !hex(&entry.sha256, 64)
                || Path::new(&entry.dest) != prefix.join(relative)
            {
                return None;
            }
        }
        Some(receipt)
    }
    pub(crate) fn matches(&self, name: &str, bytes: u64, digest: &str) -> bool {
        self.artifacts.iter().any(|entry| {
            let entry_name = entry.bin.as_deref().unwrap_or("osslscope");
            entry_name == name && entry.bytes == bytes && entry.sha256 == digest
        })
    }
}
