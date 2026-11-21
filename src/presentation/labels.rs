// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C label allowlist + frozen value vocabularies (§6C-5). One
//! allowlist governs both exporters.
use std::collections::HashSet;
use std::sync::OnceLock;

/// Closed label-name allowlist (†, §6C-5).
pub const NAMES: [&str; 11] = [
    "outcome",
    "completeness",
    "lane",
    "loss_cause",
    "gap_class",
    "cut",
    "openssl_family",
    "outcome_class",
    "drop_reason",
    "le",
    "api",
];

/// Closed value vocabularies (§6C-5 tables).
pub const OUTCOME: [&str; 5] = [
    "pass",
    "violation",
    "inconclusive",
    "no_verdict",
    "observe_only",
];
pub const COMPLETENESS: [&str; 3] = ["complete", "partial", "fatal"];
pub const LANE: [&str; 4] = [
    "legacy_exclusive",
    "non_legacy_exclusive",
    "shared_ambiguous",
    "unfenced_tails",
];
/// The 12 `LossCause` wire words (C-01 order).
pub const LOSS_CAUSE: [&str; 12] = [
    "corpse_wait",
    "cgroup_move",
    "membership_unknown",
    "ring_loss",
    "connector_drops",
    "connector_enobufs",
    "scan_loss",
    "signal_prefix_unwitnessed",
    "drain_pending",
    "exec_spanning_aggregate",
    "coalesced_loss",
    "skipped_tick",
];
pub const GAP_CLASS: [&str; 10] = [
    "unknown_denominator",
    "undiscovered_sites",
    "unattached_sites",
    "loss",
    "unattributed_calls",
    "startup_gap",
    "tail_gap",
    "signal_cut",
    "visibility_lost",
    "no_reasons",
];
pub const CUT: [&str; 4] = ["none", "signal_cut", "accum_cut", "both_cuts"];
pub const OPENSSL_FAMILY: [&str; 5] = ["3.0", "3.5", "3.6", "4.0", "unknown"];
/// The §6D-2 class names, same spelling.
pub const OUTCOME_CLASS: [&str; 5] = ["success", "failure", "empty", "retry", "unknown"];
pub const DROP_REASON: [&str; 3] = ["queue_full", "epipe", "stream_abandoned"];
/// The 19 P-17 bucket bounds as exact strings.
pub const LE: [&str; 19] = [
    "50", "100", "250", "500", "1000", "2000", "4000", "8000", "16000", "32000", "64000", "128000",
    "256000", "512000", "1000000", "2000000", "5000000", "10000000", "+Inf",
];

fn sets() -> &'static Vec<HashSet<&'static str>> {
    static SETS: OnceLock<Vec<HashSet<&'static str>>> = OnceLock::new();
    SETS.get_or_init(|| {
        [
            OUTCOME.as_slice(),
            COMPLETENESS.as_slice(),
            LANE.as_slice(),
            LOSS_CAUSE.as_slice(),
            GAP_CLASS.as_slice(),
            CUT.as_slice(),
            OPENSSL_FAMILY.as_slice(),
            OUTCOME_CLASS.as_slice(),
            DROP_REASON.as_slice(),
            LE.as_slice(),
        ]
        .into_iter()
        .map(|s| s.iter().copied().collect())
        .collect()
    })
}

/// Closed name check (§6C-5).
pub fn is_name_allowed(name: &str) -> bool {
    NAMES.contains(&name)
}

/// Closed value check (§6C-5). `api` takes decimal IDs 20..=72 only.
pub fn is_value_allowed(name: &str, value: &str) -> bool {
    if name == "api" {
        return match value.parse::<u32>() {
            // Canonical decimal spelling only (no leading zeros).
            Ok(id) => (20..=72).contains(&id) && value == id.to_string(),
            Err(_) => false,
        };
    }
    let idx = match NAMES.iter().position(|n| *n == name) {
        Some(i) => i,
        None => return false,
    };
    sets()[idx].contains(value)
}

/// Frozen spelling rule (§6C-5, ordered steps): (1) drop any
/// `:<suffix>`; (2) split CamelCase boundaries with `_`; (3) `-` →
/// `_`; (4) lowercase.
pub fn fold_word(source: &str) -> String {
    let head = source.split(':').next().unwrap_or("");
    let mut out = String::with_capacity(head.len() + 4);
    let mut prev: Option<char> = None;
    for ch in head.chars() {
        if ch == '-' {
            out.push('_');
        } else if ch.is_ascii_uppercase()
            && matches!(prev, Some(p) if p.is_ascii_lowercase() || p.is_ascii_digit())
        {
            out.push('_');
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch.to_ascii_lowercase());
        }
        prev = Some(ch);
    }
    out
}

/// `LossCause` word → epoch-bucket index (C-01 order).
pub fn loss_cause_index(word: &str) -> Option<usize> {
    LOSS_CAUSE.iter().position(|w| *w == word)
}

/// Gap-class word → epoch-bucket index (§6C-5 order).
pub fn gap_class_index(word: &str) -> Option<usize> {
    GAP_CLASS.iter().position(|w| *w == word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_values_are_decimal_ids_only() {
        assert!(is_value_allowed("api", "20"));
        assert!(is_value_allowed("api", "72"));
        assert!(!is_value_allowed("api", "19"));
        assert!(!is_value_allowed("api", "73"));
        assert!(!is_value_allowed("api", "042"));
        assert!(!is_value_allowed("api", "4a"));
        assert!(!is_value_allowed("api", ""));
    }

    #[test]
    fn fold_order_is_load_bearing() {
        // Lowercasing first would destroy the boundary.
        assert_eq!(fold_word("NoVerdict"), "no_verdict");
        assert_ne!(fold_word("NoVerdict"), "noverdict");
    }
}
