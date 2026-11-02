// SPDX-License-Identifier: GPL-3.0-or-later
// Phase 1 finite acquisition-failure taxonomy: every acquisition refusal
// carries one of nine classes; diagnostics are `class:literal` with no
// paths, addresses, target strings, or errno free text.

/// One of the nine finite acquisition-failure classes (Btrfs plan Phase 1).
/// The class travels with every refusal from producer to artifact to human
/// rendering; the literal after the colon is producer-chosen from the
/// privacy-allowlisted vocabulary (`tests/privacy_allowlist.rs` pins it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AcquisitionCause {
    Identity,
    BackingDenied,
    BackingChanged,
    Namespace,
    SymbolDiscovery,
    BpfLoad,
    Attach,
    DeadlineCancel,
    Limit,
}

impl AcquisitionCause {
    /// Finite wire spelling, also the diagnostic prefix.
    pub fn as_str(&self) -> &'static str {
        match self {
            AcquisitionCause::Identity => "identity",
            AcquisitionCause::BackingDenied => "backing-denied",
            AcquisitionCause::BackingChanged => "backing-changed",
            AcquisitionCause::Namespace => "namespace",
            AcquisitionCause::SymbolDiscovery => "symbol-discovery",
            AcquisitionCause::BpfLoad => "bpf-load",
            AcquisitionCause::Attach => "attach",
            AcquisitionCause::DeadlineCancel => "deadline-cancel",
            AcquisitionCause::Limit => "limit",
        }
    }

    /// One producer-literal diagnostic entry. The caller supplies only an
    /// allowlisted literal (static prose or a finite kind token) — never a
    /// path, address, target string, or errno free text.
    pub fn diagnostic(&self, literal: &str) -> String {
        format!("{}:{literal}", self.as_str())
    }

    /// Classify one failure chain to a finite diagnostic. Prefers a
    /// downcast I/O kind (finite kind token); otherwise the caller's
    /// default class with a fixed site literal. The chain text itself
    /// never enters the diagnostic (no errno free text, paths, or
    /// target strings by Phase 1 construction).
    pub fn from_chain(
        default: AcquisitionCause,
        literal: &'static str,
        e: &anyhow::Error,
    ) -> String {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            let (cause, token) = AcquisitionCause::classify_io_kind(io.kind());
            return cause.diagnostic(token);
        }
        default.diagnostic(literal)
    }

    /// Finite (class, kind-token) for one I/O error kind. The token keeps
    /// the errno class without errno free text.
    pub fn classify_io_kind(kind: std::io::ErrorKind) -> (AcquisitionCause, &'static str) {
        use std::io::ErrorKind::*;
        match kind {
            PermissionDenied => (AcquisitionCause::BackingDenied, "permission-denied"),
            NotFound => (AcquisitionCause::BackingChanged, "not-found"),
            TimedOut => (AcquisitionCause::DeadlineCancel, "timed-out"),
            Interrupted => (AcquisitionCause::DeadlineCancel, "interrupted"),
            ResourceBusy => (AcquisitionCause::Attach, "busy"),
            WouldBlock => (AcquisitionCause::DeadlineCancel, "would-block"),
            FileTooLarge | StorageFull | QuotaExceeded => (AcquisitionCause::Limit, "over-limit"),
            _ => (AcquisitionCause::Attach, "io-failed"),
        }
    }
}

/// Static resolve-failure tops (`harvest::resolve_query_target`): the only
/// texts the resolve site passes through verbatim (with class prefix).
/// Anything else from that site scrubs via [`AcquisitionCause::from_chain`].
pub const RESOLVE_LITERALS: [&str; 2] = [
    "legacy stage-2 attach has no file mapping",
    "stage-2 attach has no provider mapping",
];

/// Static dispatch-anchor tops: the only suffixes the reinstall site keeps
/// in its `dispatch reinstall failed: {top}` shape (with class prefix).
pub const ANCHOR_LITERALS: [&str; 3] = [
    "reinstall init anchor unresolved",
    "reinstall builtin anchor unresolved",
    "no dispatch anchor to reinstall",
];

fn is_kind_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn is_prog_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_hex_offset(s: &str) -> bool {
    s.strip_prefix("0x")
        .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Template-shape check for install-path tops (pin/link/missing-program
/// dispatch-read shapes). Mirrors the privacy-allowlist grammar; producers
/// pass through only matching tops (with class prefix) and scrub the rest
/// via [`AcquisitionCause::from_chain`].
pub fn attach_template_shape(text: &str) -> bool {
    if text == "path contains NUL"
        || text == "stage-2 pin misses the resolve-time identity (cookie retries next poll)"
    {
        return true;
    }
    if let Some(rest) = text.strip_prefix("stage-2 pin open failed (kind=") {
        return rest
            .strip_suffix("; cookie retries next poll)")
            .is_some_and(is_kind_token);
    }
    // Link form `link <name>@<hex-offset> failed (kind=…)` or pin-dup form
    // `pin dup <name>+<name> failed (kind=…)` — static names only. No
    // leading verb: the attach class prefix rides at the artifact boundary.
    if let Some(rest) = text.strip_prefix("link ") {
        if let Some((head, kind)) = rest.rsplit_once(" failed (kind=") {
            let kind_ok = kind.strip_suffix(')').is_some_and(is_kind_token);
            let link_ok = head
                .split_once('@')
                .is_some_and(|(name, off)| is_prog_name(name) && is_hex_offset(off));
            return kind_ok && link_ok;
        }
        return false;
    }
    if let Some(rest) = text.strip_prefix("pin dup ") {
        if let Some((head, kind)) = rest.rsplit_once(" failed (kind=") {
            let kind_ok = kind.strip_suffix(')').is_some_and(is_kind_token);
            let dup_ok = head
                .split_once('+')
                .is_some_and(|(a, b)| is_prog_name(a) && is_prog_name(b));
            return kind_ok && dup_ok;
        }
        return false;
    }
    if let Some(rest) = text.strip_prefix("dispatch maps read failed (kind=") {
        return rest.strip_suffix(')').is_some_and(is_kind_token);
    }
    if let Some(rest) = text.strip_prefix("dispatch provider read failed (kind=") {
        return rest.strip_suffix(')').is_some_and(is_kind_token);
    }
    if let Some(name) = text.strip_prefix("missing program ") {
        return is_prog_name(name);
    }
    false
}

impl From<&crate::provider_observation::schema::ObservationGap> for AcquisitionCause {
    fn from(gap: &crate::provider_observation::schema::ObservationGap) -> Self {
        use crate::provider_observation::schema::ObservationGap::*;
        match gap {
            IdentityUnverified | IntervalUnknown => AcquisitionCause::Identity,
            BackingUnavailable | TargetReadFailed => AcquisitionCause::BackingDenied,
            ProcessChanged | ObjectChanged | ProcessUnavailable => AcquisitionCause::BackingChanged,
            NamespaceChanged => AcquisitionCause::Namespace,
            SymbolUnavailable
            | MalformedElf
            | MalformedMaps
            | AmbiguousSite
            | UnsupportedArchitecture
            | FirstQueryUnknown => AcquisitionCause::SymbolDiscovery,
            BpfUnavailable | InvalidObject | InvalidWire | RelocationRefused => {
                AcquisitionCause::BpfLoad
            }
            AttachFailed | ClassifierFailed | RegistrationRace | MembershipUnknown
            | UnpairedReturn | DispatchPartial | SamplingPartial => AcquisitionCause::Attach,
            SnapshotLag | Invalidated => AcquisitionCause::DeadlineCancel,
            ProcessLimit | ObjectLimit | LinkLimit | PendingLimit | DepthLimit | SiteLimit
            | FactLimit | StateLimit | ReadLimit | QueueLoss | DrainOverrun => {
                AcquisitionCause::Limit
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::acquire_cause::AcquisitionCause;

    #[test]
    fn wire_strings_cover_all_nine_plan_classes() {
        use AcquisitionCause::*;
        assert_eq!(
            [
                Identity.as_str(),
                BackingDenied.as_str(),
                BackingChanged.as_str(),
                Namespace.as_str(),
                SymbolDiscovery.as_str(),
                BpfLoad.as_str(),
                Attach.as_str(),
                DeadlineCancel.as_str(),
                Limit.as_str(),
            ],
            [
                "identity",
                "backing-denied",
                "backing-changed",
                "namespace",
                "symbol-discovery",
                "bpf-load",
                "attach",
                "deadline-cancel",
                "limit",
            ]
        );
    }

    #[test]
    fn diagnostic_prefixes_finite_class_colon_literal() {
        assert_eq!(
            AcquisitionCause::Attach.diagnostic("dispatch-reinstall-failed"),
            "attach:dispatch-reinstall-failed"
        );
    }

    #[test]
    fn every_gap_maps_to_exactly_one_plan_class() {
        use crate::provider_observation::schema::ObservationGap::*;
        use AcquisitionCause::*;
        for (gap, want) in [
            (IdentityUnverified, Identity),
            (IntervalUnknown, Identity),
            (BackingUnavailable, BackingDenied),
            (TargetReadFailed, BackingDenied),
            (ProcessChanged, BackingChanged),
            (ObjectChanged, BackingChanged),
            (ProcessUnavailable, BackingChanged),
            (NamespaceChanged, Namespace),
            (SymbolUnavailable, SymbolDiscovery),
            (MalformedElf, SymbolDiscovery),
            (MalformedMaps, SymbolDiscovery),
            (AmbiguousSite, SymbolDiscovery),
            (UnsupportedArchitecture, SymbolDiscovery),
            (FirstQueryUnknown, SymbolDiscovery),
            (BpfUnavailable, BpfLoad),
            (InvalidObject, BpfLoad),
            (InvalidWire, BpfLoad),
            (RelocationRefused, BpfLoad),
            (AttachFailed, Attach),
            (ClassifierFailed, Attach),
            (RegistrationRace, Attach),
            (MembershipUnknown, Attach),
            (UnpairedReturn, Attach),
            (DispatchPartial, Attach),
            (SamplingPartial, Attach),
            (SnapshotLag, DeadlineCancel),
            (Invalidated, DeadlineCancel),
            (ProcessLimit, Limit),
            (ObjectLimit, Limit),
            (LinkLimit, Limit),
            (PendingLimit, Limit),
            (DepthLimit, Limit),
            (SiteLimit, Limit),
            (FactLimit, Limit),
            (StateLimit, Limit),
            (ReadLimit, Limit),
            (QueueLoss, Limit),
            (DrainOverrun, Limit),
        ] {
            assert_eq!(AcquisitionCause::from(&gap), want, "{gap:?}");
        }
    }

    #[test]
    fn resolve_and_anchor_literal_sets_are_exact() {
        use crate::acquire_cause::{ANCHOR_LITERALS, RESOLVE_LITERALS};
        assert_eq!(
            RESOLVE_LITERALS,
            [
                "legacy stage-2 attach has no file mapping",
                "stage-2 attach has no provider mapping",
            ]
        );
        assert_eq!(
            ANCHOR_LITERALS,
            [
                "reinstall init anchor unresolved",
                "reinstall builtin anchor unresolved",
                "no dispatch anchor to reinstall",
            ]
        );
    }

    #[test]
    fn attach_template_matcher_accepts_only_vocabulary_shapes() {
        use crate::acquire_cause::attach_template_shape;
        assert!(attach_template_shape(
            "stage-2 pin open failed (kind=NotFound; cookie retries next poll)"
        ));
        assert!(attach_template_shape(
            "link query_entry@0x1234 failed (kind=PermissionDenied)"
        ));
        assert!(attach_template_shape(
            "pin dup query_entry+query_return failed (kind=NotFound)"
        ));
        assert!(attach_template_shape("missing program query_entry"));
        assert!(attach_template_shape("path contains NUL"));
        assert!(attach_template_shape(
            "dispatch maps read failed (kind=InvalidData)"
        ));
        assert!(attach_template_shape(
            "dispatch provider read failed (kind=error)"
        ));
        assert!(attach_template_shape(
            "stage-2 pin misses the resolve-time identity (cookie retries next poll)"
        ));
        assert!(!attach_template_shape(
            "stage-2 pin open failed (kind=No way)"
        ));
        assert!(!attach_template_shape(
            "attach /proc/1/map_files failed (kind=X)"
        ));
        assert!(!attach_template_shape(
            "missing program query-entry; rm -rf"
        ));
        assert!(!attach_template_shape(""));
    }

    #[test]
    fn chain_classification_prefers_io_kind_else_site_literal() {
        let io = anyhow::anyhow!(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(
            AcquisitionCause::from_chain(AcquisitionCause::Attach, "install-failed", &io),
            "backing-denied:permission-denied"
        );
        let other = anyhow::anyhow!("stage-2 attach has no provider mapping");
        assert_eq!(
            AcquisitionCause::from_chain(
                AcquisitionCause::SymbolDiscovery,
                "resolve-failed",
                &other
            ),
            "symbol-discovery:resolve-failed"
        );
        // Chain text never leaks into the diagnostic.
        let leaky = anyhow::anyhow!("/proc/1234/map_files: permission denied (os error 13)");
        let out = AcquisitionCause::from_chain(AcquisitionCause::Attach, "install-failed", &leaky);
        assert!(!out.contains('/'), "{out}");
        assert!(!out.contains("1234"), "{out}");
        // A wrapped I/O source still yields its finite kind token.
        let wrapped = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("outer template kept elsewhere");
        assert_eq!(
            AcquisitionCause::from_chain(AcquisitionCause::Attach, "install-failed", &wrapped),
            "backing-changed:not-found"
        );
    }

    #[test]
    fn io_kinds_map_to_finite_class_and_token() {
        use std::io::ErrorKind::*;
        assert_eq!(
            AcquisitionCause::classify_io_kind(PermissionDenied),
            (AcquisitionCause::BackingDenied, "permission-denied")
        );
        assert_eq!(
            AcquisitionCause::classify_io_kind(NotFound),
            (AcquisitionCause::BackingChanged, "not-found")
        );
        assert_eq!(
            AcquisitionCause::classify_io_kind(TimedOut),
            (AcquisitionCause::DeadlineCancel, "timed-out")
        );
        assert_eq!(
            AcquisitionCause::classify_io_kind(ResourceBusy),
            (AcquisitionCause::Attach, "busy")
        );
    }
}
