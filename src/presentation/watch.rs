// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C terminal watch (§6C-9 frame contract, §6C-10 non-TTY).
use super::snapshot::{OperatorSnapshot, Presenter, checkpoint_default};
use std::path::PathBuf;
use std::process::ExitCode;

const HELP: &str = "usage: osslscope watch --out DIR [--poll-seconds S] [--format human|json] [--checkpoint PATH] [--follow]\nRender one operator frame from the service out-DIR (read-only). Non-TTY renders exactly one frame and exits 0.\n";

struct Options {
    out: PathBuf,
    poll_secs: u64,
    format_json: bool,
    checkpoint: Option<PathBuf>,
    follow: bool,
}

fn parse(args: &[String]) -> Result<Options, ()> {
    if args.first().map(String::as_str) != Some("watch") {
        return Err(());
    }
    let mut out: Option<PathBuf> = None;
    let mut poll_secs = 5u64;
    let mut format_json = false;
    let mut checkpoint: Option<PathBuf> = None;
    let mut follow = false;
    let mut it = args[1..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--out" if out.is_none() => {
                out = Some(PathBuf::from(it.next().ok_or(())?));
            }
            "--poll-seconds" => {
                let v: u64 = it.next().ok_or(())?.parse().map_err(|_| ())?;
                if !(1..=3600).contains(&v) {
                    return Err(());
                }
                poll_secs = v;
            }
            "--format" => match it.next().ok_or(())?.as_str() {
                "human" => format_json = false,
                "json" => format_json = true,
                _ => return Err(()),
            },
            "--checkpoint" if checkpoint.is_none() => {
                checkpoint = Some(PathBuf::from(it.next().ok_or(())?));
            }
            "--follow" if !follow => follow = true,
            "--help" | "-h" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            _ => return Err(()),
        }
    }
    Ok(Options {
        out: out.ok_or(())?,
        poll_secs,
        format_json,
        checkpoint,
        follow,
    })
}

fn is_tty() -> bool {
    // SAFETY: isatty on a valid fd.
    unsafe { libc::isatty(1) == 1 }
}

/// Bound one frame line (200 chars, C-17 `bound_line` rule) and
/// strip ASCII control characters (item 6 — persisted strings
/// such as counter names must not inject escapes or line breaks
/// into terminal output on any profile).
fn bound_line(line: &str) -> String {
    const MAX: usize = 200;
    let clean: String = line.chars().filter(|c| !c.is_control()).collect();
    if clean.len() <= MAX {
        return clean;
    }
    let mut cut = MAX;
    while cut > 0 && !clean.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &clean[..cut])
}

/// Render one frame (§6C-9, nine sections in order). The frame
/// delivers the snapshot's own folded-window markers (P2fix2 item
/// 13 — first applicable frame, never an empty marker set).
pub fn render_frame(snap: &OperatorSnapshot) -> String {
    render_frame_with_prev(snap, None, 0, &snap.markers)
}

/// Previous-epoch payload for the §6C-3 tail: either the last
/// published frame (a normal generation change — the legacy
/// line, byte-identical) or the preserved failed-unpublished
/// epoch (P2fix11 NEW-67 — the TRUE previous epoch WITH its
/// uncertainty, preferred over last-good).
pub enum PrevEpoch<'a> {
    Snapshot(&'a OperatorSnapshot),
    Preserved(&'a super::snapshot::PreservedEpoch),
}

/// Splice a compact `previous_epoch` object behind the opening
/// brace of a pretty-printed follow frame (P2fix11 NEW-67): the
/// frame's own bytes survive untouched (a flattened re-wrap
/// would re-emit every key through a map and reorder them), so
/// frames without preservation are byte-identical to before and
/// preserved frames differ only by this leading key. The JSON
/// frame keeps the FULL range list (no cap — P2fix12 NEW-73).
fn splice_previous_epoch(frame: &[u8], prev: &super::snapshot::PreservedEpoch) -> Option<Vec<u8>> {
    if frame.first() != Some(&b'{') {
        return None;
    }
    let compact = serde_json::to_vec(prev).ok()?;
    let mut out = Vec::with_capacity(frame.len() + compact.len() + 24);
    out.push(b'{');
    out.extend_from_slice(b"\n  \"previous_epoch\": ");
    out.extend_from_slice(&compact);
    out.push(b',');
    out.extend_from_slice(&frame[1..]);
    Some(out)
}

/// Render the `prev-unmeasured` tail line (P2fix12 NEW-73): a
/// short payload renders the full `Debug` list (byte-identical
/// to before); a payload above the 200-char bound renders
/// COMPLETE bounded entries with an EXACT omitted-range count
/// (`.., +N more]` — never a mid-list cut). The constructed
/// line is ≤ 200 chars BY CONSTRUCTION (each entry appends
/// only when the entry + its eventual suffix fit), so the
/// frame cap below never cuts it.
fn prev_unmeasured_line(unmeasured: &[[u64; 2]]) -> String {
    const MAX: usize = 200;
    let full = format!("  prev-unmeasured={unmeasured:?}");
    if full.len() <= MAX {
        return full;
    }
    let total = unmeasured.len();
    let mut line = String::from("  prev-unmeasured=[");
    let mut omitted = total;
    for range in unmeasured {
        let entry = format!("{range:?}");
        let sep = if omitted == total { "" } else { ", " };
        let rest = omitted - 1;
        // Suffix if we stop AFTER this entry (no trailing
        // comma when nothing is omitted — unreachable here,
        // since then `full` would have fit, but exact anyway).
        let suffix = if rest == 0 {
            "]".to_string()
        } else {
            format!(", +{rest} more]")
        };
        if line.len() + sep.len() + entry.len() + suffix.len() > MAX {
            break;
        }
        line.push_str(sep);
        line.push_str(&entry);
        omitted = rest;
    }
    if omitted == total {
        // No entry fit (only for absurdly wide scalars —
        // `u64::MAX` pairs still fit one) — the count alone.
        line.push_str(&format!("+{omitted} more]"));
    } else if omitted == 0 {
        line.push(']');
    } else {
        line.push_str(&format!(", +{omitted} more]"));
    }
    line
}

/// Render one frame with an optional previous-epoch tail (§6C-3
/// `PREVIOUS EPOCH` line, retained by the watch loop across a
/// generation change until the first new-epoch window finalizes).
pub fn render_frame_with_prev(
    snap: &OperatorSnapshot,
    prev: Option<PrevEpoch<'_>>,
    coalesced: u64,
    markers: &[String],
) -> String {
    let mut lines: Vec<String> = vec![];
    // (1) header.
    let run_tag = snap.source.run_id.as_ref().map(|r| {
        format!(
            "{}-{}-{}",
            r.pid,
            r.starttime,
            r.boot_id.chars().take(8).collect::<String>()
        )
    });
    lines.push(format!(
        "osslscope {} seq={} gen={} run={} win={} age={} coalesced={}{}",
        snap.schema,
        snap.snapshot_seq,
        snap.source
            .generation
            .map(|g| g.to_string())
            .unwrap_or_else(|| "?".to_string()),
        run_tag.as_deref().unwrap_or("?"),
        snap.source
            .window_seq
            .map(|s| s.to_string())
            .unwrap_or_else(|| "?".to_string()),
        snap.health
            .snapshot_age_ns
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".to_string()),
        coalesced,
        if snap.health.stale { " STALE" } else { "" },
    ));
    match prev {
        Some(PrevEpoch::Snapshot(p)) => {
            lines.push(format!(
                "PREVIOUS EPOCH gen={} calls={} win={}",
                p.source
                    .generation
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                p.counts.calls_total,
                p.source
                    .window_seq
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".to_string()),
            ));
        }
        Some(PrevEpoch::Preserved(p)) => {
            // The preserved finals WITH their uncertainty
            // (P2fix11 NEW-67): the base line stays short (the
            // C-17 200-char bound would truncate a single-line
            // tail and DROP the uncertainty), so the flags
            // (sorted comma-joined, `-` when certain) and the
            // ranges (Debug-spelled, matching the TRACE
            // `unmeasured=` lines) ride two continuation lines.
            lines.push(format!(
                "PREVIOUS EPOCH gen={} calls={} win={}",
                p.generation, p.calls_total, p.window_seq,
            ));
            let unstable = if p.unstable.is_empty() {
                "-".to_string()
            } else {
                p.unstable.join(",")
            };
            lines.push(format!("  prev-unstable={unstable}"));
            // Bounded range entries + exact omitted count
            // (P2fix12 NEW-73 — never a mid-list cut).
            lines.push(prev_unmeasured_line(&p.unmeasured));
        }
        None => {}
    }
    // (2) WINDOW.
    match snap.window.as_ref() {
        Some(w) => lines.push(format!(
            "WINDOW {}..{} eff={}..{} signal_cut={} accum_cut={} completeness={} reasons={}",
            w.requested_start_ns,
            w.requested_end_ns,
            w.effective_start_ns,
            w.effective_end_ns,
            w.signal_cut,
            w.accum_cut,
            snap.completeness.state.as_deref().unwrap_or("?"),
            first_n(&snap.completeness.reasons, 3),
        )),
        None => lines.push("WINDOW ? not_yet_observed".to_string()),
    }
    // Sticky alert markers (§6C-9 coalescing: partial/fatal/cut/
    // violation windows leave marker lines in every later frame of
    // the epoch). Capped like other lists (first 8 + N more).
    for marker in markers.iter().take(8) {
        lines.push(format!("MARKER {marker}"));
    }
    if markers.len() > 8 {
        lines.push(format!("MARKER +{} more", markers.len() - 8));
    }
    // (3) POLICY.
    lines.push(format!(
        "POLICY outcome={} active={}",
        snap.policy.outcome.as_deref().unwrap_or("?"),
        snap.policy
            .active
            .as_ref()
            .map(|a| short16(&a.sha256))
            .unwrap_or_else(|| "observe-only".to_string()),
    ));
    // (4) COUNTS.
    lines.push(format!(
        "COUNTS epoch={} window={} lanes={}/{}/{}/{} site_rows={} by_outcome={}",
        snap.counts.calls_total,
        opt_u64(snap.counts.calls_window),
        snap.counts.lanes.legacy_exclusive,
        snap.counts.lanes.non_legacy_exclusive,
        snap.counts.lanes.shared_ambiguous,
        snap.counts.lanes.unfenced_tails,
        opt_u64(snap.counts.site_rows),
        snap.counts
            .by_outcome
            .map(|b| format!("{}/{}/{}", b.success, b.failure, b.unknown))
            .unwrap_or_else(|| "? trace_disabled".to_string()),
    ));
    // (5) MEMBERS.
    lines.push(format!(
        "MEMBERS observed={} retired_window={} retired_epoch={} deferred={}",
        opt_u64(snap.members.observed),
        opt_u64(snap.members.retired_in_window),
        snap.members.retired_epoch,
        opt_u64(snap.members.deferred_depth),
    ));
    // (6) LOSS.
    let counters = &snap.loss.counters;
    let shown = counters.len().min(8);
    lines.push(format!(
        "LOSS session={} counters={}{}",
        snap.loss
            .session
            .as_ref()
            .map(|s| format!("ring={:?} unattributed={}", s.ring, s.unattributed_events))
            .unwrap_or_else(|| "?".to_string()),
        shown,
        if counters.len() > 8 {
            format!(" +{} more", counters.len() - 8)
        } else {
            String::new()
        },
    ));
    for c in counters.iter().take(8) {
        lines.push(format!(
            "  counter name={} kind={} value={}",
            c.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
            c.get("kind").and_then(|v| v.as_str()).unwrap_or("?"),
            c.get("value")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".to_string()),
        ));
    }
    if let Some(session) = snap.loss.session.as_ref() {
        for interval in session.lost_intervals.iter().take(8) {
            lines.push(format!(
                "  lost [{}..{}) {}",
                interval.start_tick, interval.end_tick, interval.cause,
            ));
        }
        if session.lost_intervals.len() > 8 {
            lines.push(format!(
                "  +{} more intervals",
                session.lost_intervals.len() - 8
            ));
        }
    }
    // (7) STREAM.
    match snap.stream.as_ref() {
        Some(s) => lines.push(format!(
            "STREAM drops={} bytes={} pending={}",
            s.drops.records,
            s.drops.bytes,
            opt_u64(s.pending_spans),
        )),
        None => lines.push("STREAM ? stream_unconfigured".to_string()),
    }
    // (8) TRACE.
    match snap.trace.as_ref() {
        Some(t) => {
            // Unbound window projection (P2fix3 NEW-P2e): a late
            // cut withholds paired as evidence with the cause
            // named; diagnostics print either way.
            let paired = if t.cut_unbound {
                "withheld (late-cut)".to_string()
            } else {
                t.paired.to_string()
            };
            lines.push(format!(
                "TRACE seq={} mode={} paired={} unpaired_e={} unpaired_r={} depth={} dropped={} capped={} nonmono={} rejected={}",
                t.window_seq,
                t.mode,
                paired,
                t.trace_unpaired_entries,
                t.trace_unpaired_results,
                t.trace_depth_exceeded,
                t.trace_dropped,
                t.trace_capped,
                t.trace_nonmonotonic_pairs,
                t.trace_rejected_unknown_api,
            ));
            match t.class_window.as_ref() {
                Some(c) => lines.push(format!(
                    "  class success={} failure={} empty={} retry={} unknown={}",
                    c.success, c.failure, c.empty, c.retry, c.unknown,
                )),
                None => lines.push("  class withheld (pairing uncertainty)".to_string()),
            }
            if !t.unmeasured_seqs.is_empty() {
                lines.push(format!("  unmeasured={:?}", t.unmeasured_seqs));
            }
            for g in t.gaps.iter().take(3) {
                lines.push(format!("  gap {g}"));
            }
            if t.gaps.len() > 3 {
                lines.push(format!("  +{} more gaps", t.gaps.len() - 3));
            }
            for e in t.exemplars.iter().take(4) {
                lines.push(format!(
                    "  exemplar {} {} api={} age={}",
                    e.dir, e.key_hash16, e.api, e.age_ns,
                ));
            }
            if t.exemplars.len() > 4 {
                lines.push(format!("  +{} more exemplars", t.exemplars.len() - 4));
            }
        }
        None => lines.push("TRACE ? trace_disabled".to_string()),
    }
    // Histograms summary (rides the TRACE section per §6D-3).
    if let Some(h) = snap.histograms.as_ref() {
        lines.push(format!(
            "HIST edges={} seqs={}..{} capped_folded={} counts={}/{}/{}/{}/{}",
            h.edges,
            h.first_seq,
            h.last_seq,
            h.capped_folded,
            h.success.count,
            h.failure.count,
            h.empty.count,
            h.retry.count,
            h.unknown.count,
        ));
        if !h.unmeasured_seqs.is_empty() {
            lines.push(format!("  unmeasured={:?}", h.unmeasured_seqs));
        }
    }
    // (9) UNKNOWN.
    if snap.unknown.is_empty() {
        lines.push("UNKNOWN none".to_string());
    } else {
        lines.push(format!("UNKNOWN {}", snap.unknown.len()));
        for e in snap.unknown.iter() {
            match e.note.as_deref() {
                Some(note) => lines.push(format!("  {} {} ({note})", e.path, e.reason)),
                None => lines.push(format!("  {} {}", e.path, e.reason)),
            }
        }
    }
    if snap.presenter.series_overflow > 0 {
        lines.push(format!(
            "series_overflow: {}",
            snap.presenter.series_overflow
        ));
    }
    // Frame cap: 500 lines MAXIMUM with conserved overflow (the
    // dropped count survives the cap as a final line — item 25).
    let total = lines.len();
    let frame: Vec<String> = if total > 500 {
        let mut frame: Vec<String> = lines
            .into_iter()
            .take(499)
            .map(|l| bound_line(&l))
            .collect();
        frame.push(format!("+{} more frame lines", total - 499));
        frame
    } else {
        lines.into_iter().map(|l| bound_line(&l)).collect()
    };
    let mut out = frame.join("\n");
    out.push('\n');
    out
}

fn opt_u64(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "?".to_string())
}

fn first_n(items: &[String], n: usize) -> String {
    if items.is_empty() {
        return "-".to_string();
    }
    let mut s = items.iter().take(n).cloned().collect::<Vec<_>>().join(",");
    if items.len() > n {
        s.push_str(&format!(" +{} more", items.len() - n));
    }
    s
}

fn short16(sha: &str) -> String {
    sha.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prev_with_ranges(unmeasured: Vec<[u64; 2]>) -> super::super::snapshot::PreservedEpoch {
        super::super::snapshot::PreservedEpoch {
            generation: 7,
            window_seq: 9,
            calls_total: 11,
            lanes: [11, 0, 0, 0],
            unstable: vec!["counts.calls_total".to_string()],
            unmeasured,
        }
    }

    #[test]
    fn new73_short_payload_renders_full_list_verbatim() {
        // P2fix12 NEW-73 (no-regression half): payloads at or
        // below the bound render the full Debug list,
        // byte-identical to before (small payloads never gain
        // a count suffix).
        assert_eq!(prev_unmeasured_line(&[]), "  prev-unmeasured=[]");
        assert_eq!(
            prev_unmeasured_line(&[[1, 1]]),
            "  prev-unmeasured=[[1, 1]]"
        );
        let ranges: Vec<[u64; 2]> = (0..10u64).map(|k| [k * 3 + 1, k * 3 + 2]).collect();
        let line = prev_unmeasured_line(&ranges);
        assert_eq!(line, format!("  prev-unmeasured={ranges:?}"));
        assert!(line.len() <= 200, "the small payload fits: {line:?}");
    }

    #[test]
    fn new73_bounded_payload_renders_complete_entries_with_exact_count() {
        // P2fix12 NEW-73 (unit half — the snapshot
        // `new73_bounded_ranges_...` pin carries the pipeline):
        // a 36-range payload renders COMPLETE entries within
        // 200 chars with the EXACT omitted count, and the
        // frame cap never cuts it (no `…`).
        let ranges: Vec<[u64; 2]> = (0..36u64).map(|k| [k * 3 + 1, k * 3 + 2]).collect();
        let line = prev_unmeasured_line(&ranges);
        assert!(
            line.len() <= 200,
            "the line respects the bound ({}): {line:?}",
            line.len()
        );
        assert_eq!(bound_line(&line), line, "the frame cap never cuts it");
        let shown = line
            .as_bytes()
            .windows(2)
            .filter(|w| w[0] == b'[' && w[1].is_ascii_digit())
            .count();
        assert!(shown > 0 && shown < 36, "bounded but nonempty: {line:?}");
        assert!(
            line.contains(&format!("+{} more", 36 - shown)),
            "the exact omitted-range count: {line:?}"
        );
        assert!(
            line.starts_with("  prev-unmeasured=[[1, 2], [4, 5]"),
            "complete entries from the front: {line:?}"
        );
        // Wide scalars: u64::MAX pairs still bound correctly.
        let wide = vec![[u64::MAX, u64::MAX]; 36];
        let wide_line = prev_unmeasured_line(&wide);
        assert!(wide_line.len() <= 200, "wide scalars bound: {wide_line:?}");
        assert_eq!(bound_line(&wide_line), wide_line, "no cut on wide scalars");
    }

    #[test]
    fn new73_json_splice_keeps_full_range_list() {
        // P2fix12 NEW-73 (JSON half): the spliced follow frame
        // keeps the FULL 36-range list (no cap on JSON) with
        // the frame body otherwise untouched.
        let ranges: Vec<[u64; 2]> = (0..36u64).map(|k| [k * 3 + 1, k * 3 + 2]).collect();
        let prev = prev_with_ranges(ranges.clone());
        let frame = b"{\n  \"source\": 1\n}\n";
        let spliced = splice_previous_epoch(frame, &prev).expect("the frame splices");
        let v: serde_json::Value = serde_json::from_slice(&spliced).expect("valid JSON");
        assert_eq!(v["source"], serde_json::json!(1), "the body survives");
        assert_eq!(
            v["previous_epoch"]["unmeasured"]
                .as_array()
                .map(|a| a.len()),
            Some(36),
            "the full range list survives"
        );
        assert_eq!(
            v["previous_epoch"]["unmeasured"][35],
            serde_json::json!([106, 107]),
            "the last range is exact"
        );
    }

    #[test]
    fn new73_unstable_line_never_hits_the_bound() {
        // P2fix12 NEW-73 (sibling-line guard): the closed
        // 8-word flag vocabulary caps the `prev-unstable` line
        // at 166 chars — it never needs bounding.
        let flags = [
            "counts.calls_total",
            "counts.lanes",
            "members.retired_epoch",
            "counts.by_outcome",
            "loss.epoch_by_cause",
            "completeness.epoch_partial_by_class",
            "histograms",
            "stream.drops",
        ];
        let line = format!("  prev-unstable={}", flags.join(","));
        assert!(line.len() <= 200, "the full flag line fits: {line:?}");
        assert_eq!(bound_line(&line), line, "the frame cap never cuts it");
    }
}

/// Watch entry: non-TTY renders exactly one frame and exits 0
/// (§6C-10); `--follow` (or a TTY) polls.
pub fn run(args: &[String]) -> ExitCode {
    let opts = match parse(args) {
        Ok(o) => o,
        Err(()) => {
            eprintln!("{HELP}");
            return ExitCode::from(2);
        }
    };
    let checkpoint = opts
        .checkpoint
        .clone()
        .unwrap_or_else(|| checkpoint_default(&opts.out));
    let mut presenter = match Presenter::open_with_checkpoint(
        &opts.out,
        &checkpoint,
        super::snapshot::WINDOW_SECS_FALLBACK,
        "watch",
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("osslscope: {e}");
            return ExitCode::from(1);
        }
    };
    // Pre-first-window with an unreadable out-DIR is exit 1 (never
    // a partial frame); `build_service` reports it.
    let tty = is_tty();
    if !tty && !opts.follow {
        return match presenter.build_service() {
            Ok(snap) => {
                // Settled with residue (P2fix15 NEW-89): the
                // commit stands — each leftover reports loudly
                // (stdout keeps the frame only).
                for r in presenter.take_flush_residue() {
                    eprintln!("osslscope: watch: checkpoint committed with residue: {r}");
                }
                if opts.format_json {
                    match serde_json::to_vec_pretty(&snap) {
                        Ok(mut bytes) => {
                            bytes.push(b'\n');
                            let _ = std::io::Write::write_all(&mut std::io::stdout(), &bytes);
                        }
                        Err(e) => {
                            eprintln!("osslscope: {e}");
                            return ExitCode::from(1);
                        }
                    }
                } else {
                    print!("{}", render_frame(&snap));
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(1)
            }
        };
    }
    // Poll loop (TTY default, or --follow anywhere): plain re-print
    // per refresh, no cursor control; `--follow` frames carry the
    // banner line.
    let mut last_built: Option<OperatorSnapshot> = None;
    let mut last_gen: Option<u64> = None;
    let mut last_seq: Option<u64> = None;
    let mut markers: Vec<String> = vec![];
    // A first-build failure is fatal (config errors surface
    // immediately); later failures are window-file outages
    // (last-good retained, recovery advances — P2fix2 item 21).
    let mut built_once = false;
    loop {
        match presenter.build_service() {
            Ok(snap) => {
                built_once = true;
                // Settled with residue (P2fix15 NEW-89): the
                // commit stands — each leftover reports loudly
                // on stderr (the frame path is untouched).
                for r in presenter.take_flush_residue() {
                    eprintln!("osslscope: watch: checkpoint committed with residue: {r}");
                }
                let generation = snap.source.generation;
                // Previous-epoch tail (P2fix11 NEW-67): the
                // preserved failed-unpublished epoch wins over
                // last-good (it is the TRUE previous epoch);
                // last-good covers normal generation changes.
                // Shown exactly once: on the first frame of a new
                // generation, or on the very first frame when a
                // restored preservation exists. Markers clear at
                // the epoch boundary (generation-bound, P2fix2
                // item 13).
                let preserved = presenter.previous_epoch();
                let gen_changed = last_gen.is_some() && generation != last_gen;
                let show_prev = if gen_changed {
                    preserved
                        .as_ref()
                        .map(PrevEpoch::Preserved)
                        .or_else(|| last_built.as_ref().map(PrevEpoch::Snapshot))
                } else if last_gen.is_none() {
                    preserved.as_ref().map(PrevEpoch::Preserved)
                } else {
                    None
                };
                let show_preserved_json = match &show_prev {
                    Some(PrevEpoch::Preserved(p)) => Some(*p),
                    _ => None,
                };
                if generation != last_gen {
                    markers.clear();
                }
                // Sticky alert markers, imported BEFORE rendering
                // (P2fix2 item 13): every window folded in this
                // build contributes its loss/cut/partial/fatal/
                // violation facts (item 25 — not just the latest
                // window), so the first applicable frame already
                // carries them; they persist across later frames of
                // the epoch (§6C-9 coalescing).
                for marker in snap.markers.iter() {
                    if !markers.contains(marker) {
                        markers.push(marker.clone());
                    }
                }
                // Coalesced windows since the last framed window
                // (§6C-9 header count).
                let coalesced = match (last_seq, snap.source.window_seq) {
                    (Some(prev), Some(cur)) if generation == last_gen && cur > prev => {
                        cur.saturating_sub(prev).saturating_sub(1)
                    }
                    _ => 0,
                };
                if opts.follow {
                    // The banner carries the exact coalesced-window
                    // count (P2fix5 NEW-29 — the JSON follow stream
                    // exposes it too, not just the human header;
                    // the snapshot body itself is unchanged).
                    println!("--- frame {} coalesced={coalesced} ---", snap.snapshot_seq);
                }
                if opts.format_json {
                    // Same generation-bound facts as the human frame
                    // (P2fix3 NEW-P2h — the sticky marker set, not
                    // just this build's) + the preserved previous
                    // epoch exactly when the human tail would show
                    // it (P2fix11 NEW-67 — spliced behind the
                    // opening brace; the frame's own bytes are
                    // untouched).
                    let mut out = snap.clone();
                    out.markers = markers.clone();
                    match serde_json::to_vec_pretty(&out) {
                        Ok(pretty) => {
                            let mut bytes = match show_preserved_json {
                                Some(p) => splice_previous_epoch(&pretty, p).unwrap_or(pretty),
                                None => pretty,
                            };
                            bytes.push(b'\n');
                            let _ = std::io::Write::write_all(&mut std::io::stdout(), &bytes);
                        }
                        Err(e) => {
                            eprintln!("osslscope: {e}");
                            return ExitCode::from(1);
                        }
                    }
                } else {
                    print!(
                        "{}",
                        render_frame_with_prev(&snap, show_prev, coalesced, &markers)
                    );
                }
                last_gen = generation;
                last_seq = snap.source.window_seq;
                last_built = Some(snap);
            }
            Err(e) => {
                if !built_once {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
                // Window-file outage: KEEP PUBLISHING last-good with
                // refreshed staleness (P2fix3 NEW-1 — no exit; the
                // terminal never freezes on a stale age; recovery
                // advances below). The note names the ACCEPTED TIP
                // beside the rejection (P2fix14 NEW-84 — the live
                // folded tip from the single scan that just ran,
                // same line, so live-test synchronization observes
                // the accepted tip + the rejected tail from the
                // SAME scan with no buffered-note counting) AND
                // the EXPLICIT rejected window (P2fix15 NEW-91 —
                // the filename sequence that scan broke at, never
                // the schema-error text — matched as complete
                // fields, never substrings).
                let tip = match presenter.folded_tip() {
                    (Some(g), Some(s)) => format!("accepted tip gen={g} seq={s}; "),
                    _ => "accepted tip none; ".to_string(),
                };
                let rejected = match presenter.rejected_window() {
                    Some(r) => format!("rejected window seq={r}; "),
                    None => "rejected window none; ".to_string(),
                };
                eprintln!("osslscope: watch: {e} ({tip}{rejected}retaining last-good)");
                if let Some(last) = last_built.clone() {
                    let mut republished = last;
                    let (age, stale) = super::snapshot::snapshot_freshness(
                        republished.window.as_ref(),
                        super::snapshot::WINDOW_SECS_FALLBACK,
                        super::snapshot::monotonic_ns(),
                    );
                    republished.health.snapshot_age_ns = age;
                    republished.health.stale = stale;
                    if opts.follow {
                        // Outage republication re-frames last-good
                        // (coalesced=0 — no new span; matches the
                        // human re-render's explicit 0 below).
                        println!("--- frame {} coalesced=0 ---", republished.snapshot_seq);
                    }
                    if opts.format_json {
                        // Same generation-bound facts as the human
                        // frame (P2fix3 NEW-P2h — the sticky marker
                        // set, not just this build's).
                        republished.markers = markers.clone();
                        match serde_json::to_vec_pretty(&republished) {
                            Ok(mut bytes) => {
                                bytes.push(b'\n');
                                let _ = std::io::Write::write_all(&mut std::io::stdout(), &bytes);
                            }
                            Err(e) => {
                                eprintln!("osslscope: {e}");
                                return ExitCode::from(1);
                            }
                        }
                    } else {
                        print!(
                            "{}",
                            render_frame_with_prev(&republished, None, 0, &markers)
                        );
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(opts.poll_secs));
    }
}
