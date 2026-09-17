//! Provisional P2 `report` (JSON doc + minimal human table; P3
//! freezes the schema, adds `check`, and narrows exits).
//!
//! `report [--duration S] [--format human|json] [--out FILE]
//! [--provider P] [--builtin] [--object O] [--count-object C]
//! [--settle S] [--timeout S] [--grace S] {--pid P | run -- <cmd>}`
//!
//! Exit precedence (PRD §6 proposal): child non-zero → 1 (with
//! `child_exit` in the doc — the subject failed, evidence rides
//! along); fatal (recycled / zero-attached / environment) → 4;
//! PARTIAL → 3; clean COMPLETE → 0; usage → 2. Violation (10) and
//! inconclusive (11) arrive with `check` at P3.
use crate::capture;
use std::collections::BTreeMap;
use std::process::ExitCode;
use std::time::Duration;

/// Default window (P3 exit-5): 3× the 10 s P2 exactness cells that
/// went COMPLETE on all lanes (spawn + first crypto + loop ops all
/// observed) — comfortably exceeds seconds-scale target warmup
/// (attach runs pre-window) while keeping CI windows cheap.
pub(crate) const DEFAULT_DURATION_SECS: f64 = 30.0;

struct Args {
    cfg: capture::Config,
    target: capture::Target,
    format: String,
    out: Option<String>,
    cbom: Option<String>,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut duration: Option<f64> = None;
    let mut format = "human".to_string();
    let mut out: Option<String> = None;
    let mut provider: Option<String> = None;
    let mut builtin = false;
    let mut object: Option<String> = None;
    let mut count_object: Option<String> = None;
    let mut settle = 2.0f64;
    let mut timeout = 60.0f64;
    let mut grace = 5.0f64;
    let mut pid: Option<u32> = None;
    let mut image_digest = String::new();
    let mut cbom: Option<String> = None;
    let mut run_at: Option<usize> = None;
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "run" {
            run_at = Some(i);
            break;
        }
        let val = |k: &str| -> Result<String, String> {
            argv.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{k} needs a value"))
        };
        match a {
            "--duration" => {
                duration = Some(val(a)?.parse().map_err(|_| "--duration needs seconds")?)
            }
            "--format" => format = val(a)?,
            "--out" => out = Some(val(a)?),
            "--provider" => provider = Some(val(a)?),
            "--builtin" => {
                builtin = true;
                i += 1;
                continue;
            }
            "--object" => object = Some(val(a)?),
            "--count-object" => count_object = Some(val(a)?),
            "--settle" => settle = val(a)?.parse().map_err(|_| "--settle needs seconds")?,
            "--timeout" => timeout = val(a)?.parse().map_err(|_| "--timeout needs seconds")?,
            "--grace" => grace = val(a)?.parse().map_err(|_| "--grace needs seconds")?,
            "--pid" => pid = Some(val(a)?.parse().map_err(|_| "--pid needs an integer")?),
            "--image-digest" => image_digest = val(a)?,
            "--cbom" => cbom = Some(val(a)?),
            x => return Err(format!("unknown flag {x}")),
        }
        i += 2;
    }
    if format != "human" && format != "json" {
        return Err("--format must be human|json".to_string());
    }
    let target = match (pid, run_at) {
        (Some(p), None) => capture::Target::Pid(p),
        (None, Some(j)) => {
            if argv.get(j + 1).map(String::as_str) != Some("--") {
                return Err("run needs -- before the command".to_string());
            }
            let cmd: Vec<String> = argv[j + 2..].to_vec();
            if cmd.is_empty() {
                return Err("run -- needs a command".to_string());
            }
            capture::Target::Spawn { argv: cmd }
        }
        _ => return Err("need exactly one of --pid P | run -- <cmd>".to_string()),
    };
    let duration = duration.unwrap_or(DEFAULT_DURATION_SECS);
    if !duration.is_finite() || duration <= 0.0 {
        return Err("--duration must be > 0".to_string());
    }
    for (name, v) in [
        ("--settle", settle),
        ("--timeout", timeout),
        ("--grace", grace),
    ] {
        if !v.is_finite() || v < 0.0 {
            return Err(format!("{name} must be >= 0 seconds"));
        }
    }
    Ok(Args {
        cfg: capture::Config {
            harvest_object: object.ok_or("--object O is required")?.into(),
            count_object: count_object.ok_or("--count-object C is required")?.into(),
            provider: provider.ok_or("--provider P is required")?.into(),
            builtin,
            duration: Duration::from_secs_f64(duration),
            settle: Duration::from_secs_f64(settle),
            harvest_timeout: Duration::from_secs_f64(timeout),
            grace: Duration::from_secs_f64(grace),
            image_digest,
        },
        target,
        format,
        out,
        cbom,
    })
}

/// Exit for a finished capture (pure — unit-tested).
fn exit_for(c: &capture::Capture) -> u8 {
    if matches!(c.child_exit, Some(code) if code != 0) {
        return 1;
    }
    match &c.outcome {
        capture::Outcome::Fatal(_) => 4,
        capture::Outcome::Partial => 3,
        capture::Outcome::Complete => 0,
    }
}

pub(crate) fn epoch_of(t: std::time::SystemTime) -> f64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub(crate) fn doc(c: &capture::Capture) -> serde_json::Value {
    let status = match &c.outcome {
        capture::Outcome::Complete => "COMPLETE",
        capture::Outcome::Partial => "PARTIAL",
        capture::Outcome::Fatal(_) => "FATAL",
    };
    let k = &c.counters;
    let executions: Vec<serde_json::Value> = c
        .executions
        .iter()
        .map(|e| {
            serde_json::json!({
                "cookie": e.cookie,
                "provider": e.id.provider,
                "op": e.id.op,
                "funcid": e.id.funcid,
                "alg_class": e.id.alg_class,
                "offset": e.id.offset,
                "count": e.count,
                "first_ns": e.first_ns,
                "last_ns": e.last_ns,
                "aliases": e.aliases.iter().map(|a| serde_json::json!({
                    "provider": a.provider, "op": a.op, "funcid": a.funcid,
                    "alg_class": a.alg_class, "offset": a.offset,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut d = serde_json::json!({
        "schema_version": "observed-crypto-v1.0",
        "target": {"pid": c.target_pid, "comm": c.target_comm, "cmdline": c.target_cmdline,
                   "container_id": c.target_container_id, "image_digest": c.image_digest},
        "window": {"planned_s": c.window_planned.as_secs_f64(), "actual_s": c.window_actual.as_secs_f64(),
                   "start_epoch": epoch_of(c.window_start_wall), "end_epoch": epoch_of(c.window_end_wall)},
        "kernel": c.kernel_release,
        "provider": {"path": c.provider_path, "build_id": c.provider_build_id},
        "completeness": {
            "status": status,
            "reasons": c.reasons,
            "counters": {
                "dropped_events": k.dropped_bpf + k.dropped_userspace,
                "dropped_events_bpf": k.dropped_bpf,
                "dropped_events_userspace": k.dropped_userspace,
                "missed_attaches": k.missed_attaches,
                "unresolved_offsets": k.unresolved_offsets,
                "table_staleness_events": k.table_staleness_events,
                "cold_gap_calls": k.cold_gap_calls,
                "provider_changed": k.provider_changed,
                "scan_budget_exhaustions": k.scan_budget_exhaustions,
                "engine_fallback_uninstrumented": k.engine_fallback_uninstrumented,
                "drain_shortfall": k.drain_shortfall,
                "uninstrumented_ops": k.uninstrumented_ops,
                "fork_exec_ignored": k.fork_exec_ignored,
                "over_budget": k.over_budget,
            },
        },
        "executions": executions,
        "legacy": legacy_with_executed_weak(c),
        "stale": c.stale.iter().map(|s| serde_json::json!({
            "generation": s.generation, "events": s.events, "keys": s.keys,
            "detail": s.detail.iter().map(|d| serde_json::json!({
                "cookie": d.cookie,
                "provider": d.id.provider, "op": d.id.op, "funcid": d.id.funcid,
                "alg_class": d.id.alg_class, "offset": d.id.offset,
                "count": d.count, "first_ns": d.first_ns, "last_ns": d.last_ns,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "drain_wall_us": c.drain_wall_us,
    });
    if let Some(code) = c.child_exit {
        d["child_exit"] = code.into();
    }
    d
}

/// Adopted harvest `legacy` block plus window-executed weak rollup:
/// `weak.executed_calls`/`weak.executed_algs` count executions (and
/// fenced detail) whose class is registry-weak; `weak.unknown_calls`
/// counts `other`-class executions (custom spellings — triage, never
/// auto-deny). Null legacy stays null (no harvest produced one).
fn legacy_with_executed_weak(c: &capture::Capture) -> serde_json::Value {
    let mut legacy = c.legacy.clone();
    if legacy.is_null() {
        return legacy;
    }
    let mut calls = 0u64;
    let mut unknown = 0u64;
    let mut algs = std::collections::BTreeSet::new();
    let mut fold = |class: &str, n: u64| {
        if crate::kinds::is_weak_alg(class) {
            calls += n;
            algs.insert(class.to_string());
        } else if class == "other" {
            unknown += n;
        }
    };
    for e in &c.executions {
        fold(&e.id.alg_class, e.count);
    }
    for s in &c.stale {
        for d in &s.detail {
            fold(&d.id.alg_class, d.count);
        }
    }
    legacy["weak"]["executed_calls"] = calls.into();
    legacy["weak"]["executed_algs"] = algs.into_iter().collect::<Vec<_>>().into();
    legacy["weak"]["unknown_calls"] = unknown.into();
    legacy
}

/// Epoch seconds → RFC3339 UTC (`2023-11-14T22:13:20Z`).
/// Hand-rolled civil date (Hinnant days-from-civil — a security
/// observer takes no date dependency for this).
pub(crate) fn iso8601_utc(epoch: u64) -> String {
    let days = (epoch / 86_400) as i64;
    let secs = epoch % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

pub(crate) fn epoch_secs(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Thousands separator for call counts.
pub(crate) fn grouped(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.bytes().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch as char);
    }
    out
}

/// Op id → display name (`OSSL_OP_DIGEST` → `DIGEST`).
pub(crate) fn op_display(id: u32) -> String {
    crate::kinds::OPS
        .iter()
        .find(|o| o.id == id)
        .map(|o| {
            o.name
                .strip_prefix("OSSL_OP_")
                .unwrap_or(o.name)
                .to_string()
        })
        .unwrap_or_else(|| format!("OP{id}"))
}

/// Footer status line, no trailing newline (shared with check's
/// evidence line — goldens pin the bytes, so extraction is exact).
pub(crate) fn status_line(c: &capture::Capture) -> String {
    let mut s = String::new();
    let status = match &c.outcome {
        capture::Outcome::Complete => "COMPLETE",
        capture::Outcome::Partial => "PARTIAL",
        capture::Outcome::Fatal(_) => "FATAL",
    };
    s.push_str(&format!("status={status}"));
    if !c.reasons.is_empty() {
        s.push_str(&format!(" reasons={}", c.reasons.join(",")));
    }
    let k = &c.counters;
    let mut nz = Vec::new();
    for (name, v) in [
        ("dropped", k.dropped_bpf + k.dropped_userspace),
        ("missed", k.missed_attaches),
        ("unresolved", k.unresolved_offsets),
        ("staleness", k.table_staleness_events),
        ("cold_gap", k.cold_gap_calls),
        ("prov_changed", k.provider_changed),
        ("scan_overruns", k.scan_budget_exhaustions),
        ("eng_fallback", k.engine_fallback_uninstrumented),
        ("shortfall", k.drain_shortfall),
        ("uninstrumented_ops", k.uninstrumented_ops),
        ("fork_ignored", k.fork_exec_ignored),
        ("over_budget", k.over_budget),
    ] {
        if v > 0 {
            nz.push(format!("{name}={v}"));
        }
    }
    if !nz.is_empty() {
        s.push_str(&format!(" counters[{}]", nz.join(" ")));
    }
    if let Some(code) = c.child_exit {
        s.push_str(&format!(" child_exit={code}"));
    }
    s
}

/// Build-id short form for the header (hex is ASCII: byte cut safe).
fn short_id(build_id: &str) -> &str {
    if build_id.len() > 12 {
        &build_id[..12]
    } else {
        build_id
    }
}

fn human(c: &capture::Capture) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "osslscope report: pid={} ({}) window={} - {} ({:.1}s/{:.1}s planned)\n",
        c.target_pid,
        c.target_comm,
        iso8601_utc(epoch_secs(c.window_start_wall)),
        iso8601_utc(epoch_secs(c.window_end_wall)),
        c.window_actual.as_secs_f64(),
        c.window_planned.as_secs_f64()
    ));
    s.push_str(&format!(
        "provider: {} build-id={} kernel={}\n",
        c.provider_path,
        short_id(&c.provider_build_id),
        c.kernel_release
    ));
    s.push_str(&format!(
        "cmdline: {}\n",
        if c.target_cmdline.is_empty() {
            "(unknown)"
        } else {
            &c.target_cmdline
        }
    ));
    s.push('\n');
    // Op-grouped executions (display-name order for scanning; the
    // JSON keeps the byte-stable identity order).
    let mut groups: BTreeMap<String, Vec<&capture::Execution>> = BTreeMap::new();
    for e in &c.executions {
        groups.entry(op_display(e.id.op)).or_default().push(e);
    }
    if !groups.is_empty() {
        for (op, execs) in &groups {
            s.push_str(&format!("{op}\n"));
            for e in execs {
                s.push_str(&format!(
                    "  {} provider={} funcid={} {} calls\n",
                    e.id.alg_class,
                    e.id.provider,
                    e.id.funcid,
                    grouped(e.count)
                ));
            }
        }
        s.push('\n');
    }
    if !c.stale.is_empty() {
        s.push_str("Fenced generations\n");
        for b in &c.stale {
            s.push_str(&format!(
                "  gen {}: {} events, {} keys (detail in JSON)\n",
                b.generation,
                grouped(b.events),
                grouped(b.keys)
            ));
        }
        s.push('\n');
    }
    // Same adopted block as the JSON (weak rollup recomputed —
    // the formats must never disagree).
    human_legacy(&legacy_with_executed_weak(c), &mut s);
    s.push('\n');
    s.push_str(&status_line(c));
    s.push('\n');
    s.push_str("absence = not-observed in window (never \"not present / never used\")\n");
    if c.reasons.iter().any(|r| r == "fips-unlabeled") {
        s.push_str("note: FIPS executions unlabeled in v1 (self-test calls not distinguished)\n");
    }
    s.push_str("note: alg-name-only strength (key sizes unobservable); window-only claims\n");
    s
}

/// Legacy section: entry states, ENGINE/legacy-provider activity,
/// weak rollup, tripwire capability, flags.
fn human_legacy(legacy: &serde_json::Value, s: &mut String) {
    s.push_str("Legacy paths\n");
    if legacy.is_null() {
        s.push_str("  not harvested (no harvest produced a block)\n");
        return;
    }
    let name = |e: &serde_json::Value| {
        e.pointer("/name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string()
    };
    let (mut obs, mut abs, mut un) = (0u64, 0u64, 0u64);
    let (mut obs_names, mut un_names) = (Vec::new(), Vec::new());
    let mut probed_quiet = 0u64;
    if let Some(list) = legacy.pointer("/entries").and_then(|v| v.as_array()) {
        for e in list {
            match e.pointer("/state").and_then(|v| v.as_str()).unwrap_or("") {
                "observed" => {
                    obs += 1;
                    obs_names.push(name(e));
                }
                "uninstrumented" => {
                    un += 1;
                    un_names.push(name(e));
                }
                _ => {
                    abs += 1;
                    if e.pointer("/probed")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        probed_quiet += 1;
                    }
                }
            }
        }
    }
    s.push_str(&format!(
        "  entries: {obs} observed, {abs} absent ({probed_quiet} probed-quiet, {} not in target), {un} uninstrumented\n",
        abs - probed_quiet
    ));
    if !obs_names.is_empty() {
        s.push_str(&format!("  observed: {}\n", obs_names.join(", ")));
    }
    if !un_names.is_empty() {
        s.push_str(&format!("  uninstrumented: {}\n", un_names.join(", ")));
    }
    let map_sum = |ptr: &str| -> u64 {
        legacy
            .pointer(ptr)
            .and_then(|v| v.as_object())
            .map(|m| m.values().map(|v| v.as_u64().unwrap_or(0)).sum())
            .unwrap_or(0)
    };
    let num = |ptr: &str| -> u64 { legacy.pointer(ptr).and_then(|v| v.as_u64()).unwrap_or(0) };
    let strs = |ptr: &str| -> Vec<String> {
        legacy
            .pointer(ptr)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    s.push_str(&format!(
        "  ENGINE calls: {}\n",
        grouped(map_sum("/engine/calls_by_entrypoint"))
    ));
    let ids: Vec<String> = ["dynamic", "builtin", "other"]
        .iter()
        .filter_map(|k| {
            let n = num(&format!("/engine/engine_id_class/{k}"));
            (n > 0).then(|| format!("{k}={n}"))
        })
        .collect();
    if !ids.is_empty() {
        s.push_str(&format!("  engine ids: {}\n", ids.join(" ")));
    }
    s.push_str(&format!(
        "  legacy provider: loads={} executed={} algs=[{}]\n",
        grouped(map_sum("/legacy_provider/loads")),
        grouped(num("/legacy_provider/executed_calls")),
        strs("/legacy_provider/algs").join(", ")
    ));
    let w_algs = strs("/weak/legacy_algs");
    let w_exec = num("/weak/executed_calls");
    let w_unk = num("/weak/unknown_calls");
    if w_algs.is_empty() && w_exec == 0 && w_unk == 0 {
        s.push_str("  weak legacy algs: none\n");
    } else {
        s.push_str(&format!(
            "  weak legacy algs: [{}] executed={} (algs=[{}]) unknown={}\n",
            w_algs.join(", "),
            grouped(w_exec),
            strs("/weak/executed_algs").join(", "),
            grouped(w_unk)
        ));
    }
    s.push_str(&format!(
        "  tripwires: {} attached, {} missed of {} syms\n",
        grouped(num("/capability/tripwires_attached")),
        grouped(num("/capability/tripwires_missed")),
        grouped(num("/capability/syms_present"))
    ));
    let flags = strs("/flags");
    if flags.is_empty() {
        s.push_str("  flags: none\n");
    } else {
        s.push_str(&format!("  flags: {}\n", flags.join(", ")));
    }
}

/// CycloneDX 1.6 CBOM (P3 exit-4): one `cryptographic-asset`
/// component per executed identity (current + fenced detail).
/// Minimal field map (P3 gate record documents it): algorithm,
/// provider (+object/build-id), op, funcid, calls, generation,
/// window edges, per-component completeness. PARTIAL/FATAL ride a
/// metadata disclaimer; FATAL has zero components. No
/// `algorithmProperties` in v1 (primitive/mode are not reliably
/// known — never fabricate crypto metadata).
fn cbom(c: &capture::Capture) -> serde_json::Value {
    let status = match &c.outcome {
        capture::Outcome::Complete => "COMPLETE",
        capture::Outcome::Partial => "PARTIAL",
        capture::Outcome::Fatal(_) => "FATAL",
    };
    let start = iso8601_utc(epoch_secs(c.window_start_wall));
    let end = iso8601_utc(epoch_secs(c.window_end_wall));
    let prop = |name: &str, value: String| serde_json::json!({"name": name, "value": value});
    let mut comps: Vec<serde_json::Value> = Vec::new();
    if !matches!(c.outcome, capture::Outcome::Fatal(_)) {
        let mut one = |cookie: u32,
                       provider: &str,
                       op: u32,
                       funcid: u32,
                       alg: &str,
                       count: u64,
                       generation: &str| {
            comps.push(serde_json::json!({
                "bom-ref": format!("urn:osslscope:exec:{generation}:{cookie}:{op}:{funcid}:{provider}:{alg}"),
                "type": "cryptographic-asset",
                "name": format!("{alg} ({}) via {provider}", op_display(op)),
                "cryptoProperties": {"assetType": "algorithm"},
                "properties": [
                    prop("osslscope:algorithm", alg.to_string()),
                    prop("osslscope:provider", provider.to_string()),
                    prop("osslscope:provider-object", c.provider_path.clone()),
                    prop("osslscope:provider-build-id", c.provider_build_id.clone()),
                    prop("osslscope:op", op_display(op)),
                    prop("osslscope:funcid", funcid.to_string()),
                    prop("osslscope:calls", count.to_string()),
                    prop("osslscope:generation", generation.to_string()),
                    prop("osslscope:window-start", start.clone()),
                    prop("osslscope:window-end", end.clone()),
                    prop("osslscope:execution-evidence-completeness", status.to_string()),
                ],
            }));
        };
        for e in &c.executions {
            one(
                e.cookie,
                &e.id.provider,
                e.id.op,
                e.id.funcid,
                &e.id.alg_class,
                e.count,
                "current",
            );
        }
        for s in &c.stale {
            let generation = s.generation.to_string();
            for d in &s.detail {
                one(
                    d.cookie,
                    &d.id.provider,
                    d.id.op,
                    d.id.funcid,
                    &d.id.alg_class,
                    d.count,
                    &generation,
                );
            }
        }
    }
    let mut metadata = serde_json::json!({"timestamp": end});
    let why = if c.reasons.is_empty() {
        "unknown".to_string()
    } else {
        c.reasons.join(",")
    };
    match &c.outcome {
        capture::Outcome::Complete => {}
        capture::Outcome::Partial => {
            metadata["properties"] = serde_json::json!([{
                "name": "osslscope:completeness-disclaimer",
                "value": format!("PARTIAL evidence ({why}); absence = not-observed in window"),
            }]);
        }
        capture::Outcome::Fatal(_) => {
            metadata["properties"] = serde_json::json!([{
                "name": "osslscope:completeness-disclaimer",
                "value": format!("FATAL: no usable evidence ({why})"),
            }]);
        }
    }
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": metadata,
        "components": comps,
    })
}

const USAGE: &str = "usage: report [--duration S] --provider P --object O --count-object C [--format human|json] [--out F] [--cbom FILE] [--builtin] [--settle S] [--timeout S] [--grace S] [--image-digest D] {--pid P | run -- <cmd>}";

pub fn run(argv: &[String]) -> ExitCode {
    // --help anywhere on the osslscope side (a target command after
    // run -- may legitimately contain --help).
    if argv
        .iter()
        .take_while(|a| a.as_str() != "run")
        .any(|a| a == "--help" || a == "-h")
    {
        println!("{USAGE}");
        return ExitCode::from(0);
    }
    let args = match parse(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("osslscope report: {e}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let c = match capture::run(&args.cfg, args.target) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("osslscope report: {e:#}");
            eprintln!("osslscope report: run 'osslscope doctor' to diagnose environment failures");
            return ExitCode::from(4);
        }
    };
    let text = if args.format == "json" {
        serde_json::to_string_pretty(&doc(&c)).unwrap() + "\n"
    } else {
        human(&c)
    };
    if let Some(path) = &args.out {
        if let Err(e) = std::fs::write(path, &text) {
            eprintln!("osslscope report: write {path}: {e}");
            return ExitCode::from(4);
        }
    } else {
        print!("{text}");
    }
    // --cbom additionally writes, never replaces stdout (written
    // even on PARTIAL/FATAL — the disclaimer travels in-band).
    if let Some(path) = &args.cbom {
        let text = serde_json::to_string_pretty(&cbom(&c)).unwrap() + "\n";
        if let Err(e) = std::fs::write(path, &text) {
            eprintln!("osslscope report: write {path}: {e}");
            return ExitCode::from(4);
        }
    }
    ExitCode::from(exit_for(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(outcome: capture::Outcome, child_exit: Option<i32>) -> capture::Capture {
        capture::Capture {
            target_pid: 7,
            target_comm: "t".to_string(),
            window_planned: Duration::from_secs(1),
            window_actual: Duration::from_secs(1),
            outcome,
            reasons: Vec::new(),
            executions: Vec::new(),
            stale: Vec::new(),
            counters: capture::Counters::default(),
            child_exit,
            drain_wall_us: 0,
            harvest_doc: serde_json::json!({}),
            legacy: serde_json::Value::Null,
            window_start_wall: std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            window_end_wall: std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_001),
            kernel_release: "test-kernel".to_string(),
            target_cmdline: "t".to_string(),
            target_container_id: String::new(),
            provider_build_id: "unknown".to_string(),
            provider_path: "/p/provider.so".to_string(),
            image_digest: String::new(),
        }
    }

    #[test]
    fn exit_precedence() {
        use capture::{FatalKind, Outcome};
        assert_eq!(exit_for(&cap(Outcome::Complete, None)), 0);
        assert_eq!(exit_for(&cap(Outcome::Complete, Some(0))), 0);
        assert_eq!(exit_for(&cap(Outcome::Partial, None)), 3);
        assert_eq!(
            exit_for(&cap(Outcome::Fatal(FatalKind::AttachZero), None)),
            4
        );
        // Child failure dominates evidence status (never 10 without a verdict).
        assert_eq!(exit_for(&cap(Outcome::Complete, Some(2))), 1);
        assert_eq!(exit_for(&cap(Outcome::Partial, Some(139))), 1);
        assert_eq!(
            exit_for(&cap(Outcome::Fatal(FatalKind::Recycled), Some(1))),
            1
        );
    }

    #[test]
    fn doc_shape() {
        let d = doc(&cap(capture::Outcome::Complete, Some(0)));
        assert_eq!(d["schema_version"], "observed-crypto-v1.0");
        assert_eq!(d["completeness"]["status"], "COMPLETE");
        assert!(d["completeness"]["counters"]["dropped_events"].is_number());
        assert!(d["executions"].as_array().unwrap().is_empty());
        assert_eq!(d["child_exit"], 0);
        // P3 window/target enrichment (fixed stamps in cap()).
        assert_eq!(d["window"]["start_epoch"], 1_700_000_000.0);
        assert_eq!(d["window"]["end_epoch"], 1_700_000_001.0);
        assert_eq!(d["target"]["cmdline"], "t");
        assert_eq!(d["target"]["container_id"], "");
        assert_eq!(d["target"]["image_digest"], "");
        assert_eq!(d["kernel"], "test-kernel");
        assert_eq!(d["provider"]["path"], "/p/provider.so");
        assert_eq!(d["provider"]["build_id"], "unknown");
        assert!(
            d.get("policy").is_none(),
            "report omits policy (check adds it)"
        );
        assert!(d.get("kat").is_none(), "v1 has no KAT discriminator");
        let d = doc(&cap(capture::Outcome::Partial, None));
        assert!(d.get("child_exit").is_none());
    }

    fn full_cap() -> capture::Capture {
        let mut c = cap(capture::Outcome::Complete, Some(0));
        let exec = |op: u32, alg: &str, funcid: u32, count: u64| capture::Execution {
            cookie: op,
            id: crate::plan::Identity {
                provider: "default".to_string(),
                op,
                funcid,
                alg_class: alg.to_string(),
                offset: 0,
            },
            aliases: Vec::new(),
            count,
            first_ns: 0,
            last_ns: 0,
        };
        // Identity-sorted input (as finish() produces); human
        // regroups by op display name.
        c.executions = vec![
            exec(1, "SHA-256", 11, 1_204_033),
            exec(2, "DES", 21, 500),
            exec(2, "other", 22, 9),
            exec(13, "ML-DSA-65", 31, 7),
        ];
        c.stale = vec![capture::StaleBucket {
            generation: 0,
            events: 450,
            keys: 2,
            detail: Vec::new(),
        }];
        c.legacy = serde_json::json!({
            "entries": [
                {"name": "ENGINE_init", "class": "engine", "state": "observed", "probed": true},
                {"name": "RSA_meth_new", "class": "meth", "state": "uninstrumented", "probed": false},
                {"name": "SHA256_Update", "class": "lowlevel", "state": "absent", "probed": true},
            ],
            "engine": {"calls_by_entrypoint": {"ENGINE_init": 5},
                       "engine_id_class": {"dynamic": 1, "builtin": 0, "other": 0}},
            "legacy_provider": {"loads": {"legacy": 1}, "executed_calls": 4, "algs": ["MD4"]},
            "weak": {"legacy_algs": ["MD4"]},
            "capability": {"syms_present": 10, "tripwires_attached": 8, "tripwires_missed": 2},
            "flags": ["engine-api-absent"],
        });
        c
    }

    #[test]
    fn human_full_shape() {
        let want = "osslscope report: pid=7 (t) window=2023-11-14T22:13:20Z - 2023-11-14T22:13:21Z (1.0s/1.0s planned)\n\
provider: /p/provider.so build-id=unknown kernel=test-kernel\n\
cmdline: t\n\
\n\
ASYM_CIPHER\n  ML-DSA-65 provider=default funcid=31 7 calls\n\
CIPHER\n  DES provider=default funcid=21 500 calls\n  other provider=default funcid=22 9 calls\n\
DIGEST\n  SHA-256 provider=default funcid=11 1,204,033 calls\n\
\n\
Fenced generations\n  gen 0: 450 events, 2 keys (detail in JSON)\n\
\n\
Legacy paths\n  entries: 1 observed, 1 absent (1 probed-quiet, 0 not in target), 1 uninstrumented\n  observed: ENGINE_init\n  uninstrumented: RSA_meth_new\n  ENGINE calls: 5\n  engine ids: dynamic=1\n  legacy provider: loads=1 executed=4 algs=[MD4]\n  weak legacy algs: [MD4] executed=500 (algs=[DES]) unknown=9\n  tripwires: 8 attached, 2 missed of 10 syms\n  flags: engine-api-absent\n\
\n\
status=COMPLETE child_exit=0\n\
absence = not-observed in window (never \"not present / never used\")\n\
note: alg-name-only strength (key sizes unobservable); window-only claims\n";
        assert_eq!(human(&full_cap()), want);
    }

    #[test]
    fn human_empty_sections() {
        // Null legacy, no executions, no stale: sections collapse,
        // footer doctrine still prints.
        let want = "osslscope report: pid=7 (t) window=2023-11-14T22:13:20Z - 2023-11-14T22:13:21Z (1.0s/1.0s planned)\n\
provider: /p/provider.so build-id=unknown kernel=test-kernel\n\
cmdline: t\n\
\n\
Legacy paths\n  not harvested (no harvest produced a block)\n\
\n\
status=COMPLETE\n\
absence = not-observed in window (never \"not present / never used\")\n\
note: alg-name-only strength (key sizes unobservable); window-only claims\n";
        assert_eq!(human(&cap(capture::Outcome::Complete, None)), want);
        // Clean legacy block: zero lines collapse to none-forms.
        let mut c = cap(capture::Outcome::Complete, None);
        c.legacy = serde_json::json!({
            "entries": [
                {"name": "E1", "class": "engine", "state": "absent", "probed": true},
                {"name": "E2", "class": "engine", "state": "absent", "probed": false},
            ],
            "engine": {"calls_by_entrypoint": {}, "engine_id_class": {}},
            "legacy_provider": {"loads": {}, "executed_calls": 0, "algs": []},
            "weak": {"legacy_algs": [], "executed_calls": 0, "executed_algs": [], "unknown_calls": 0},
            "capability": {"syms_present": 2, "tripwires_attached": 2, "tripwires_missed": 0},
            "flags": [],
        });
        let out = human(&c);
        assert!(out.contains("  entries: 0 observed, 2 absent (1 probed-quiet, 1 not in target), 0 uninstrumented\n"), "{out}");
        assert!(out.contains("  ENGINE calls: 0\n"), "{out}");
        assert!(out.contains("  weak legacy algs: none\n"), "{out}");
        assert!(out.contains("  flags: none\n"), "{out}");
        assert!(!out.contains("observed: E"), "{out}");
        assert!(!out.contains("engine ids:"), "{out}");
    }

    #[test]
    fn human_helpers() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(7), "7");
        assert_eq!(grouped(1_204_033), "1,204,033");
        assert_eq!(op_display(1), "DIGEST");
        assert_eq!(op_display(12), "SIGNATURE");
        assert_eq!(op_display(999), "OP999");
        assert_eq!(short_id("unknown"), "unknown");
        assert_eq!(short_id("abcdef1234567890"), "abcdef123456");
    }

    #[test]
    fn iso8601_vectors() {
        // Oracle: `date -u -d @EPOCH +%Y-%m-%dT%H:%M:%SZ`.
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601_utc(1_700_000_001), "2023-11-14T22:13:21Z");
        assert_eq!(iso8601_utc(1_767_225_600), "2026-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(2_147_483_647), "2038-01-19T03:14:07Z");
    }

    /// PARTIAL reason taxonomy (P3 exit-1: reasons distinguish
    /// blind vs clean). blind = may have missed executions;
    /// clean = fully observed, nothing unexpected found.
    /// `harvest-*` flow from the harvest doc reason (frozen
    /// bootstrap vocabulary — see locations below — plus the
    /// fail-closed `harvest-partial` fallback).
    const REASON_TAXONOMY: &[(&str, &str)] = &[
        ("no-query", "clean"),
        ("empty-inventory", "clean"),
        ("harvest-no-query-trigger", "clean"),
        ("missed-attaches", "blind"),
        ("unresolved-offsets", "blind"),
        ("unattributed", "blind"),
        ("drain-shortfall", "blind"),
        ("reharvest-skipped", "blind"),
        ("cold-gap", "blind"),
        ("reharvest-no-query", "blind"),
        ("fips-unlabeled", "blind"),
        ("reharvest-failed", "blind"),
        ("replan-skipped", "blind"),
        ("pid-recycled", "blind"),
        ("fork-exec-ignored", "blind"),
        ("over-budget", "blind"),
        ("interrupted", "blind"),
        ("engine-fallback-uninstrumented", "blind"),
        ("meth-fallback-uninstrumented", "blind"),
        ("lowlevel-fallback-uninstrumented", "blind"),
        ("harvest-pid-recycled", "blind"),
        ("harvest-anchor-unresolved", "blind"),
        ("harvest-zero-rows", "blind"),
        ("harvest-fenced-rows", "blind"),
        ("harvest-zero-row-ops", "blind"),
        ("harvest-truncated-walk", "blind"),
        ("harvest-partial", "blind"),
    ];

    fn reason_class(r: &str) -> Option<&'static str> {
        REASON_TAXONOMY
            .iter()
            .find(|(name, _)| *name == r)
            .map(|(_, c)| *c)
    }

    /// Extract string literals following a marker (reason-scan).
    fn scan_lits(src: &str, marker: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = src;
        while let Some(i) = rest.find(marker) {
            rest = &rest[i + marker.len()..];
            if let Some(end) = rest.find('"') {
                out.push(rest[..end].to_string());
                rest = &rest[end + 1..];
            } else {
                break;
            }
        }
        out
    }

    #[test]
    fn reason_taxonomy_complete() {
        // Every static capture reason is classified; a novel
        // literal breaks this test until deliberately placed.
        let src = include_str!("capture.rs");
        let mut found = scan_lits(src, ".reason(\"");
        found.extend(scan_lits(src, "reasons.push(\""));
        found.sort();
        found.dedup();
        assert!(!found.is_empty(), "scan found nothing — patterns rotted");
        for r in &found {
            assert!(reason_class(r).is_some(), "unclassified reason: {r}");
        }
        // Both directions: no table rot (every static table entry
        // still exists in source).
        for (name, _) in REASON_TAXONOMY
            .iter()
            .filter(|(n, _)| !n.starts_with("harvest-"))
        {
            assert!(
                found.iter().any(|f| f == name),
                "table rot (not in source): {name}"
            );
        }
        // Frozen harvest vocabulary (harvest.rs: anchor-unresolved
        // ×2 preset, no-query-trigger ×2, zero-rows, pid-recycled;
        // schema.rs fallback: fenced-rows, zero-row-ops,
        // truncated-walk; capture fallback: harvest-partial).
        // Novel harvest reasons need table updates by review.
        for (name, _) in REASON_TAXONOMY
            .iter()
            .filter(|(n, _)| n.starts_with("harvest-"))
        {
            assert!(reason_class(name).is_some(), "unclassified: {name}");
        }
        // Blind and clean both exist (the distinction is real).
        assert!(found.iter().any(|r| reason_class(r) == Some("blind")));
        assert!(found.iter().any(|r| reason_class(r) == Some("clean")));
    }

    /// Pin a rendered artifact against `tests/goldens/`.
    /// Mismatch → FAIL with a line diff (never auto-update).
    /// Regenerate explicitly with OSSLSCOPE_REGENERATE_GOLDENS=1,
    /// then REVIEW THE DIFF before committing.
    fn assert_golden(name: &str, actual: &str) {
        let path = format!("{}/tests/goldens/{name}", env!("CARGO_MANIFEST_DIR"));
        if std::env::var("OSSLSCOPE_REGENERATE_GOLDENS").is_ok() {
            std::fs::write(&path, actual).unwrap();
            return;
        }
        let want = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing golden {name} (regenerate explicitly)"));
        if want != actual {
            let mut diff = format!("golden {name} mismatch:\n");
            let w: Vec<&str> = want.lines().collect();
            let a: Vec<&str> = actual.lines().collect();
            let mut shown = 0;
            for (i, (x, y)) in w.iter().zip(a.iter()).enumerate() {
                if x != y {
                    diff.push_str(&format!("line {}:\n  want: {x}\n  got:  {y}\n", i + 1));
                    shown += 1;
                    if shown >= 10 {
                        break;
                    }
                }
            }
            if w.len() != a.len() {
                diff.push_str(&format!("lengths: want {} got {}\n", w.len(), a.len()));
            }
            panic!("{diff}");
        }
    }

    fn json_of(c: &capture::Capture) -> String {
        serde_json::to_string_pretty(&doc(c)).unwrap() + "\n"
    }

    fn cbom_json(c: &capture::Capture) -> String {
        serde_json::to_string_pretty(&cbom(c)).unwrap() + "\n"
    }

    fn partial(reasons: &[&str]) -> capture::Capture {
        let mut c = cap(capture::Outcome::Partial, None);
        c.reasons = reasons.iter().map(|r| r.to_string()).collect();
        c
    }

    fn blind_legacy(engine_un: u64, meth_un: u64, low_un: u64) -> serde_json::Value {
        let mut l = serde_json::json!({
            "entries": [
                {"name": "ENGINE_init", "class": "engine", "state": "observed", "probed": true},
                {"name": "RSA_meth_new", "class": "meth", "state": "uninstrumented", "probed": false},
            ],
            "engine": {"calls_by_entrypoint": {"ENGINE_init": 2}, "engine_id_class": {}},
            "legacy_provider": {"loads": {}, "executed_calls": 0, "algs": []},
            "weak": {"legacy_algs": [], "executed_calls": 0, "executed_algs": [], "unknown_calls": 0},
            "capability": {"syms_present": 5, "tripwires_attached": 2, "tripwires_missed": 3},
            "flags": ["engine-fallback-uninstrumented"],
        });
        if engine_un > 0 {
            l["engine"]["uninstrumented"] = engine_un.into();
        }
        if meth_un > 0 {
            l["meth_new"]["uninstrumented"] = meth_un.into();
        }
        if low_un > 0 {
            l["lowlevel"]["uninstrumented"] = low_un.into();
        }
        l
    }

    #[test]
    fn goldens_complete() {
        assert_golden("report-complete.json", &json_of(&full_cap()));
        assert_golden("report-complete.txt", &human(&full_cap()));
    }

    #[test]
    fn goldens_partial_cells() {
        assert_golden(
            "report-partial-no-query.json",
            &json_of(&partial(&["no-query"])),
        );
        let interrupted = partial(&["interrupted"]);
        assert_golden("report-partial-interrupted.json", &json_of(&interrupted));
        assert_golden("report-partial-interrupted.txt", &human(&interrupted));
        let mut over = partial(&["over-budget"]);
        over.counters.over_budget = 1;
        assert_golden("report-partial-over-budget.json", &json_of(&over));
        let mut fork = partial(&["fork-exec-ignored"]);
        fork.counters.fork_exec_ignored = 2;
        assert_golden("report-partial-fork-ignored.json", &json_of(&fork));
        let mut cold = partial(&["cold-gap"]);
        cold.counters.cold_gap_calls = 5;
        assert_golden("report-partial-cold-gap.json", &json_of(&cold));
        assert_golden(
            "report-partial-fips-unlabeled.json",
            &json_of(&partial(&["fips-unlabeled"])),
        );
        assert_golden(
            "report-partial-fips-unlabeled.txt",
            &human(&partial(&["fips-unlabeled"])),
        );
    }

    #[test]
    fn goldens_legacy_cells() {
        // PRD §6: engine_fallback_uninstrumented > 0 → PARTIAL mandatory.
        let mut c = partial(&["engine-fallback-uninstrumented"]);
        c.counters.engine_fallback_uninstrumented = 2;
        c.legacy = blind_legacy(2, 0, 0);
        assert_eq!(exit_for(&c), 3);
        assert_golden("report-partial-engine-fallback.json", &json_of(&c));
        assert_golden("report-partial-engine-fallback.txt", &human(&c));
        // Static / no-engine target: clean COMPLETE with an
        // all-absent block (probed=false = not in target).
        let mut s = cap(capture::Outcome::Complete, Some(0));
        s.legacy = serde_json::json!({
            "entries": [
                {"name": "ENGINE_init", "class": "engine", "state": "absent", "probed": false},
                {"name": "SHA256_Update", "class": "lowlevel", "state": "absent", "probed": false},
            ],
            "engine": {"calls_by_entrypoint": {}, "engine_id_class": {}},
            "legacy_provider": {"loads": {}, "executed_calls": 0, "algs": []},
            "weak": {"legacy_algs": [], "executed_calls": 0, "executed_algs": [], "unknown_calls": 0},
            "capability": {"syms_present": 0, "tripwires_attached": 0, "tripwires_missed": 0},
            "flags": ["engine-api-absent"],
        });
        assert_golden("report-legacy-static.json", &json_of(&s));
        assert_golden("report-legacy-static.txt", &human(&s));
    }

    #[test]
    fn goldens_cbom() {
        assert_golden("cbom-complete.json", &cbom_json(&full_cap()));
        let mut p = partial(&["cold-gap"]);
        p.counters.cold_gap_calls = 5;
        p.executions = vec![capture::Execution {
            cookie: 0,
            id: crate::plan::Identity {
                provider: "default".to_string(),
                op: 2,
                funcid: 21,
                alg_class: "DES".to_string(),
                offset: 0,
            },
            aliases: Vec::new(),
            count: 500,
            first_ns: 0,
            last_ns: 0,
        }];
        assert_golden("cbom-partial.json", &cbom_json(&p));
        let mut f = cap(
            capture::Outcome::Fatal(capture::FatalKind::AttachZero),
            None,
        );
        f.reasons = vec!["pid-recycled".to_string()];
        assert_golden("cbom-fatal.json", &cbom_json(&f));
    }

    #[test]
    fn goldens_determinism_and_signals() {
        // Byte-stable for identical input (BTreeMap keys + sorted
        // executions — PRD §6 determinism test).
        let (a, b) = (json_of(&full_cap()), json_of(&full_cap()));
        assert_eq!(a, b);
        // Signals golden, unit half (P3 exit-7): signal-cut windows
        // are PARTIAL with exit 3; drain_shortfall == 0 when the
        // drain completes. (Live SIGTERM e2e runs on lane B, Task 10.)
        let c = partial(&["interrupted"]);
        assert_eq!(c.counters.drain_shortfall, 0);
        assert_eq!(exit_for(&c), 3);
        assert_eq!(doc(&c)["completeness"]["status"], "PARTIAL");
    }

    fn cbom_props(c: &serde_json::Value) -> std::collections::BTreeMap<String, String> {
        c["properties"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["name"].as_str().unwrap().to_string(),
                    p["value"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn cbom_complete_shape() {
        let b = cbom(&full_cap());
        assert_eq!(b["bomFormat"], "CycloneDX");
        assert_eq!(b["specVersion"], "1.6");
        assert_eq!(b["version"], 1);
        assert_eq!(b["metadata"]["timestamp"], "2023-11-14T22:13:21Z");
        assert!(
            b["metadata"].get("properties").is_none(),
            "clean: no disclaimer"
        );
        let comps = b["components"].as_array().unwrap();
        assert_eq!(
            comps.len(),
            4,
            "one component per execution (stale detail empty)"
        );
        let c0 = &comps[0];
        assert_eq!(c0["type"], "cryptographic-asset");
        assert_eq!(c0["cryptoProperties"]["assetType"], "algorithm");
        assert!(c0["bom-ref"].as_str().unwrap().contains("SHA-256"));
        let p = cbom_props(c0);
        assert_eq!(p["osslscope:algorithm"], "SHA-256");
        assert_eq!(p["osslscope:provider"], "default");
        assert_eq!(p["osslscope:op"], "DIGEST");
        assert_eq!(p["osslscope:funcid"], "11");
        assert_eq!(p["osslscope:calls"], "1204033");
        assert_eq!(p["osslscope:generation"], "current");
        assert_eq!(p["osslscope:provider-object"], "/p/provider.so");
        assert_eq!(p["osslscope:provider-build-id"], "unknown");
        assert_eq!(p["osslscope:execution-evidence-completeness"], "COMPLETE");
        assert_eq!(p["osslscope:window-start"], "2023-11-14T22:13:20Z");
        assert_eq!(p["osslscope:window-end"], "2023-11-14T22:13:21Z");
    }

    #[test]
    fn cbom_covers_fenced_detail() {
        let mut c = cap(capture::Outcome::Complete, None);
        c.executions = vec![capture::Execution {
            cookie: 0,
            id: crate::plan::Identity {
                provider: "default".to_string(),
                op: 1,
                funcid: 11,
                alg_class: "SHA-256".to_string(),
                offset: 0,
            },
            aliases: Vec::new(),
            count: 5,
            first_ns: 0,
            last_ns: 0,
        }];
        c.stale = vec![capture::StaleBucket {
            generation: 3,
            events: 9,
            keys: 1,
            detail: vec![capture::StaleDetail {
                cookie: 0,
                id: crate::plan::Identity {
                    provider: "spike".to_string(),
                    op: 2,
                    funcid: 21,
                    alg_class: "DES".to_string(),
                    offset: 0,
                },
                count: 9,
                first_ns: 0,
                last_ns: 0,
            }],
        }];
        let comps = cbom(&c)["components"].as_array().unwrap().clone();
        assert_eq!(comps.len(), 2);
        assert_eq!(cbom_props(&comps[0])["osslscope:generation"], "current");
        assert_eq!(cbom_props(&comps[1])["osslscope:generation"], "3");
        assert_eq!(cbom_props(&comps[1])["osslscope:algorithm"], "DES");
    }

    #[test]
    fn cbom_partial_and_fatal_disclaimers() {
        let mut c = cap(capture::Outcome::Partial, None);
        c.reasons = vec!["cold-gap".to_string()];
        let b = cbom(&c);
        let dis = b["metadata"]["properties"].as_array().unwrap();
        assert_eq!(dis.len(), 1);
        assert_eq!(dis[0]["name"], "osslscope:completeness-disclaimer");
        assert!(dis[0]["value"].as_str().unwrap().contains("cold-gap"));
        assert_eq!(b["components"].as_array().unwrap().len(), 0);
        // FATAL: empty components + FATAL disclaimer (uniform shape).
        let f = cap(
            capture::Outcome::Fatal(capture::FatalKind::AttachZero),
            None,
        );
        let b = cbom(&f);
        assert_eq!(b["components"].as_array().unwrap().len(), 0);
        let v = b["metadata"]["properties"][0]["value"].as_str().unwrap();
        assert!(v.contains("FATAL"), "{v}");
    }

    #[test]
    fn cbom_flag_parses() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse(&v(vec![
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
            "--cbom",
            "/tmp/x.cdx.json",
        ]))
        .unwrap();
        assert_eq!(a.cbom, Some("/tmp/x.cdx.json".to_string()));
        let a = parse(&v(vec![
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
        ]))
        .unwrap();
        assert_eq!(a.cbom, None);
    }

    #[test]
    fn help_exits_zero_before_run_only() {
        use std::process::ExitCode;
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(run(&v(vec!["--help"])), ExitCode::from(0));
        assert_eq!(run(&v(vec!["-h"])), ExitCode::from(0));
        // A target command after run -- may contain --help.
        assert_eq!(run(&v(vec!["run", "--", "--help"])), ExitCode::from(2));
    }

    #[test]
    fn duration_defaults_to_30s() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let no_dur = vec![
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
        ];
        assert_eq!(
            parse(&v(no_dur)).unwrap().cfg.duration,
            Duration::from_secs(30)
        );
        let explicit = vec![
            "--duration",
            "5",
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
            "--pid",
            "9",
        ];
        assert_eq!(
            parse(&v(explicit)).unwrap().cfg.duration,
            Duration::from_secs(5)
        );
    }

    #[test]
    fn parse_matrix() {
        let v = |s: Vec<&str>| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let base = vec![
            "--duration",
            "5",
            "--provider",
            "p",
            "--object",
            "o",
            "--count-object",
            "c",
        ];
        let mut pid = base.clone();
        pid.extend(["--pid", "9"]);
        assert!(parse(&v(pid)).is_ok());
        let mut run = base.clone();
        run.extend(["run", "--", "echo", "hi"]);
        assert!(parse(&v(run)).is_ok());
        assert!(parse(&v(base.clone())).is_err()); // no target
        let mut both = base.clone();
        both.extend(["--pid", "9", "run", "--", "x"]);
        assert!(parse(&v(both)).is_err()); // both targets
        assert!(parse(&v(vec!["--provider", "p", "--pid", "9"])).is_err()); // no objects
        let mut yaml = base.clone();
        yaml.extend(["--pid", "9", "--format", "yaml"]);
        assert!(parse(&v(yaml)).is_err());
        let mut digest = base.clone();
        digest.extend(["--pid", "9", "--image-digest", "sha256:abc"]);
        assert_eq!(parse(&v(digest)).unwrap().cfg.image_digest, "sha256:abc");
        let mut no_digest = base.clone();
        no_digest.extend(["--pid", "9"]);
        assert_eq!(parse(&v(no_digest)).unwrap().cfg.image_digest, "");
        // Valueless flags consume one slot (mid-argv position).
        let mut bi = base.clone();
        bi.extend(["--builtin", "--pid", "9"]);
        let a = parse(&v(bi)).unwrap();
        assert!(a.cfg.builtin);
        assert!(matches!(a.target, capture::Target::Pid(9)));
    }
}
