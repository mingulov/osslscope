// SPDX-License-Identifier: GPL-3.0-or-later
//! T5 `--resolve-paths` hostile cells 1–10 (integration legs).
//!
//! Cell plan: `docs/2026-11-03-t5-privacy-d-record.md` ("Hostile
//! cells"). Resolver-mechanics legs (races, magic-link walks,
//! sanitization units, no-I/O counters) live as unit cells in
//! `src/inventory/resolve.rs`; each test below names its unit
//! counterpart. These tests drive the real binary: byte-compare
//! legs run piped, rendering legs run under `script(1)` for a real
//! TTY.

use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "osslscope-rp-{}-{}-{}",
        std::process::id(),
        test,
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_osslscope"))
}

/// Minimal shared object (valid ELF for `inspect --module`).
fn build_so(dir: &Path, name: &str) -> PathBuf {
    let source = dir.join(format!("{name}.c"));
    let output = dir.join(name);
    fs::write(&source, "int marker(void) { return 1; }\n").unwrap();
    let result = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&output)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

fn symlink(original: &Path, link: &Path) {
    std::os::unix::fs::symlink(original, link).unwrap();
}

/// Run argv under a real pty (`script -qec`); output CRLF-normalized.
/// `script -e` propagates the child exit status.
fn pty_run(argv: &[&str]) -> Output {
    let mut shell = String::new();
    for arg in argv {
        if !shell.is_empty() {
            shell.push(' ');
        }
        shell.push('\'');
        shell.push_str(&arg.replace('\'', "'\\''"));
        shell.push('\'');
    }
    // No success assertion: scan exits 3 on partial inventory;
    // tests assert the rows they need. `script -e` propagates the
    // child status into `output.status`.
    Command::new("script")
        .args(["-qec", &shell, "/dev/null"])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).replace('\r', "")
}

/// Human module rows (v0.6.0 P0-3 shape `  {kind} sha256=…`): the
/// only human lines carrying `sha256=` (verdict/MEANING/totals
/// lines never do; JSON spells the key `"sha256":`).
fn module_rows(text: &str) -> Vec<&str> {
    text.lines().filter(|l| l.contains("sha256=")).collect()
}

struct Sleeper(Child);
impl Sleeper {
    /// Plain sleeper (no OpenSSL mappings — no module rows).
    fn spawn() -> Self {
        Self(
            Command::new("sleep")
                .arg("120")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    /// Sleeper with libssl/libcrypto mapped (module rows expected).
    fn spawn_tls() -> Self {
        Self(
            Command::new("python3")
                .args(["-c", "import ssl, time; time.sleep(120)"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn pid(&mut self) -> u32 {
        self.0.id()
    }
}
impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Cell 2: symlink chain resolves to the canonical target on a TTY;
/// full machine outputs identical with the flag on vs off.
#[test]
fn cell2_chain_resolves_canonical_machine_bytes_identical() {
    let dir = scratch("cell2");
    let sentinel = dir.join("SENTINEL_resolve_only");
    fs::create_dir(&sentinel).unwrap();
    let real = build_so(&sentinel, "real.so");
    let b = dir.join("b.so");
    let a = dir.join("a.so");
    symlink(&real, &b);
    symlink(&b, &a);

    // Human TTY leg: canonical path shown, chain links not shown.
    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "inspect",
        "--module",
        a.to_str().unwrap(),
        "--resolve-paths",
    ]);
    let text = stdout_text(&out);
    assert!(out.status.success(), "{text}");
    let row = module_rows(&text);
    assert_eq!(row.len(), 1, "{text}");
    assert!(
        row[0].contains(&format!("path={}", real.display())),
        "{}",
        row[0]
    );
    assert!(!row[0].contains("a.so"), "{}", row[0]);

    // Machine legs: JSON bytes / stderr / exit identical on vs off.
    let off = bin()
        .args(["inspect", "--module", a.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    let on = bin()
        .args([
            "inspect",
            "--module",
            a.to_str().unwrap(),
            "--json",
            "--resolve-paths",
        ])
        .output()
        .unwrap();
    assert_eq!(off.status, on.status);
    assert_eq!(off.stdout, on.stdout);
    assert_eq!(off.stderr, on.stderr);
    assert!(!stdout_text(&on).contains("SENTINEL_resolve_only"));
    assert!(!String::from_utf8_lossy(&on.stderr).contains("SENTINEL_resolve_only"));
}

/// Cell 5: flag absent → no `path=` fragment anywhere (human or
/// JSON). v0.6.0 P0-3 stdout split: the module route's human bytes
/// carry rows, never the JSON document (the old human-tail-equals-
/// `--json` comparison is retired with the mixed output); existing
/// golden suites pin the remaining routes' bytes. No-I/O leg is the
/// unit cell `writer_gates_flag_terminal_and_status_without_io`.
#[test]
fn cell5_flag_absent_omits_fragments() {
    let dir = scratch("cell5");
    let real = build_so(&dir, "real.so");
    for extra in [&["--json"][..], &[][..]] {
        let mut args = vec!["inspect", "--module", real.to_str().unwrap()];
        args.extend_from_slice(extra);
        let out = bin().args(&args).output().unwrap();
        assert!(out.status.success());
        assert!(!stdout_text(&out).contains("path="), "{args:?}");
        assert!(!stdout_text(&out).contains("real.so"), "{args:?}");
    }
    // Human bytes: MEANING + module rows + error counts, no JSON.
    let human = bin()
        .args(["inspect", "--module", real.to_str().unwrap()])
        .output()
        .unwrap();
    let human_text = stdout_text(&human);
    assert!(human_text.contains("Passive inventory:"), "{human_text}");
    assert_eq!(module_rows(&human_text).len(), 1, "{human_text}");
    assert!(human_text.contains("errors: 0"), "{human_text}");
    assert!(!human_text.contains("\"schema_version\""), "{human_text}");
}

/// Cell 6 as amended by v0.6.0 D1 (never-in-JSON gate rejected):
/// machine modes ACQUIRE path evidence now, but stay flag-identical
/// (the module route carries no path keys; discovery JSON acquires
/// in both runs — see `v060_json_paths_come_from_custody_not_maps_text`);
/// redirected human output renders the not-a-terminal placeholder,
/// never a path.
#[test]
fn cell6_machine_and_redirected_bypass() {
    let dir = scratch("cell6");
    let real = build_so(&dir, "real.so");
    let module = real.to_str().unwrap().to_string();

    // --json with the flag: bytes identical to --json without (both
    // runs acquire under D1; the module route has no path keys).
    let off = bin()
        .args(["inspect", "--module", &module, "--json"])
        .output()
        .unwrap();
    let on = bin()
        .args(["inspect", "--module", &module, "--json", "--resolve-paths"])
        .output()
        .unwrap();
    assert_eq!(off.stdout, on.stdout);
    assert!(!stdout_text(&on).contains("path="));
    // D1: --json on a TTY acquires like piped JSON (same evidence
    // both sides): pty JSON bytes equal piped bytes.
    let tty_json = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "inspect",
        "--module",
        module.as_str(),
        "--json",
        "--resolve-paths",
    ]);
    assert_eq!(stdout_text(&tty_json).as_bytes(), off.stdout.as_slice());

    // Watch NDJSON with/without the flag: identical records
    // modulo wall-clock stamps (F5a — a TLS child guarantees
    // inventoried rows; both runs acquire under D1, and stripping
    // covers wall-clock stamps only, so any flag-induced record
    // delta still fails).
    let mut child = Sleeper::spawn_tls();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let pid = child.pid().to_string();
    fn watch_json(pid: &str, flag: bool) -> Output {
        let mut args = vec![
            "scan".to_string(),
            "--pid".to_string(),
            pid.to_string(),
            "--watch".to_string(),
            "--interval".to_string(),
            "1".to_string(),
            "--duration".to_string(),
            "1".to_string(),
            "--json".to_string(),
        ];
        if flag {
            args.push("--resolve-paths".to_string());
        }
        bin().args(&args).output().unwrap()
    }
    fn strip(value: &mut serde_json::Value) {
        // Wall-clock stamps + remaining-time budgets are
        // run-varying; everything else must be flag-identical.
        // (`capture_unix_ms` is D1's per-row wall stamp — same
        // class as the interval edges.)
        match value {
            serde_json::Value::Object(object) => {
                for key in [
                    "interval",
                    "poll_interval",
                    "elapsed",
                    "timeout",
                    "capture_unix_ms",
                ] {
                    object.remove(key);
                }
                for value in object.values_mut() {
                    strip(value);
                }
            }
            serde_json::Value::Array(items) => {
                for value in items {
                    strip(value);
                }
            }
            _ => {}
        }
    }
    fn stripped(output: &Output) -> Vec<serde_json::Value> {
        stdout_text(output)
            .lines()
            .map(|line| {
                let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
                strip(&mut value);
                value
            })
            .collect()
    }
    let off = watch_json(&pid, false);
    let on = watch_json(&pid, true);
    assert_eq!(off.status, on.status);
    assert_eq!(off.stderr, on.stderr);
    assert_eq!(stripped(&off), stripped(&on));
    assert!(!stdout_text(&on).contains("path="));
    assert!(!off.stdout.is_empty());

    // Redirected (piped) human output: placeholder, no real path.
    let piped = bin()
        .args(["inspect", "--module", &module, "--resolve-paths"])
        .output()
        .unwrap();
    let text = stdout_text(&piped);
    assert!(text.contains("path=(not-a-terminal)"), "{text}");
    assert!(!text.contains("real.so"), "{text}");
    assert!(!text.contains(dir.to_str().unwrap()), "{text}");
}

/// Cell 7: argv-only — env key changes nothing; `--resolve-paths`
/// takes no value (existing parser policy).
#[test]
fn cell7_argv_only_no_env_no_value() {
    let dir = scratch("cell7");
    let real = build_so(&dir, "real.so");
    let module = real.to_str().unwrap().to_string();
    let clean = bin()
        .args(["inspect", "--module", &module])
        .output()
        .unwrap();
    let env = bin()
        .env("OSSL_RESOLVE_PATHS", "1")
        .args(["inspect", "--module", &module])
        .output()
        .unwrap();
    assert_eq!(clean.status, env.status);
    assert_eq!(clean.stdout, env.stdout);
    assert_eq!(clean.stderr, env.stderr);

    // Value-taking shape rejected like any unknown flag shape.
    let bad = bin()
        .args(["inspect", "--module", &module, "--resolve-paths=x"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

/// Cell 4 (integration legs): `/proc/<pid>/exe` (magic link) never
/// publishes its spelling — `(unavailable)` on a TTY; an ordinary
/// directory literally named `proc` resolves normally. Walk/swap
/// mechanics are unit cells (`proc_magic_links_suppress_by_link_type`,
/// `swap_safe_to_magic_mid_walk_suppresses`, ...).
#[test]
fn cell4_proc_magic_suppresses_plain_proc_resolves() {
    // Magic-link target: small ELF (sleep) parses and stages a row,
    // but the magic spelling never publishes.
    let mut child = Sleeper::spawn();
    let exe = format!("/proc/{}/exe", child.pid());
    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "inspect",
        "--module",
        exe.as_str(),
        "--resolve-paths",
    ]);
    let text = stdout_text(&out);
    assert!(out.status.success(), "{text}");
    let row = module_rows(&text);
    assert_eq!(row.len(), 1, "{text}");
    assert!(row[0].contains("path=(unavailable)"), "{}", row[0]);
    assert!(!text.contains("/proc/"), "{text}");

    // Contrast: ordinary directory named `proc`.
    let dir = scratch("cell4");
    let procdir = dir.join("proc");
    fs::create_dir(&procdir).unwrap();
    let real = build_so(&procdir, "real.so");
    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "inspect",
        "--module",
        real.to_str().unwrap(),
        "--resolve-paths",
    ]);
    let text = stdout_text(&out);
    let row = module_rows(&text);
    assert_eq!(row.len(), 1, "{text}");
    assert!(
        row[0].contains(&format!("path={}", real.display())),
        "{}",
        row[0]
    );
}

/// Cell 8 (integration leg): hostile bytes in a real filename are
/// sanitized + bounded on the TTY row; no escape survives. Unit cell:
/// `display_sanitizes_and_bounds_verified_paths`.
#[test]
fn cell8_hostile_filename_sanitized_on_tty() {
    let dir = scratch("cell8");
    // 300-char total path: deep nesting + hostile leaf name.
    let mut deep = dir.clone();
    for i in 0..8 {
        deep = deep.join(format!("nest{i:02}-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        fs::create_dir(&deep).unwrap();
    }
    let hostile = "x-\u{1b}]0;owned\u{07}-\u{202e}rtl-\r\n-\u{0090}dcs.so";
    assert!(deep.join(hostile).as_os_str().len() < 4096);
    let target = deep.join(hostile);
    let source = deep.join("s.c");
    fs::write(&source, "int marker(void) { return 1; }\n").unwrap();
    let result = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&target)
        .arg(&source)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(target.as_os_str().as_bytes().len() > 200);

    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "inspect",
        "--module",
        target.to_str().unwrap(),
        "--resolve-paths",
    ]);
    let raw = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    assert!(!raw.contains('\u{1b}'), "{raw:?}");
    let row = module_rows(&raw);
    assert_eq!(row.len(), 1, "{raw}");
    assert!(row[0].contains('…'), "{}", row[0]);
    assert!(!row[0].contains('\u{202e}'), "{}", row[0]);
}

/// Cell 9 (route legs): every intended route renders `path=`
/// fragments on a TTY with the flag. Backing-divergence mechanics are
/// unit cells (`establish_proves_or_refuses`, ...).
#[test]
fn cell9_all_routes_render_tty_fragments() {
    let dir = scratch("cell9");
    let real = build_so(&dir, "real.so");

    // inspect --module route.
    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "inspect",
        "--module",
        real.to_str().unwrap(),
        "--resolve-paths",
    ]);
    let text = stdout_text(&out);
    assert!(
        module_rows(&text).iter().any(|l| l.contains("path=")),
        "{text}"
    );

    // scan --pid route.
    let mut child = Sleeper::spawn_tls();
    // libssl loads at import; wait for the mapping to appear.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let pid = child.pid().to_string();
    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "scan",
        "--pid",
        pid.as_str(),
        "--resolve-paths",
    ]);
    let text = stdout_text(&out);
    let objects = module_rows(&text);
    assert!(!objects.is_empty(), "{text}");
    assert!(objects.iter().all(|l| l.contains("path=")), "{text}");

    // inspect --pid route.
    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "inspect",
        "--pid",
        pid.as_str(),
        "--resolve-paths",
    ]);
    let text = stdout_text(&out);
    let objects = module_rows(&text);
    assert!(!objects.is_empty(), "{text}");
    assert!(objects.iter().all(|l| l.contains("path=")), "{text}");

    // scan --watch route: change rows carry fragments.
    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "scan",
        "--pid",
        pid.as_str(),
        "--watch",
        "--interval",
        "1",
        "--duration",
        "2",
        "--resolve-paths",
    ]);
    let text = stdout_text(&out);
    assert!(
        text.lines()
            .any(|l| l.contains("module_seen") && l.contains("path=")),
        "{text}"
    );

    // scan --watch --observe-crypto route (external F4): Object
    // rows carry fragments on a TTY with the flag.
    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "scan",
        "--pid",
        pid.as_str(),
        "--watch",
        "--observe-crypto",
        "--interval",
        "1",
        "--duration",
        "3",
        "--resolve-paths",
    ]);
    let text = stdout_text(&out);
    assert!(
        text.lines()
            .any(|l| l.contains("Object ") && l.contains("path=")),
        "{text}"
    );
}

/// Cell 1 (integration leg): every TTY `path=` value is either a
/// `(placeholder)` or a canonical on-disk path — adversarial maps
/// text can never surface. Status-gate + no-I/O legs are the unit
/// cell `writer_gates_flag_terminal_and_status_without_io`.
#[test]
fn cell1_tty_paths_canonical_or_placeholder() {
    let mut child = Sleeper::spawn_tls();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let pid = child.pid().to_string();
    let out = pty_run(&[
        env!("CARGO_BIN_EXE_osslscope"),
        "scan",
        "--pid",
        pid.as_str(),
        "--resolve-paths",
    ]);
    let text = stdout_text(&out);
    let mut rows = 0;
    for line in module_rows(&text) {
        rows += 1;
        // Rows end `path={value} version={…}` with version= last,
        // so the trailing split isolates the path value (these
        // system-lib paths never embed " version=").
        let head = line.rsplit_once(" version=").unwrap().0;
        let value = head.rsplit_once("path=").unwrap().1;
        if value.starts_with('(') {
            assert!(value.ends_with(')'), "{line}");
        } else {
            let path = Path::new(value);
            assert!(!value.contains(".."), "{line}");
            assert_eq!(
                fs::canonicalize(path).unwrap(),
                path,
                "non-canonical: {line}"
            );
        }
    }
    assert!(rows > 0, "{text}");
}

/// External F3: under FD pressure the flag cannot change machine
/// records or exit status. 40 distinct modules with RLIMIT_NOFILE=64:
/// the machine loop stages no resolve state at all (deferred
/// materialization), so the `--json` bytes and exits are identical
/// with the flag on vs off — on a TTY (acquisition active) and piped.
/// (Pre-fix inline staging retained 40 extra dups mid-loop and
/// degraded the flagged run under this limit.)
#[test]
fn f3_fd_pressure_leaves_machine_records_identical() {
    let dir = scratch("f3");
    let mut modules: Vec<String> = Vec::new();
    for i in 0..40 {
        let so = build_so(&dir, &format!("m{i:02}.so"));
        modules.push(so.to_str().unwrap().to_string());
    }
    fn limited(argv: &[String]) -> Output {
        // SAFETY: pre_exec runs after fork, before exec; setrlimit
        // is async-signal-safe and only narrows this child.
        unsafe {
            Command::new("script")
                .args(["-qec", &argv.join(" "), "/dev/null"])
                .stdin(Stdio::null())
                .pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 64,
                        rlim_max: 64,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                })
                .output()
                .unwrap()
        }
    }
    fn argv(binary: &str, modules: &[String], flag: bool, json: bool) -> Vec<String> {
        let mut argv = vec![format!("'{binary}'"), "'inspect'".to_string()];
        for module in modules {
            argv.push("'--module'".to_string());
            argv.push(format!("'{module}'"));
        }
        if json {
            argv.push("'--json'".to_string());
        }
        if flag {
            argv.push("'--resolve-paths'".to_string());
        }
        argv
    }
    // Shell-quote check: single-quote wrap (no quotes in tmp paths).
    let binary = env!("CARGO_BIN_EXE_osslscope");
    // Machine bytes identical with the flag on vs off (the module
    // route carries no timestamps, so this is an exact comparison;
    // v0.6.0 P0-3 split the JSON out of human bytes, hence `--json`).
    let off = limited(&argv(binary, &modules, false, true));
    let on = limited(&argv(binary, &modules, true, true));
    assert_eq!(off.status, on.status);
    assert_eq!(stdout_text(&off), stdout_text(&on));
    // And the flagged run still rendered its rows (placeholders or
    // paths — acquisition ran, machine output didn't move).
    let human = limited(&argv(binary, &modules, true, false));
    let human_text = stdout_text(&human);
    assert!(
        module_rows(&human_text).iter().any(|l| l.contains("path=")),
        "{human_text}"
    );
}

/// Cells 3 + 10 (integration legs): removal races classify without
/// path-bearing diagnostics; stderr/exit identical on vs off.
/// Replacement/retarget/EACCES mechanics are unit cells
/// (`replacement_retarget_and_removal_classify`,
/// `permission_and_length_failures_suppress`).
#[test]
fn cell3_and_10_removal_stable_no_path_in_diagnostics() {
    let dir = scratch("cell3");
    let dangling = dir.join("dangling.so");
    symlink(&dir.join("gone.so"), &dangling);
    let target = dangling.to_str().unwrap().to_string();

    let off = bin()
        .args(["inspect", "--module", &target])
        .output()
        .unwrap();
    let on = bin()
        .args(["inspect", "--module", &target, "--resolve-paths"])
        .output()
        .unwrap();
    assert_eq!(off.status, on.status);
    assert_eq!(off.stdout, on.stdout);
    assert_eq!(off.stderr, on.stderr);
    assert!(!stdout_text(&on).contains("path="));
    let stderr = String::from_utf8_lossy(&on.stderr);
    assert!(!stderr.contains("dangling"), "{stderr}");
    assert!(!stderr.contains(dir.to_str().unwrap()), "{stderr}");
}

#[test]
fn v060_json_paths_come_from_custody_not_maps_text() {
    // Uses the file's existing helpers: scratch(), bin().
    let _dir = scratch("v060-paths");
    let mut workload = Command::new("python3")
        .args(["-c", "import ssl, time; time.sleep(120)"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = workload.id().to_string();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let snap = bin()
        .args(["scan", "--pid", &pid, "--json"])
        .output()
        .unwrap();
    let _ = workload.kill();
    let _ = workload.wait();
    let doc: serde_json::Value = serde_json::from_slice(&snap.stdout).unwrap();
    let modules = doc["processes"][0]["modules"].as_array().unwrap();
    assert!(!modules.is_empty(), "ssl workload has no modules");
    for module in modules {
        assert!(module.get("verified_path").is_some());
        assert!(module.get("verified_path_unavailable").is_some());
        assert!(module.get("maps_spelling").is_some());
        if module["identity_status"] == "verified" {
            if module["verified_path"].is_null() {
                assert!(!module["verified_path_unavailable"].is_null());
            } else {
                assert_eq!(
                    module["verified_path"]["path_encoding"].as_str().unwrap(),
                    "utf8"
                );
            }
        } else {
            assert!(module["verified_path"].is_null());
            assert_eq!(module["verified_path_unavailable"], "unverified_identity");
        }
        if !module["maps_spelling"].is_null() {
            assert_eq!(module["maps_spelling"]["source"], "proc_maps");
            assert_eq!(module["maps_spelling"]["verification"], "unverified");
        }
    }
}
