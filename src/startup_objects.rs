// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded pre-exec file discovery. Predictions are never mapped authority or a
//! public ABI: static shapes grant entry counting only; independently validated
//! public exports grant their existing typed ABI under original-owned custody.
use crate::{
    provider_observation::{
        ObservationBudget, ObservationGap,
        objects::{self, VerifiedStaticCandidate},
    },
    target::OwnedTarget,
};
use std::{
    collections::{BTreeSet, VecDeque},
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const MAX_FILES: usize = 128;
const MAX_METADATA: u64 = 128 << 20;
const MAX_NEEDED: usize = 256;
pub(crate) enum StartupAcquisition {
    Legacy,
    TypedSources,
}
pub(crate) fn acquire_startup(
    mut acquire: impl FnMut(StartupAcquisition) -> Result<(), ObservationGap>,
) -> [Result<(), ObservationGap>; 2] {
    // Anchors retain full-file capacity, including through the Object cache.
    // Complete legacy acquisition before spending any optional source capacity.
    [
        acquire(StartupAcquisition::Legacy),
        acquire(StartupAcquisition::TypedSources),
    ]
}
pub(crate) struct PreExecSites {
    pub(crate) candidates: Vec<VerifiedStaticCandidate>,
    pub(crate) apis: Vec<objects::StartupApiSite>,
    pub(crate) typed: Vec<objects::StartupTypedSite>,
    pub(crate) gaps: BTreeSet<ObservationGap>,
    pub(crate) copied_skipped: usize,
    pub(crate) plan_arrays: Vec<crate::provider_observation::copied_plan::FileArrays>,
}
fn check(deadline: Instant, cancel: &AtomicBool) -> Result<(), ObservationGap> {
    if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
        Err(ObservationGap::SnapshotLag)
    } else {
        Ok(())
    }
}
// Codex R1: bounded startup file read (at most `limit` bytes),
// cancellable between chunks exactly like the F3 scan-path
// `Work::read`. Cancellation/deadline aborts use the same
// SnapshotLag outcome `check` produces everywhere in this
// acquisition path.
fn read_startup_bytes(
    file: impl Read,
    limit: u64,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, ObservationGap> {
    let mut file = file;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        check(deadline, cancel)?;
        let allowed = limit.saturating_sub(bytes.len() as u64);
        if allowed == 0 {
            check(deadline, cancel)?;
            return Ok(bytes);
        }
        let count = chunk
            .len()
            .min(usize::try_from(allowed).unwrap_or(usize::MAX));
        let read = match file.read(&mut chunk[..count]) {
            // EINTR checks cancel before retry: a signal that
            // cancelled the acquisition ends the read; any other
            // interruption retries as before.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                check(deadline, cancel)?;
                continue;
            }
            Err(_) => return Err(ObservationGap::BackingUnavailable),
            Ok(read) => read,
        };
        if read == 0 {
            check(deadline, cancel)?;
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}
fn expand_dirs(value: &str, origin: &Path) -> Vec<PathBuf> {
    value
        .split(':')
        .take(MAX_NEEDED)
        .filter_map(|component| {
            if component.len() > 4096 {
                return None;
            }
            let expanded = component
                .replace("${ORIGIN}", &origin.to_string_lossy())
                .replace("$ORIGIN", &origin.to_string_lossy());
            if expanded.contains('$') || expanded.len() > 4096 {
                return None;
            }
            Some(PathBuf::from(if expanded.is_empty() {
                ".".into()
            } else {
                expanded
            }))
        })
        .collect()
}
fn append_dirs(dirs: &mut Vec<PathBuf>, value: &str, origin: &Path) {
    if dirs.len() < MAX_NEEDED {
        dirs.extend(
            expand_dirs(value, origin)
                .into_iter()
                .take(MAX_NEEDED - dirs.len()),
        );
    }
}
fn open_file(path: &Path) -> Result<File, ObservationGap> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ObservationGap::BackingUnavailable)?;
    if !file
        .metadata()
        .map_err(|_| ObservationGap::BackingUnavailable)?
        .is_file()
    {
        return Err(ObservationGap::BackingUnavailable);
    }
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // Proc pseudo-files can claim regular-file metadata; refuse before reading.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0
        || unsafe { filesystem.assume_init() }.f_type == libc::PROC_SUPER_MAGIC
    {
        return Err(ObservationGap::BackingUnavailable);
    }
    Ok(file)
}
pub(crate) fn prepare_owned_startup(
    child: &OwnedTarget,
    argv: &[String],
    budget: &mut ObservationBudget,
    deadline: Instant,
    cancel: &AtomicBool,
    plan: Option<&crate::provider_observation::copied_plan::CopiedPlan>,
) -> Result<PreExecSites, ObservationGap> {
    check(deadline, cancel)?;
    budget.set_deadline(deadline);
    let custody = objects::StartupProcess::held(child)?;
    let path = std::env::var("PATH").unwrap_or_else(|_| "/bin:/usr/bin".into());
    // This is the observer's inherited spawn environment, never /proc environ.
    let ld = std::env::var("LD_LIBRARY_PATH").ok();
    let env = crate::discovery::onboard::SpawnEnv {
        path: &path,
        ld_library_path: ld.as_deref(),
    };
    let executable = crate::discovery::onboard::resolve_spawn_exe(
        argv.first().ok_or(ObservationGap::BackingUnavailable)?,
        &env,
    );
    let mut pending = VecDeque::from([(executable, Vec::<PathBuf>::new())]);
    let mut seen = BTreeSet::new();
    let mut result = PreExecSites {
        candidates: Vec::new(),
        apis: Vec::new(),
        typed: Vec::new(),
        gaps: BTreeSet::new(),
        copied_skipped: 0,
        plan_arrays: Vec::new(),
    };
    // Loader cache/hwcaps, preloads, scripts, dynamically selected modules and
    // inherited RPATH subtleties cannot establish universal startup coverage.
    result.gaps.insert(ObservationGap::SamplingPartial);
    'files: while let Some((path, inherited)) = pending.pop_front() {
        check(deadline, cancel)?;
        if seen.len() >= MAX_FILES {
            result.gaps.insert(ObservationGap::ObjectLimit);
            break;
        }
        let mut file = match open_file(&path) {
            Ok(f) => f,
            Err(g) => {
                result.gaps.insert(g);
                continue;
            }
        };
        let before = file
            .metadata()
            .map_err(|_| ObservationGap::BackingUnavailable)?;
        if !seen.insert((before.dev(), before.ino())) {
            continue;
        }
        if before.len() > MAX_METADATA {
            result.gaps.insert(ObservationGap::ReadLimit);
            continue;
        }
        let scratch = match &budget.memory {
            Some(pool) => match pool.reserve(
                crate::inventory::elf::parser_scratch_bytes(before.len())
                    .map_err(|_| ObservationGap::ReadLimit)?,
            ) {
                Some(lease) => Some(lease),
                None => {
                    result.gaps.insert(ObservationGap::StateLimit);
                    continue;
                }
            },
            None => None,
        };
        if let Err(gap) = budget.read(before.len()) {
            result.gaps.insert(gap);
            break;
        }
        let bytes = read_startup_bytes(file.by_ref(), before.len() + 1, deadline, cancel)?;
        let after = file.metadata().map_err(|_| ObservationGap::ObjectChanged)?;
        if bytes.len() as u64 != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(ObservationGap::ObjectChanged);
        }
        // Codex F3: admission is cancel-aware; a Deadline abort
        // is lag (like `check` above), never malformed evidence.
        match crate::inventory::elf::admit_parser_metadata(&bytes, cancel) {
            Ok(()) => {}
            Err(crate::inventory::GapReason::Deadline) => {
                result.gaps.insert(ObservationGap::SnapshotLag);
                continue;
            }
            Err(_) => {
                result.gaps.insert(ObservationGap::MalformedElf);
                continue;
            }
        }
        // Codex R1: a signal landing between the read and the parse
        // aborts before the non-interruptible goblin parse instead of
        // paying for the parse plus the dependency walks below. The
        // post-parse side is the existing `check` before
        // `startup_candidates`.
        check(deadline, cancel)?;
        let elf = match goblin::elf::Elf::parse(&bytes) {
            Ok(e)
                if e.is_64
                    && e.little_endian
                    && e.header.e_machine == goblin::elf::header::EM_X86_64 =>
            {
                e
            }
            _ => {
                result.gaps.insert(ObservationGap::MalformedElf);
                continue;
            }
        };
        let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
        let origin = resolved.parent().unwrap_or(Path::new("."));
        let mut dirs = Vec::new();
        let mut children_inherited = inherited.clone();
        if elf.runpaths.is_empty() {
            for value in &elf.rpaths {
                append_dirs(&mut dirs, value, origin);
            }
            children_inherited.splice(0..0, dirs.clone());
            dirs.extend(inherited.into_iter().take(MAX_NEEDED - dirs.len()));
        }
        if let Some(ld) = &ld {
            append_dirs(&mut dirs, ld, origin);
        }
        for value in &elf.runpaths {
            append_dirs(&mut dirs, value, origin);
        }
        dirs.extend(crate::discovery::onboard::default_loader_dirs());
        dirs.truncate(MAX_NEEDED);
        children_inherited.truncate(MAX_NEEDED);
        if let Some(interpreter) = elf.interpreter {
            if interpreter.len() <= 4096 && pending.len() < MAX_FILES {
                pending.push_back((PathBuf::from(interpreter), Vec::new()));
            } else {
                result.gaps.insert(ObservationGap::ReadLimit);
            }
        }
        if elf.libraries.len() > MAX_NEEDED {
            result.gaps.insert(ObservationGap::ReadLimit);
        }
        for needed in elf.libraries.iter().take(MAX_NEEDED) {
            if needed.len() > 4096 {
                result.gaps.insert(ObservationGap::ReadLimit);
                continue;
            }
            let found = if needed.contains('/') {
                Some(PathBuf::from(needed))
            } else {
                dirs.iter()
                    .map(|dir| dir.join(needed))
                    .find(|p| p.is_file())
            };
            match found {
                Some(p) if pending.len() < MAX_FILES => {
                    if let Err(gap) = budget.state(
                        p.as_os_str().len()
                            + children_inherited
                                .iter()
                                .map(|d| d.as_os_str().len() + std::mem::size_of::<PathBuf>())
                                .sum::<usize>()
                            + 128,
                    ) {
                        result.gaps.insert(gap);
                        break 'files;
                    }
                    pending.push_back((p, children_inherited.clone()))
                }
                _ => {
                    result.gaps.insert(ObservationGap::BackingUnavailable);
                }
            }
        }
        drop(elf);
        drop(bytes);
        drop(scratch);
        check(deadline, cancel)?;
        match objects::startup_candidates(custody.clone(), file, budget, plan) {
            Ok(objects::StartupCandidates {
                candidates,
                apis,
                typed,
                partial,
                typed_gap,
                plan_gap,
                copied_skipped,
                plan_arrays,
            }) => {
                result.apis.extend(apis);
                result.typed.extend(typed);
                result.copied_skipped += copied_skipped;
                result.plan_arrays.push(plan_arrays);
                if let Some(gap) = typed_gap {
                    result.gaps.insert(gap);
                }
                if let Some(gap) = plan_gap {
                    result.gaps.insert(gap);
                }
                if partial {
                    result.gaps.insert(ObservationGap::DispatchPartial);
                }
                result.candidates.extend(candidates);
            }
            Err(gap) => {
                result.gaps.insert(gap);
            }
        }
    }
    check(deadline, cancel)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_static_impostor_never_receives_a_metadata_signature() {
        let dir =
            std::env::temp_dir().join(format!("osslscope-startup-impostor-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let path = dir.join("impostor.so");
        assert!(
            std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-O2", "-Wl,-z,relro", "-o"])
                .arg(&path)
                .arg("tests/fixtures/static_tables.c")
                .status()
                .unwrap()
                .success()
        );
        let child =
            OwnedTarget::spawn_stopped(&["/bin/true".into()], crate::target::WorkloadDest::Null)
                .unwrap();
        let objects::StartupCandidates {
            candidates, apis, ..
        } = objects::startup_candidates(
            objects::StartupProcess::held(&child).unwrap(),
            File::open(path).unwrap(),
            &ObservationBudget::default(),
            None,
        )
        .unwrap();
        assert!(
            !candidates.is_empty(),
            "public table-shaped fixture is a real entry-count candidate"
        );
        assert!(
            apis.is_empty(),
            "public tables and executable callbacks cannot mint any argument-reading role"
        );
        assert!(candidates.iter().all(|c| c.site().is_startup()));
    }
    #[test]
    fn startup_requires_held_original_and_honors_cancel_and_deadline() {
        let argv = vec!["/bin/true".into()];
        let mut child =
            OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null).unwrap();
        let mut budget = ObservationBudget::default();
        assert!(matches!(
            prepare_owned_startup(
                &child,
                &argv,
                &mut budget,
                Instant::now() + std::time::Duration::from_secs(2),
                &AtomicBool::new(true),
                None,
            ),
            Err(ObservationGap::SnapshotLag)
        ));
        assert_eq!(budget.elf_read_bytes(), 0);
        assert!(matches!(
            prepare_owned_startup(
                &child,
                &argv,
                &mut budget,
                Instant::now(),
                &AtomicBool::new(false),
                None,
            ),
            Err(ObservationGap::SnapshotLag)
        ));
        child.release().unwrap();
        assert!(objects::StartupProcess::held(&child).is_err());
        let until = Instant::now() + std::time::Duration::from_secs(2);
        while child.peek_exit().unwrap().is_none() && Instant::now() < until {
            std::thread::yield_now();
        }
        assert!(child.peek_exit().unwrap().is_some());
        child.finish_observation().unwrap();
    }
    #[test]
    fn startup_rejects_proc_pseudofiles_before_any_read() {
        assert!(matches!(
            open_file(Path::new("/proc/self/environ")),
            Err(ObservationGap::BackingUnavailable)
        ));
        assert!(matches!(
            open_file(Path::new("/proc/self/mem")),
            Err(ObservationGap::BackingUnavailable)
        ));
    }
    #[test]
    fn origin_is_relative_to_each_dependency_and_other_tokens_are_not_guessed() {
        let mut dirs = Vec::new();
        for _ in 0..MAX_NEEDED + 1 {
            append_dirs(&mut dirs, "/a:/b", Path::new("/"));
        }
        assert_eq!(dirs.len(), MAX_NEEDED);
        assert!(expand_dirs(&"x".repeat(4097), Path::new("/")).is_empty());
        assert_eq!(
            expand_dirs("$ORIGIN/lib:${ORIGIN}/../lib:$LIB", Path::new("/a/b")),
            vec![PathBuf::from("/a/b/lib"), PathBuf::from("/a/b/../lib")]
        );
    }
    // Codex R1: cancellation landing after a successful read chunk
    // aborts the startup acquisition read promptly with SnapshotLag —
    // it never waits for the whole object. Deterministic without
    // sleeps: the first write is sized above the pipe capacity (N1),
    // so its return PROVES the reader drained chunks; the writer
    // then sets cancel and starts a blocking probe write also sized
    // above the measured capacity (N2). A prompt abort closes the
    // read end (probe fails with EPIPE); a reader that keeps
    // draining lets the probe complete — which the post-read cancel
    // check would then mask as SnapshotLag, so the probe outcome
    // (not just the error) is what proves promptness.
    #[test]
    fn v060_startup_read_aborts_promptly_on_cancel_after_chunk() {
        use std::os::fd::FromRawFd as _;
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read = unsafe { File::from_raw_fd(fds[0]) };
        let mut write = unsafe { File::from_raw_fd(fds[1]) };
        // N1: size the first write from the pipe capacity with
        // margin — never assume a fixed payload exceeds it.
        let pipe_cap = unsafe { libc::fcntl(fds[0], libc::F_GETPIPE_SZ) };
        assert!(
            pipe_cap > 0,
            "pipe must report a positive capacity, got {pipe_cap}"
        );
        let first_write = pipe_cap as usize + 64 * 1024;
        // N2: size the post-cancel probe from the measured
        // capacity too — a fixed 1 MiB probe could complete on a
        // ≥1 MiB pipe before the reader closes and fail a correct
        // implementation. The 64 KiB margin exceeds the worst-case
        // racy drain (one 8 KiB chunk past a loop-top check) 8×,
        // so only a reader that keeps draining lets it complete.
        let probe_write = pipe_cap as usize + 64 * 1024;
        let cancel = AtomicBool::new(false);
        let writer_cancel = &cancel;
        std::thread::scope(|s| {
            // `move`: the writer OWNS the write end, so it closes
            // when the writer finishes — a borrow would leak the FD
            // on this stack and the reader would block past EOF
            // forever (deadlock, not a timeout).
            let probe = s.spawn(move || {
                use std::io::Write as _;
                write.write_all(&vec![0x41u8; first_write]).unwrap();
                writer_cancel.store(true, Ordering::Relaxed);
                // Blocking probe: EPIPE here is the fix working (the
                // reader aborted and closed the read end), completion
                // means the reader kept draining past the cancel.
                write.write_all(&vec![0x43u8; probe_write]).is_err()
            });
            let deadline = Instant::now() + std::time::Duration::from_secs(30);
            let outcome = read_startup_bytes(read, u64::MAX, deadline, &cancel);
            assert!(
                matches!(outcome, Err(ObservationGap::SnapshotLag)),
                "cancel after a successful chunk must abort the startup read"
            );
            assert!(
                probe.join().unwrap(),
                "startup read kept draining past cancel instead of aborting promptly"
            );
        });
    }
}
