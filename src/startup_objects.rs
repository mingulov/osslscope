// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded pre-exec file discovery. Predictions are never mapped authority or a
//! public ABI: only retained-file, original-owned-group entry counters result.
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
pub(crate) struct PreExecSites {
    pub(crate) candidates: Vec<VerifiedStaticCandidate>,
    pub(crate) apis: Vec<objects::StartupApiSite>,
    pub(crate) gaps: BTreeSet<ObservationGap>,
}
fn check(deadline: Instant, cancel: &AtomicBool) -> Result<(), ObservationGap> {
    if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
        Err(ObservationGap::SnapshotLag)
    } else {
        Ok(())
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
        gaps: BTreeSet::new(),
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
        let mut bytes = Vec::with_capacity(before.len() as usize + 1);
        file.by_ref()
            .take(before.len() + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ObservationGap::BackingUnavailable)?;
        check(deadline, cancel)?;
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
        if crate::inventory::elf::admit_parser_metadata(&bytes).is_err() {
            result.gaps.insert(ObservationGap::MalformedElf);
            continue;
        }
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
        match objects::startup_candidates(custody.clone(), file, budget) {
            Ok((candidates, apis, partial)) => {
                result.apis.extend(apis);
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
                &AtomicBool::new(true)
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
                &AtomicBool::new(false)
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
}
