//! Capture planner (P2): harvest doc + live maps → multi-link plan.
//!
//! Plans are ASLR-immune: doc rows carry the stable
//! backing{dev,ino,offset} triple, and entries resolve (path, offset)
//! through live mappings matched on dev:ino — runtime addresses are
//! never consulted. Userspace-first validation (offset < file size,
//! in X LOAD) keeps kernel EINVALs rare; survivors are isolated by
//! `bisect_attach` (bounded log n) into `unresolved_offsets`.
//! Plan-time rejects (unmapped / unreadable / past-eof /
//! not-executable) surface as `missed_attaches` — planned offsets
//! with no active probe at window end.
use crate::discovery::{elf, maps};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{OwnedFd, RawFd};

/// Cookie identity: what a plan index MEANS (drain attribution).
/// File offset (not addr) — stable across runs (ASLR-immune).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub provider: String,
    pub op: u32,
    pub funcid: u32,
    pub alg_class: String,
    pub offset: u64,
}

/// One planned probe: multi-link site + cookie + identity. Shared
/// implementations (same path+offset under several rows) attach ONCE
/// under the first identity; the rest ride as `aliases` (their calls
/// ARE counted — under the canonical cookie — so this is plan
/// metadata, not a gap counter).
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: String,
    pub offset: u64,
    pub cookie: u32,
    pub id: Identity,
    pub aliases: Vec<Identity>,
}

/// Plan-time reject → `missed_attaches` at window end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missed {
    pub dev: String,
    pub ino: u64,
    pub offset: u64,
    pub reason: &'static str,
}

/// Attach plan at one generation epoch.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub entries: Vec<Entry>,
    pub missed: Vec<Missed>,
    pub generation: u32,
}

/// One multi link's payload: parallel offsets + cookies for `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub path: String,
    pub offsets: Vec<u64>,
    pub cookies: Vec<u64>,
}

fn str_at(r: &serde_json::Value, k: &str) -> anyhow::Result<String> {
    r.get(k)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("harvest row lacks string {k:?}"))
}

fn u32_at(r: &serde_json::Value, k: &str) -> anyhow::Result<u32> {
    let v = r
        .get(k)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("harvest row lacks numeric {k:?}"))?;
    u32::try_from(v).map_err(|_| anyhow::anyhow!("harvest row {k:?} overflows u32"))
}

fn u64_at(r: &serde_json::Value, k: &str) -> anyhow::Result<u64> {
    r.get(k)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("harvest row lacks numeric {k:?}"))
}

/// Stable cookie allocator across fence re-plans. Cookies identify
/// (path, offset) for the whole run — old links keep firing with
/// correct cookies under new generations (the gen half of the key
/// separates pre/post-fence counts), so re-plans never detach.
/// Single-shot `plan` is the fresh-allocator case (cookies 0..n).
#[derive(Debug, Default)]
pub struct StableCookies {
    next: u32,
    ids: HashMap<(String, u64), u32>,
}

impl StableCookies {
    fn cookie_for(&mut self, path: &str, offset: u64) -> anyhow::Result<u32> {
        if let Some(&c) = self.ids.get(&(path.to_string(), offset)) {
            return Ok(c);
        }
        if self.next == u32::MAX {
            anyhow::bail!("cookie space exhausted");
        }
        let c = self.next;
        self.next += 1;
        self.ids.insert((path.to_string(), offset), c);
        Ok(c)
    }
}

/// Plan every doc row against live mappings. `files` maps link-path
/// → file bytes (caller pre-reads each distinct mapped path once).
/// Fail-closed: malformed rows are an error, never a skip.
pub fn plan(
    doc: &serde_json::Value,
    live: &[maps::Mapping],
    files: &HashMap<String, Vec<u8>>,
    generation: u32,
) -> anyhow::Result<Plan> {
    plan_stable(doc, live, files, generation, &mut StableCookies::default())
}

/// `plan` with caller-held cookie stability (fence re-plans reuse
/// cookies for surviving sites; fresh sites mint new ones).
pub fn plan_stable(
    doc: &serde_json::Value,
    live: &[maps::Mapping],
    files: &HashMap<String, Vec<u8>>,
    generation: u32,
    stable: &mut StableCookies,
) -> anyhow::Result<Plan> {
    let rows = doc
        .get("rows")
        .and_then(|r| r.as_array())
        .ok_or_else(|| anyhow::anyhow!("harvest doc has no rows array"))?;
    let mut out = Plan {
        entries: Vec::new(),
        missed: Vec::new(),
        generation,
    };
    let mut seen: HashMap<(String, u64), usize> = HashMap::new();
    for r in rows {
        let backing = r
            .get("backing")
            .ok_or_else(|| anyhow::anyhow!("harvest row lacks backing"))?;
        let id = Identity {
            provider: str_at(r, "provider")?,
            op: u32_at(r, "op")?,
            funcid: u32_at(r, "funcid")?,
            alg_class: str_at(r, "alg_class")?,
            offset: u64_at(backing, "offset")?,
        };
        let dev = str_at(backing, "dev")?;
        let ino = u64_at(backing, "ino")?;
        // Candidate link paths: X mappings of the same file.
        let mut cands: Vec<&str> = live
            .iter()
            .filter(|m| m.x && m.ino != 0 && m.dev == dev && m.ino == ino)
            .map(|m| m.path.as_str())
            .collect();
        cands.sort_unstable();
        cands.dedup();
        let path = cands.iter().find(|p| files.contains_key(**p));
        let Some(path) = path else {
            out.missed.push(Missed {
                dev,
                ino,
                offset: id.offset,
                reason: if cands.is_empty() {
                    "unmapped"
                } else {
                    "unreadable"
                },
            });
            continue;
        };
        let bytes = &files[*path];
        if id.offset >= bytes.len() as u64 {
            out.missed.push(Missed {
                dev,
                ino,
                offset: id.offset,
                reason: "past-eof",
            });
            continue;
        }
        let reason = match elf::parse_elf(bytes) {
            Ok(e) if elf::offset_in_x_segment(&e, id.offset) => None,
            Ok(_) => Some("not-executable"),
            Err(_) => Some("unreadable"),
        };
        if let Some(reason) = reason {
            out.missed.push(Missed {
                dev,
                ino,
                offset: id.offset,
                reason,
            });
            continue;
        }
        // Shared implementation: alias under the canonical cookie.
        let key = (path.to_string(), id.offset);
        if let Some(&i) = seen.get(&key) {
            out.entries[i].aliases.push(id);
            continue;
        }
        let cookie = stable.cookie_for(path, id.offset)?;
        seen.insert(key, out.entries.len());
        out.entries.push(Entry {
            path: path.to_string(),
            offset: id.offset,
            cookie,
            id,
            aliases: Vec::new(),
        });
    }
    Ok(out)
}

/// Group entries by link path (sorted by path, offsets ascending —
/// deterministic link order for stable behavior + diffable logs).
pub fn groups(plan: &Plan) -> Vec<Group> {
    let mut by_path: HashMap<&str, Vec<&Entry>> = HashMap::new();
    for e in &plan.entries {
        by_path.entry(e.path.as_str()).or_default().push(e);
    }
    let mut paths: Vec<&str> = by_path.keys().copied().collect();
    paths.sort_unstable();
    paths
        .into_iter()
        .map(|p| {
            let mut es = by_path.remove(p).unwrap();
            es.sort_by_key(|e| e.offset);
            Group {
                path: p.to_string(),
                offsets: es.iter().map(|e| e.offset).collect(),
                cookies: es.iter().map(|e| e.cookie as u64).collect(),
            }
        })
        .collect()
}

/// One multi link over `path` (production `bisect_attach` leaf).
pub fn attach_group(
    prog_fd: RawFd,
    pid: u32,
    path: &str,
    offsets: &[u64],
    cookies: &[u64],
) -> std::io::Result<OwnedFd> {
    let cpath = CString::new(path)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in link path"))?;
    ossl_bpf_sys::link_create_uprobe_multi(prog_fd, &cpath, offsets, cookies, pid)
}

/// Attach one group's sites, bisecting EINVALs to isolate
/// kernel-rejected offsets (bounded: ≤ 2n−1 attempts, log n depth).
/// `attach` tries a slice as ONE multi link. Non-EINVAL errors fail
/// the whole slice (no retry storm on EPERM-class faults). Returns
/// live links + refused site indices (→ `unresolved_offsets`).
/// Generic over the link handle so the isolation logic unit-tests
/// without caps or fds; production passes `attach_group`.
pub type TryAttach<'a, T> = dyn Fn(&[(u64, u64)]) -> std::io::Result<T> + 'a;

pub fn bisect_attach<T>(attach: &TryAttach<'_, T>, sites: &[(u64, u64)]) -> (Vec<T>, Vec<usize>) {
    let mut links = Vec::new();
    let mut bad = Vec::new();
    let mut stack: Vec<Vec<usize>> = vec![(0..sites.len()).collect()];
    while let Some(idxs) = stack.pop() {
        if idxs.is_empty() {
            continue;
        }
        let slice: Vec<(u64, u64)> = idxs.iter().map(|&i| sites[i]).collect();
        match attach(&slice) {
            Ok(l) => links.push(l),
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) && idxs.len() > 1 => {
                let mid = idxs.len() / 2;
                stack.push(idxs[mid..].to_vec());
                stack.push(idxs[..mid].to_vec());
            }
            Err(_) => bad.extend(idxs),
        }
    }
    bad.sort_unstable();
    (links, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real executable bytes (self): offsets derived from its own
    /// program headers (same precedent as elf::tests::self_bytes).
    fn self_bytes() -> Vec<u8> {
        std::fs::read(std::env::current_exe().unwrap()).unwrap()
    }

    /// (in-X-LOAD offset, in-file-but-not-X offset) from real phdrs.
    fn probe_offsets(bytes: &[u8]) -> (u64, u64) {
        use goblin::elf::program_header::{PF_X, PT_LOAD};
        let e = elf::parse_elf(bytes).unwrap();
        let x = e
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0)
            .unwrap();
        let r = e
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X == 0)
            .unwrap();
        (x.p_offset + 8, r.p_offset + 8)
    }

    fn row(op: u32, funcid: u32, dev: &str, ino: u64, off: u64) -> serde_json::Value {
        serde_json::json!({
            "provider": "spike", "op": op, "alg_class": "digest", "funcid": funcid,
            "addr": 0x7f00_0000_0000u64 + off,
            "backing": {"dev": dev, "ino": ino, "offset": off},
        })
    }

    fn mapping(dev: &str, ino: u64, path: &str) -> maps::Mapping {
        maps::Mapping {
            start: 0x7f00_0000_0000,
            end: 0x7f00_0000_1000,
            x: true,
            offset: 0,
            dev: dev.to_string(),
            ino,
            path: path.to_string(),
        }
    }

    fn doc(rows: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({"provider": "spike", "rows": rows})
    }

    #[test]
    fn plan_entries_aliases_groups() {
        let bytes = self_bytes();
        let (x_off, _) = probe_offsets(&bytes);
        let live = vec![mapping("08:01", 99, "/lib/spike.so")];
        let files = HashMap::from([("/lib/spike.so".to_string(), bytes)]);
        let d = doc(vec![
            row(1, 7, "08:01", 99, x_off),
            row(1, 9, "08:01", 99, x_off + 0x40),
            row(2, 7, "08:01", 99, x_off), // alias: same impl
        ]);
        let p = plan(&d, &live, &files, 3).unwrap();
        assert_eq!(p.generation, 3);
        assert!(p.missed.is_empty(), "{:?}", p.missed);
        assert_eq!(p.entries.len(), 2);
        assert_eq!((p.entries[0].cookie, p.entries[1].cookie), (0, 1));
        assert_eq!(p.entries[0].aliases.len(), 1);
        assert_eq!(p.entries[0].aliases[0].op, 2);
        let g = groups(&p);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].offsets, vec![x_off, x_off + 0x40]);
        assert_eq!(g[0].cookies, vec![0, 1]);
    }

    #[test]
    fn plan_missed_matrix() {
        let bytes = self_bytes();
        let (x_off, r_off) = probe_offsets(&bytes);
        let eof_off = bytes.len() as u64 + 8;
        let live = vec![
            mapping("08:01", 99, "/lib/spike.so"),
            mapping("08:01", 100, "/lib/gone.so"), // no bytes
        ];
        let files = HashMap::from([("/lib/spike.so".to_string(), bytes)]);
        let d = doc(vec![
            row(1, 1, "08:01", 4242, x_off), // unmapped
            row(1, 2, "08:01", 100, x_off),  // unreadable
            row(1, 3, "08:01", 99, eof_off), // past-eof
            row(1, 4, "08:01", 99, r_off),   // not-executable
        ]);
        let p = plan(&d, &live, &files, 0).unwrap();
        assert!(p.entries.is_empty());
        let reasons: Vec<&str> = p.missed.iter().map(|m| m.reason).collect();
        assert_eq!(
            reasons,
            vec!["unmapped", "unreadable", "past-eof", "not-executable"]
        );
    }

    #[test]
    fn plan_rejects_malformed_rows() {
        let live = vec![mapping("08:01", 99, "/lib/spike.so")];
        let files = HashMap::from([("/lib/spike.so".to_string(), self_bytes())]);
        assert!(plan(&serde_json::json!({}), &live, &files, 0).is_err());
        assert!(plan(&doc(vec![serde_json::json!({"op": 1})]), &live, &files, 0).is_err());
        let mut bad = row(1, 1, "08:01", 99, 0x1010);
        bad["op"] = serde_json::json!(u64::from(u32::MAX) + 1);
        assert!(plan(&doc(vec![bad]), &live, &files, 0).is_err());
    }

    /// Stub multi attach: EINVAL iff the slice holds a poison offset.
    fn poisoned(poison: Vec<u64>) -> impl Fn(&[(u64, u64)]) -> std::io::Result<()> {
        move |slice: &[(u64, u64)]| {
            if slice.iter().any(|(o, _)| poison.contains(o)) {
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn bisect_isolates_poison() {
        let sites: Vec<(u64, u64)> = (0..8u64).map(|i| (0x1000 + i * 8, i)).collect();
        let (links, bad) = bisect_attach(&poisoned(vec![0x1018, 0x1030]), &sites);
        assert_eq!(links.len(), 4);
        assert_eq!(bad, vec![3, 6]);
        let (links, bad) = bisect_attach(&poisoned(vec![]), &sites);
        assert_eq!(links.len(), 1);
        assert!(bad.is_empty());
    }

    #[test]
    fn stable_cookies_survive_replan() {
        let bytes = self_bytes();
        let (x_off, _) = probe_offsets(&bytes);
        let live = vec![mapping("08:01", 99, "/lib/spike.so")];
        let files = HashMap::from([("/lib/spike.so".to_string(), bytes)]);
        let mut stable = StableCookies::default();
        let p0 = plan_stable(
            &doc(vec![
                row(1, 7, "08:01", 99, x_off),
                row(1, 9, "08:01", 99, x_off + 0x40),
            ]),
            &live,
            &files,
            0,
            &mut stable,
        )
        .unwrap();
        assert_eq!((p0.entries[0].cookie, p0.entries[1].cookie), (0, 1));
        // Re-plan: one survivor (reordered), one fresh site.
        let p1 = plan_stable(
            &doc(vec![
                row(1, 9, "08:01", 99, x_off + 0x40),
                row(3, 1, "08:01", 99, x_off + 0x80),
            ]),
            &live,
            &files,
            1,
            &mut stable,
        )
        .unwrap();
        assert_eq!(p1.entries[0].cookie, 1); // survivor keeps 1
        assert_eq!(p1.entries[1].cookie, 2); // fresh mints 2
    }

    #[test]
    fn bisect_non_einval_fails_slice() {
        let sites: Vec<(u64, u64)> = (0..4u64).map(|i| (0x1000 + i * 8, i)).collect();
        let (links, bad) = bisect_attach::<()>(
            &|_| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
            &sites,
        );
        assert!(links.is_empty());
        assert_eq!(bad, vec![0, 1, 2, 3]);
    }
}
