//! SPDX-License-Identifier: GPL-3.0-or-later
//! `/proc/pid/maps` parsing + provider-mapping lookup for the
//! relocation leg. Userspace never reads target memory — only maps.
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// One parsed maps line ( path keeps the ` (deleted)`-style suffixes).
#[derive(Debug, Clone)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub x: bool,
    pub offset: u64,
    pub dev: String,
    pub ino: u64,
    pub path: String,
}

pub fn read_maps(pid: u32) -> anyhow::Result<Vec<Mapping>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    Ok(parse_maps(&text))
}

pub fn parse_maps(text: &str) -> Vec<Mapping> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (range, perms, off, dev, ino) = match (f.next(), f.next(), f.next(), f.next(), f.next())
        {
            (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
            _ => continue,
        };
        let (start, end) = match range.split_once('-') {
            Some((s, e)) => (
                u64::from_str_radix(s, 16).unwrap_or(0),
                u64::from_str_radix(e, 16).unwrap_or(0),
            ),
            None => continue,
        };
        if start == 0 && end == 0 {
            continue;
        }
        out.push(Mapping {
            start,
            end,
            x: perms.as_bytes().get(2) == Some(&b'x'),
            offset: u64::from_str_radix(off, 16).unwrap_or(0),
            dev: dev.to_string(),
            ino: ino.parse().unwrap_or(0),
            path: f.collect::<Vec<_>>().join(" "),
        });
    }
    out
}

/// Mapping of the provider file covering `addr`: same-file
/// (dev,ino) first (hardlink/symlink aliases share bytes+inode; the
/// path is only a locator), then exact, canonical, or suffix path
/// match (lanes bind-mount providers at odd prefixes).
pub fn provider_mapping<'a>(
    maps: &'a [Mapping],
    provider: &Path,
    _canon: &str,
    addr: u64,
) -> Option<&'a Mapping> {
    // Same-file ONLY (stat-or-None): stat the provider argument
    // (follows symlinks, so symlink/hardlink/bind aliases resolve
    // to the mapped file's identity). Any mapping of the same inode
    // covering `addr` is the provider file, whatever locator path
    // it was mapped under. The stat runs per call (not hoisted): a
    // provider path replaced mid-run resolves to the CURRENT file,
    // never a pinned stale identity. There is NO pathname fallback:
    // after a same-path replacement the old mapping still matches
    // by pathname but backs the WRONG bytes, and a deleted path's
    // unlinked mapping must fail closed (loud attach failure), never
    // misattribute (T14r4-2b). The match key is the INODE alone:
    // stat-dev and maps-text dev DIVERGE on overlayfs (measured
    // 00:33 vs 00:22 for one file — xino reporting), while the inode
    // is the same dentry both sides. Addr coverage makes cross-fs
    // ino collisions vanish (two filesystems' files mapped over one
    // address), and the epoch fingerprint keeps the maps-view dev
    // for maps-consistent turnover detection.
    let Ok(meta) = std::fs::metadata(provider) else {
        return None;
    };
    let ino = meta.ino();
    if ino == 0 {
        return None;
    }
    maps.iter()
        .find(|m| m.start <= addr && addr < m.end && m.ino == ino)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "7f2a1000-7f2a2000 r--p 00000000 08:01 1234 /opt/ossl/lib64/provider.so\n\
        7f2a2000-7f2a3000 r-xp 00001000 08:01 1234 /opt/ossl/lib64/provider.so\n\
        7f2a3000-7f2a4000 rw-p 00002000 08:01 1234 /opt/ossl/lib64/provider.so\n\
        malformed line without enough fields\n";

    #[test]
    fn parses_and_skips_malformed() {
        let m = parse_maps(SAMPLE);
        assert_eq!(m.len(), 3);
        assert!(!m[0].x && m[1].x && !m[2].x);
        assert_eq!(m[1].offset, 0x1000);
        assert_eq!(m[1].ino, 1234);
    }

    /// T14r4-2b pins: no pathname fallback. A same-path
    /// replacement (new inode, old mapping still matches by
    /// pathname) must NOT resolve to the stale bytes, and a deleted
    /// path must fail closed even though its unlinked mapping keeps
    /// the pathname. Identity is (dev,ino), never the locator.
    #[test]
    fn mapping_lookup_rejects_stale_pathname() {
        let dir = std::env::temp_dir().join(format!("osslscope-repl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("idprov.so");
        std::fs::write(&path, b"v1-bytes").unwrap();
        let meta1 = std::fs::metadata(&path).unwrap();
        let dev = format!(
            "{:02x}:{:02x}",
            libc::major(meta1.dev()),
            libc::minor(meta1.dev())
        );
        // Target mapped v1 under the module path.
        let text = format!(
            "7f2a2000-7f2a3000 r-xp 00000000 {} {} {}\\n",
            dev,
            meta1.ino(),
            path.display()
        );
        let m = parse_maps(&text);
        assert_eq!(m.len(), 1);
        // Sanity: v1 resolves while it is the current file.
        assert!(provider_mapping(&m, &path, "", 0x7f2a2400).is_some());
        // Replace the path with v2 bytes (new inode, same path).
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"v2-bytes-longer").unwrap();
        let meta2 = std::fs::metadata(&path).unwrap();
        assert_ne!(meta2.ino(), meta1.ino());
        // The old mapping still matches BY PATHNAME, but it backs
        // v1 bytes, not the current file: fail closed, never
        // misattribute the stale bytes as the new provider.
        assert!(provider_mapping(&m, &path, "", 0x7f2a2400).is_none());
        // Deleted path with the unlinked mapping still present:
        // fail closed (no pathname fallback to the ghost).
        std::fs::remove_file(&path).unwrap();
        assert!(provider_mapping(&m, &path, "", 0x7f2a2400).is_none());
        // Unrelated path and out-of-range address stay negative.
        assert!(provider_mapping(&m, Path::new("other.so"), "", 0x7f2a2400).is_none());
        std::fs::write(&path, b"v3").unwrap();
        assert!(provider_mapping(&m, &path, "", 0x1000).is_none());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap_or_default();
    }

    /// F-IDENT-1 pin: a hardlink alias (same inode, unrelated path)
    /// resolves by (dev,ino) even though no path arm matches; a
    /// same-named different file does not (its bytes differ); a
    /// deleted provider path fails closed instead of misattributing.
    #[test]
    fn mapping_lookup_by_same_file_identity() {
        let dir = std::env::temp_dir().join(format!("osslscope-ident-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let orig = dir.join("prov-v1.so");
        let alias = dir.join("modules").join("idprov.so");
        std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
        std::fs::write(&orig, b"fake-provider-bytes").unwrap();
        let _ = std::fs::remove_file(&alias);
        std::fs::hard_link(&orig, &alias).unwrap();
        let meta = std::fs::metadata(&orig).unwrap();
        let dev = format!(
            "{:02x}:{:02x}",
            libc::major(meta.dev()),
            libc::minor(meta.dev())
        );
        // Target mapped the file under the ALIAS path only.
        let text = format!(
            "7f2a2000-7f2a3000 r-xp 00000000 {} {} {}\n",
            dev,
            meta.ino(),
            alias.display()
        );
        let m = parse_maps(&text);
        assert_eq!(m.len(), 1);
        // Provider argument names the ORIGINAL path: the alias
        // mapping still resolves (same bytes+inode).
        let hit = provider_mapping(&m, &orig, "", 0x7f2a2400);
        assert!(hit.is_some(), "hardlink alias must resolve by (dev,ino)");
        // Same directory name, different bytes: must NOT resolve.
        let other = dir.join("prov-v2.so");
        std::fs::write(&other, b"different-bytes").unwrap();
        assert_ne!(std::fs::metadata(&other).unwrap().ino(), meta.ino());
        assert!(provider_mapping(&m, &other, "", 0x7f2a2400).is_none());
        // Deleted provider path: stat fails → None (no pathname
        // fallback) — fail closed, never misattribute.
        std::fs::remove_file(&orig).unwrap();
        std::fs::remove_file(&alias).unwrap();
        let ghost = dir.join("prov-v1.so");
        assert!(provider_mapping(&m, &ghost, "", 0x7f2a2400).is_none());
        std::fs::remove_file(&other).unwrap();
        std::fs::remove_dir_all(&dir).unwrap_or_default();
    }
}
