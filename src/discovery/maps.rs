//! SPDX-License-Identifier: GPL-3.0-or-later
//! `/proc/pid/maps` parsing + provider-mapping lookup for the
//! relocation leg. Userspace never reads target memory — only maps.
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

/// Mapping of the provider file covering `addr` (exact, canonical, or
/// suffix path match — lanes bind-mount providers at odd prefixes).
pub fn provider_mapping<'a>(
    maps: &'a [Mapping],
    provider: &Path,
    canon: &str,
    addr: u64,
) -> Option<&'a Mapping> {
    let arg = provider.to_string_lossy();
    maps.iter().find(|m| {
        m.start <= addr
            && addr < m.end
            && (m.path == arg || m.path == canon || (!canon.is_empty() && m.path.ends_with(canon)))
    })
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

    #[test]
    fn mapping_lookup_by_suffix() {
        let m = parse_maps(SAMPLE);
        let hit = provider_mapping(
            &m,
            Path::new("provider.so"),
            "lib64/provider.so",
            0x7f2a2400,
        );
        assert!(hit.is_some() && hit.unwrap().x);
        assert!(provider_mapping(&m, Path::new("other.so"), "", 0x7f2a2400).is_none());
        assert!(provider_mapping(&m, Path::new("provider.so"), "", 0x1000).is_none());
    }
}
