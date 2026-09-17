//! Live harvest driver: two-stage attach + ring drain + settle,
//! promoted behavior-identical from the P0-4 spike. The fixture-only
//! `evp_driver` cmdline guard is now a caller-supplied marker
//! (`None` = any target — what `inspect --pid` uses at P1 exit 1).
use crate::discovery::{elf, maps, schema};
use anyhow::{Context as _, anyhow, bail};
use aya::maps::RingBuf;
use aya::programs::UProbe;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};
use aya::{Ebpf, EbpfLoader};
use std::collections::HashSet;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const KIND_INIT_RET: u32 = 1;
const KIND_QUERY_RET: u32 = 2;
const KIND_ROW: u32 = 3;
const EVENT_LEN: usize = 96;

/// Load-mandated init anchor, present even in stripped modules.
const INIT_ANCHOR: &str = "OSSL_provider_init";

/// Harvest run configuration.
pub struct Config {
    pub pid: u32,
    pub provider: PathBuf,
    pub object: PathBuf,
    pub settle: Duration,
    pub timeout: Duration,
    /// Required cmdline marker (fixture guard), or None for any target.
    pub cmdline_marker: Option<String>,
}

fn attach_pair(
    bpf: &mut Ebpf,
    entry: &str,
    ret: &str,
    offset: u64,
    path: &Path,
    pid: NonZeroU32,
) -> anyhow::Result<()> {
    for name in [entry, ret] {
        let prog: &mut UProbe = bpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("missing program {name}"))?
            .try_into()?;
        prog.load().with_context(|| format!("load {name}"))?;
        let point = UProbeAttachPoint {
            location: UProbeAttachLocation::AbsoluteOffset(offset),
            cookie: None,
        };
        prog.attach(point, path, UProbeScope::OneProcess(pid))
            .map_err(|e| anyhow!("attach {name}@{offset:#x}: {e}"))?;
    }
    Ok(())
}

/// Run the harvest; returns the emitted document on success.
pub fn run(cfg: &Config) -> anyhow::Result<serde_json::Value> {
    let pid = NonZeroU32::new(cfg.pid).ok_or_else(|| anyhow!("pid must be non-zero"))?;
    if let Some(marker) = &cfg.cmdline_marker {
        let cmdline = std::fs::read(format!("/proc/{}/cmdline", cfg.pid))?;
        let m = marker.as_bytes();
        if !cmdline.windows(m.len()).any(|w| w == m) {
            bail!("pid {} cmdline lacks marker {marker}", cfg.pid);
        }
    }
    let elf_bytes = std::fs::read(&cfg.provider)?;
    let canon = std::fs::canonicalize(&cfg.provider)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let obj_bytes = std::fs::read(&cfg.object)?;

    let mut bpf = EbpfLoader::new().load(&obj_bytes)?;
    let init_off = elf::dynsym_file_offset(&elf_bytes, INIT_ANCHOR)?;
    attach_pair(
        &mut bpf,
        "init_entry",
        "init_return",
        init_off,
        &cfg.provider,
        pid,
    )?;

    let map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("no EVENTS map"))?;
    let mut ring = RingBuf::try_from(map)?;
    let start = Instant::now();
    let mut last_event = None;
    let mut trigger_observed = false;
    let mut query_attached = false;
    let mut rows: Vec<schema::Row> = Vec::new();
    // Identity includes addr: scaled tables cycle funcids, so the triple
    // alone collapses distinct dispatch entries (72 vs 504 observed).
    let mut seen: HashSet<(u32, String, u32, u64)> = HashSet::new();

    while start.elapsed() < cfg.timeout {
        let mut fresh = false;
        while let Some(item) = ring.next() {
            fresh = true;
            last_event = Some(Instant::now());
            let b: &[u8] = &item;
            if b.len() < EVENT_LEN {
                eprintln!("short event: {} bytes", b.len());
                continue;
            }
            let u32at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
            let u64at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
            match u32at(0) {
                KIND_INIT_RET => {
                    if query_attached {
                        continue;
                    }
                    let addr = u64at(16);
                    let live = maps::read_maps(cfg.pid)?;
                    let m = maps::provider_mapping(&live, &cfg.provider, &canon, addr)
                        .ok_or_else(|| anyhow!("query addr {addr:#x} outside provider mappings"))?;
                    let off = addr - m.start + m.offset;
                    attach_pair(
                        &mut bpf,
                        "query_entry",
                        "query_return",
                        off,
                        &cfg.provider,
                        pid,
                    )?;
                    query_attached = true;
                }
                KIND_QUERY_RET if u32at(8) == 0 => {
                    trigger_observed = true;
                }
                KIND_ROW => {
                    trigger_observed = true;
                    let name = &b[32..96];
                    let len = name.iter().position(|c| *c == 0).unwrap_or(name.len());
                    let alg = String::from_utf8_lossy(&name[..len]).into_owned();
                    let key = (u32at(4), alg.clone(), u32at(8), u64at(16));
                    if seen.insert(key) {
                        rows.push(schema::Row {
                            op: u32at(4),
                            alg,
                            funcid: u32at(8),
                            addr: u64at(16),
                        });
                    }
                }
                k => eprintln!("unknown event kind {k}"),
            }
        }
        if trigger_observed && !fresh {
            if let Some(t) = last_event {
                if t.elapsed() > cfg.settle {
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !trigger_observed {
        bail!("no query trigger observed before timeout");
    }

    let live = maps::read_maps(cfg.pid).unwrap_or_default();
    let provider_name = cfg
        .provider
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());
    schema::emit(
        &provider_name,
        &cfg.provider,
        &canon,
        &elf_bytes,
        &live,
        &rows,
        trigger_observed,
    )
}
