//! SPDX-License-Identifier: GPL-3.0-or-later
//! Raw multi loader for the frozen eBPF shape (P2).
//!
//! aya 0.14 loads uprobe progs with `expected_attach_type=0`, which
//! the kernel rejects for multi links — so the multi path parses the
//! object itself (goblin), creates maps raw, applies relocations,
//! and loads progs raw with `expected_attach_type=UPROBE_MULTI`.
//!
//! `prepare()` is pure (unit-tested on synthetic ELFs — no blobs,
//! no toolchain); `load()` needs caps. The lane gates load the real
//! object. Fail-closed throughout: any shape drift (BTF sections,
//! unknown relocs, dim mismatch, non-GPL license) is an error, and
//! map-fd fixups assert `BPF_PSEUDO_MAP_FD` at the site.
use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd as _, OwnedFd};

/// BPF relocation types (from `readelf -r` on the real object).
const R_BPF_64_64: u32 = 1;
const R_BPF_64_32: u32 = 10;
/// `ld_imm64` src reg the loader sets at a map-fd site (the
/// compiler emits src=0; anything else pre-patch is corruption).
const BPF_PSEUDO_MAP_FD: u8 = 1;
/// aya legacy map-def record size (7×u32; first 5 are dims).
const MAP_DEF_SIZE: usize = 28;
/// Kernel GPL-compatible license set (subset we accept).
const GPL_OK: [&str; 6] = [
    "GPL",
    "GPL v2",
    "GPL and additional rights",
    "Dual BSD/GPL",
    "Dual MIT/GPL",
    "Dual MPL/GPL",
];

/// Wanted map: dimensions frozen by spec, asserted vs the object.
#[derive(Debug, Clone, Copy)]
pub struct MapSpec {
    pub name: &'static str,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

/// Wanted program: looked up by symbol in its section.
#[derive(Debug, Clone, Copy)]
pub struct ProgSpec {
    pub name: &'static str,
    /// "uprobe" (entry) or "uretprobe" (return).
    pub section: &'static str,
}

impl ProgSpec {
    /// Entry-program spec (const so frozen tables stay `const`).
    pub const fn uprobe(name: &'static str) -> ProgSpec {
        ProgSpec {
            name,
            section: "uprobe",
        }
    }
    /// Return-program spec (const so frozen tables stay `const`).
    pub const fn uretprobe(name: &'static str) -> ProgSpec {
        ProgSpec {
            name,
            section: "uretprobe",
        }
    }
}

/// Frozen harvest shape (keyed-design §1): dims asserted vs the
/// object by `prepare`, fail-closed on drift. Proven by the P2
/// task-0 spike (spike-uret.sh GREEN 3/3). T02 adds the two
/// observer-populated classifier tables (`ALG_CLASS`, `TRIP_CLASS`):
/// same frozen discipline, same commit as the wire ABI change.
/// F-C/A8: the five counter/flag maps (`LOSS`, `TRUNC`, `CALLS`,
/// `TRIP`, `LGCALLS`) are per-CPU hash (type 5) — exact
/// single-writer slots replace racy shared read-modify-write.
/// P5a-C1 adds the chain jump table (`JUMPS`, prog-array); the
/// handoff rides `PENDING_QUERY` + `QUERY_NEXT` (no new state — a
/// dedicated `CURSOR` map was prototyped and rejected, see the BPF
/// notes: stash materialization vs the verifier meets the
/// no-tail-call-in-subprog kernel rule).
pub const HARVEST_MAPS: [MapSpec; 14] = [
    MapSpec {
        name: "EVENTS",
        map_type: 27,
        key_size: 0,
        value_size: 0,
        max_entries: 1 << 21,
        flags: 0,
    },
    MapSpec {
        name: "PENDING_INIT",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "PENDING_QUERY",
        map_type: 1,
        key_size: 8,
        value_size: 16,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "TERMD",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "GEN",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "LOSS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 32,
        flags: 0,
    },
    MapSpec {
        name: "QUERY_NEXT",
        map_type: 1,
        key_size: 16,
        value_size: 8,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "TRUNC",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "CALLS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "TRIP",
        map_type: 5,
        key_size: 8,
        value_size: 8,
        max_entries: 128,
        flags: 0,
    },
    MapSpec {
        name: "LGCALLS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "ALG_CLASS",
        map_type: 1,
        key_size: 8,
        value_size: 42,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "TRIP_CLASS",
        map_type: 1,
        key_size: 8,
        value_size: 22,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "JUMPS",
        map_type: 3,
        key_size: 4,
        value_size: 4,
        max_entries: 8,
        flags: 0,
    },
];

/// Frozen capture shape (keyed-design §2): dims asserted vs the
/// object by `prepare`, fail-closed on drift. Read off the built
/// `osslscope-count` object (maps-section records). T07 count ABI
/// v2 adds `WINDOW` (2 u64 cells: start/deadline); an object without
/// it fails `prepare` rather than running deadline-blind.
pub const COUNT_MAPS: [MapSpec; 5] = [
    MapSpec {
        name: "COUNTS",
        map_type: 5,
        key_size: 8,
        value_size: 24,
        max_entries: 8192,
        flags: 0,
    },
    MapSpec {
        name: "GEN",
        map_type: 2,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "TARGET",
        map_type: 2,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "WINDOW",
        map_type: 2,
        key_size: 4,
        value_size: 8,
        max_entries: 2,
        flags: 0,
    },
    MapSpec {
        name: "DROPFAIL",
        map_type: 6,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
];

/// Frozen capture programs: entry-only counting (v1).
pub const COUNT_PROGS: [ProgSpec; 1] = [ProgSpec {
    name: "count_entry",
    section: "uprobe",
}];

/// Frozen harvest programs: the init/query entry+return pairs plus
/// the three entry-only tripwire counters. P5a adds the eight chain
/// hops (`c0..c7` — loaded, never directly attached: the only attach
/// call sites name entry/return pairs explicitly, and hop `i` is
/// reachable solely via `JUMPS[i]`).
pub const HARVEST_PROGS: [ProgSpec; 15] = [
    ProgSpec {
        name: "init_entry",
        section: "uprobe",
    },
    ProgSpec {
        name: "init_return",
        section: "uretprobe",
    },
    ProgSpec {
        name: "query_entry",
        section: "uprobe",
    },
    ProgSpec {
        name: "query_return",
        section: "uretprobe",
    },
    ProgSpec {
        name: "trip_count",
        section: "uprobe",
    },
    ProgSpec {
        name: "trip_str0",
        section: "uprobe",
    },
    ProgSpec {
        name: "trip_str1",
        section: "uprobe",
    },
    ProgSpec {
        name: "c0",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c1",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c2",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c3",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c4",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c5",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c6",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c7",
        section: "uretprobe",
    },
];

/// Frozen member shape (P7 items 3–5): dims asserted vs
/// `osslscope-members` by `prepare`, fail-closed on drift. The
/// first 6 mirror harvest dims; TERMD/LGCALLS/QUERY_NEXT are
/// deliberately absent (single-site CALLS only, no cursor — every
/// scan is full; termination proof is the item-4 join's job). The
/// scan plane (SCAN/SEQ/BIRTH/RCOUNT/T_CACHE/CTRL/ATTEMPT)
/// arrives with item 3; members.o dropped its PENDING_QUERY
/// scaffold in stage D when members switched to SCAN (R18 §6.1;
/// the harvest path's cursor maps retire in item 9). Item 5 adds
/// the tier-1 BUCKET map; item 7 grows EVENTS to 16MiB.
pub const MEMBER_MAPS: [MapSpec; 14] = [
    MapSpec {
        name: "EVENTS",
        map_type: 27,
        key_size: 0,
        value_size: 0,
        max_entries: 1 << 24,
        flags: 0,
    },
    MapSpec {
        name: "BUCKET",
        map_type: 1,
        key_size: 4,
        value_size: 8,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "GEN",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "LOSS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 32,
        flags: 0,
    },
    MapSpec {
        name: "TRUNC",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "CALLS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "ALG_CLASS",
        map_type: 1,
        key_size: 8,
        value_size: 42,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "SCAN",
        map_type: 9,
        key_size: 4,
        value_size: 40,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "SEQ",
        map_type: 1,
        key_size: 4,
        value_size: 8,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "BIRTH",
        map_type: 1,
        key_size: 4,
        value_size: 2,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "RCOUNT",
        map_type: 1,
        key_size: 4,
        value_size: 8,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "T_CACHE",
        map_type: 1,
        key_size: 8,
        value_size: 16,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "CTRL",
        map_type: 2,
        key_size: 4,
        value_size: 24,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "ATTEMPT",
        map_type: 6,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
];

/// Frozen member programs: `member_entry` (uprobe stash) + 512
/// baked-slot members (`member_000..member_511`, uretprobe). One
/// line per member via the const constructors (struct literals
/// would fmt-expand to 4 lines each), generated once and committed
/// explicitly — the frozen `HARVEST_PROGS` discipline (dynamic
/// names stay test-only per the B-chunk probe's comment).
/// `prepare` fails closed on any name/symbol drift.
#[allow(
    clippy::large_const_arrays,
    reason = "the 513 frozen specs are the point"
)]
pub const MEMBER_PROGS: [ProgSpec; 513] = [
    ProgSpec::uprobe("member_entry"),
    ProgSpec::uretprobe("member_000"),
    ProgSpec::uretprobe("member_001"),
    ProgSpec::uretprobe("member_002"),
    ProgSpec::uretprobe("member_003"),
    ProgSpec::uretprobe("member_004"),
    ProgSpec::uretprobe("member_005"),
    ProgSpec::uretprobe("member_006"),
    ProgSpec::uretprobe("member_007"),
    ProgSpec::uretprobe("member_008"),
    ProgSpec::uretprobe("member_009"),
    ProgSpec::uretprobe("member_010"),
    ProgSpec::uretprobe("member_011"),
    ProgSpec::uretprobe("member_012"),
    ProgSpec::uretprobe("member_013"),
    ProgSpec::uretprobe("member_014"),
    ProgSpec::uretprobe("member_015"),
    ProgSpec::uretprobe("member_016"),
    ProgSpec::uretprobe("member_017"),
    ProgSpec::uretprobe("member_018"),
    ProgSpec::uretprobe("member_019"),
    ProgSpec::uretprobe("member_020"),
    ProgSpec::uretprobe("member_021"),
    ProgSpec::uretprobe("member_022"),
    ProgSpec::uretprobe("member_023"),
    ProgSpec::uretprobe("member_024"),
    ProgSpec::uretprobe("member_025"),
    ProgSpec::uretprobe("member_026"),
    ProgSpec::uretprobe("member_027"),
    ProgSpec::uretprobe("member_028"),
    ProgSpec::uretprobe("member_029"),
    ProgSpec::uretprobe("member_030"),
    ProgSpec::uretprobe("member_031"),
    ProgSpec::uretprobe("member_032"),
    ProgSpec::uretprobe("member_033"),
    ProgSpec::uretprobe("member_034"),
    ProgSpec::uretprobe("member_035"),
    ProgSpec::uretprobe("member_036"),
    ProgSpec::uretprobe("member_037"),
    ProgSpec::uretprobe("member_038"),
    ProgSpec::uretprobe("member_039"),
    ProgSpec::uretprobe("member_040"),
    ProgSpec::uretprobe("member_041"),
    ProgSpec::uretprobe("member_042"),
    ProgSpec::uretprobe("member_043"),
    ProgSpec::uretprobe("member_044"),
    ProgSpec::uretprobe("member_045"),
    ProgSpec::uretprobe("member_046"),
    ProgSpec::uretprobe("member_047"),
    ProgSpec::uretprobe("member_048"),
    ProgSpec::uretprobe("member_049"),
    ProgSpec::uretprobe("member_050"),
    ProgSpec::uretprobe("member_051"),
    ProgSpec::uretprobe("member_052"),
    ProgSpec::uretprobe("member_053"),
    ProgSpec::uretprobe("member_054"),
    ProgSpec::uretprobe("member_055"),
    ProgSpec::uretprobe("member_056"),
    ProgSpec::uretprobe("member_057"),
    ProgSpec::uretprobe("member_058"),
    ProgSpec::uretprobe("member_059"),
    ProgSpec::uretprobe("member_060"),
    ProgSpec::uretprobe("member_061"),
    ProgSpec::uretprobe("member_062"),
    ProgSpec::uretprobe("member_063"),
    ProgSpec::uretprobe("member_064"),
    ProgSpec::uretprobe("member_065"),
    ProgSpec::uretprobe("member_066"),
    ProgSpec::uretprobe("member_067"),
    ProgSpec::uretprobe("member_068"),
    ProgSpec::uretprobe("member_069"),
    ProgSpec::uretprobe("member_070"),
    ProgSpec::uretprobe("member_071"),
    ProgSpec::uretprobe("member_072"),
    ProgSpec::uretprobe("member_073"),
    ProgSpec::uretprobe("member_074"),
    ProgSpec::uretprobe("member_075"),
    ProgSpec::uretprobe("member_076"),
    ProgSpec::uretprobe("member_077"),
    ProgSpec::uretprobe("member_078"),
    ProgSpec::uretprobe("member_079"),
    ProgSpec::uretprobe("member_080"),
    ProgSpec::uretprobe("member_081"),
    ProgSpec::uretprobe("member_082"),
    ProgSpec::uretprobe("member_083"),
    ProgSpec::uretprobe("member_084"),
    ProgSpec::uretprobe("member_085"),
    ProgSpec::uretprobe("member_086"),
    ProgSpec::uretprobe("member_087"),
    ProgSpec::uretprobe("member_088"),
    ProgSpec::uretprobe("member_089"),
    ProgSpec::uretprobe("member_090"),
    ProgSpec::uretprobe("member_091"),
    ProgSpec::uretprobe("member_092"),
    ProgSpec::uretprobe("member_093"),
    ProgSpec::uretprobe("member_094"),
    ProgSpec::uretprobe("member_095"),
    ProgSpec::uretprobe("member_096"),
    ProgSpec::uretprobe("member_097"),
    ProgSpec::uretprobe("member_098"),
    ProgSpec::uretprobe("member_099"),
    ProgSpec::uretprobe("member_100"),
    ProgSpec::uretprobe("member_101"),
    ProgSpec::uretprobe("member_102"),
    ProgSpec::uretprobe("member_103"),
    ProgSpec::uretprobe("member_104"),
    ProgSpec::uretprobe("member_105"),
    ProgSpec::uretprobe("member_106"),
    ProgSpec::uretprobe("member_107"),
    ProgSpec::uretprobe("member_108"),
    ProgSpec::uretprobe("member_109"),
    ProgSpec::uretprobe("member_110"),
    ProgSpec::uretprobe("member_111"),
    ProgSpec::uretprobe("member_112"),
    ProgSpec::uretprobe("member_113"),
    ProgSpec::uretprobe("member_114"),
    ProgSpec::uretprobe("member_115"),
    ProgSpec::uretprobe("member_116"),
    ProgSpec::uretprobe("member_117"),
    ProgSpec::uretprobe("member_118"),
    ProgSpec::uretprobe("member_119"),
    ProgSpec::uretprobe("member_120"),
    ProgSpec::uretprobe("member_121"),
    ProgSpec::uretprobe("member_122"),
    ProgSpec::uretprobe("member_123"),
    ProgSpec::uretprobe("member_124"),
    ProgSpec::uretprobe("member_125"),
    ProgSpec::uretprobe("member_126"),
    ProgSpec::uretprobe("member_127"),
    ProgSpec::uretprobe("member_128"),
    ProgSpec::uretprobe("member_129"),
    ProgSpec::uretprobe("member_130"),
    ProgSpec::uretprobe("member_131"),
    ProgSpec::uretprobe("member_132"),
    ProgSpec::uretprobe("member_133"),
    ProgSpec::uretprobe("member_134"),
    ProgSpec::uretprobe("member_135"),
    ProgSpec::uretprobe("member_136"),
    ProgSpec::uretprobe("member_137"),
    ProgSpec::uretprobe("member_138"),
    ProgSpec::uretprobe("member_139"),
    ProgSpec::uretprobe("member_140"),
    ProgSpec::uretprobe("member_141"),
    ProgSpec::uretprobe("member_142"),
    ProgSpec::uretprobe("member_143"),
    ProgSpec::uretprobe("member_144"),
    ProgSpec::uretprobe("member_145"),
    ProgSpec::uretprobe("member_146"),
    ProgSpec::uretprobe("member_147"),
    ProgSpec::uretprobe("member_148"),
    ProgSpec::uretprobe("member_149"),
    ProgSpec::uretprobe("member_150"),
    ProgSpec::uretprobe("member_151"),
    ProgSpec::uretprobe("member_152"),
    ProgSpec::uretprobe("member_153"),
    ProgSpec::uretprobe("member_154"),
    ProgSpec::uretprobe("member_155"),
    ProgSpec::uretprobe("member_156"),
    ProgSpec::uretprobe("member_157"),
    ProgSpec::uretprobe("member_158"),
    ProgSpec::uretprobe("member_159"),
    ProgSpec::uretprobe("member_160"),
    ProgSpec::uretprobe("member_161"),
    ProgSpec::uretprobe("member_162"),
    ProgSpec::uretprobe("member_163"),
    ProgSpec::uretprobe("member_164"),
    ProgSpec::uretprobe("member_165"),
    ProgSpec::uretprobe("member_166"),
    ProgSpec::uretprobe("member_167"),
    ProgSpec::uretprobe("member_168"),
    ProgSpec::uretprobe("member_169"),
    ProgSpec::uretprobe("member_170"),
    ProgSpec::uretprobe("member_171"),
    ProgSpec::uretprobe("member_172"),
    ProgSpec::uretprobe("member_173"),
    ProgSpec::uretprobe("member_174"),
    ProgSpec::uretprobe("member_175"),
    ProgSpec::uretprobe("member_176"),
    ProgSpec::uretprobe("member_177"),
    ProgSpec::uretprobe("member_178"),
    ProgSpec::uretprobe("member_179"),
    ProgSpec::uretprobe("member_180"),
    ProgSpec::uretprobe("member_181"),
    ProgSpec::uretprobe("member_182"),
    ProgSpec::uretprobe("member_183"),
    ProgSpec::uretprobe("member_184"),
    ProgSpec::uretprobe("member_185"),
    ProgSpec::uretprobe("member_186"),
    ProgSpec::uretprobe("member_187"),
    ProgSpec::uretprobe("member_188"),
    ProgSpec::uretprobe("member_189"),
    ProgSpec::uretprobe("member_190"),
    ProgSpec::uretprobe("member_191"),
    ProgSpec::uretprobe("member_192"),
    ProgSpec::uretprobe("member_193"),
    ProgSpec::uretprobe("member_194"),
    ProgSpec::uretprobe("member_195"),
    ProgSpec::uretprobe("member_196"),
    ProgSpec::uretprobe("member_197"),
    ProgSpec::uretprobe("member_198"),
    ProgSpec::uretprobe("member_199"),
    ProgSpec::uretprobe("member_200"),
    ProgSpec::uretprobe("member_201"),
    ProgSpec::uretprobe("member_202"),
    ProgSpec::uretprobe("member_203"),
    ProgSpec::uretprobe("member_204"),
    ProgSpec::uretprobe("member_205"),
    ProgSpec::uretprobe("member_206"),
    ProgSpec::uretprobe("member_207"),
    ProgSpec::uretprobe("member_208"),
    ProgSpec::uretprobe("member_209"),
    ProgSpec::uretprobe("member_210"),
    ProgSpec::uretprobe("member_211"),
    ProgSpec::uretprobe("member_212"),
    ProgSpec::uretprobe("member_213"),
    ProgSpec::uretprobe("member_214"),
    ProgSpec::uretprobe("member_215"),
    ProgSpec::uretprobe("member_216"),
    ProgSpec::uretprobe("member_217"),
    ProgSpec::uretprobe("member_218"),
    ProgSpec::uretprobe("member_219"),
    ProgSpec::uretprobe("member_220"),
    ProgSpec::uretprobe("member_221"),
    ProgSpec::uretprobe("member_222"),
    ProgSpec::uretprobe("member_223"),
    ProgSpec::uretprobe("member_224"),
    ProgSpec::uretprobe("member_225"),
    ProgSpec::uretprobe("member_226"),
    ProgSpec::uretprobe("member_227"),
    ProgSpec::uretprobe("member_228"),
    ProgSpec::uretprobe("member_229"),
    ProgSpec::uretprobe("member_230"),
    ProgSpec::uretprobe("member_231"),
    ProgSpec::uretprobe("member_232"),
    ProgSpec::uretprobe("member_233"),
    ProgSpec::uretprobe("member_234"),
    ProgSpec::uretprobe("member_235"),
    ProgSpec::uretprobe("member_236"),
    ProgSpec::uretprobe("member_237"),
    ProgSpec::uretprobe("member_238"),
    ProgSpec::uretprobe("member_239"),
    ProgSpec::uretprobe("member_240"),
    ProgSpec::uretprobe("member_241"),
    ProgSpec::uretprobe("member_242"),
    ProgSpec::uretprobe("member_243"),
    ProgSpec::uretprobe("member_244"),
    ProgSpec::uretprobe("member_245"),
    ProgSpec::uretprobe("member_246"),
    ProgSpec::uretprobe("member_247"),
    ProgSpec::uretprobe("member_248"),
    ProgSpec::uretprobe("member_249"),
    ProgSpec::uretprobe("member_250"),
    ProgSpec::uretprobe("member_251"),
    ProgSpec::uretprobe("member_252"),
    ProgSpec::uretprobe("member_253"),
    ProgSpec::uretprobe("member_254"),
    ProgSpec::uretprobe("member_255"),
    ProgSpec::uretprobe("member_256"),
    ProgSpec::uretprobe("member_257"),
    ProgSpec::uretprobe("member_258"),
    ProgSpec::uretprobe("member_259"),
    ProgSpec::uretprobe("member_260"),
    ProgSpec::uretprobe("member_261"),
    ProgSpec::uretprobe("member_262"),
    ProgSpec::uretprobe("member_263"),
    ProgSpec::uretprobe("member_264"),
    ProgSpec::uretprobe("member_265"),
    ProgSpec::uretprobe("member_266"),
    ProgSpec::uretprobe("member_267"),
    ProgSpec::uretprobe("member_268"),
    ProgSpec::uretprobe("member_269"),
    ProgSpec::uretprobe("member_270"),
    ProgSpec::uretprobe("member_271"),
    ProgSpec::uretprobe("member_272"),
    ProgSpec::uretprobe("member_273"),
    ProgSpec::uretprobe("member_274"),
    ProgSpec::uretprobe("member_275"),
    ProgSpec::uretprobe("member_276"),
    ProgSpec::uretprobe("member_277"),
    ProgSpec::uretprobe("member_278"),
    ProgSpec::uretprobe("member_279"),
    ProgSpec::uretprobe("member_280"),
    ProgSpec::uretprobe("member_281"),
    ProgSpec::uretprobe("member_282"),
    ProgSpec::uretprobe("member_283"),
    ProgSpec::uretprobe("member_284"),
    ProgSpec::uretprobe("member_285"),
    ProgSpec::uretprobe("member_286"),
    ProgSpec::uretprobe("member_287"),
    ProgSpec::uretprobe("member_288"),
    ProgSpec::uretprobe("member_289"),
    ProgSpec::uretprobe("member_290"),
    ProgSpec::uretprobe("member_291"),
    ProgSpec::uretprobe("member_292"),
    ProgSpec::uretprobe("member_293"),
    ProgSpec::uretprobe("member_294"),
    ProgSpec::uretprobe("member_295"),
    ProgSpec::uretprobe("member_296"),
    ProgSpec::uretprobe("member_297"),
    ProgSpec::uretprobe("member_298"),
    ProgSpec::uretprobe("member_299"),
    ProgSpec::uretprobe("member_300"),
    ProgSpec::uretprobe("member_301"),
    ProgSpec::uretprobe("member_302"),
    ProgSpec::uretprobe("member_303"),
    ProgSpec::uretprobe("member_304"),
    ProgSpec::uretprobe("member_305"),
    ProgSpec::uretprobe("member_306"),
    ProgSpec::uretprobe("member_307"),
    ProgSpec::uretprobe("member_308"),
    ProgSpec::uretprobe("member_309"),
    ProgSpec::uretprobe("member_310"),
    ProgSpec::uretprobe("member_311"),
    ProgSpec::uretprobe("member_312"),
    ProgSpec::uretprobe("member_313"),
    ProgSpec::uretprobe("member_314"),
    ProgSpec::uretprobe("member_315"),
    ProgSpec::uretprobe("member_316"),
    ProgSpec::uretprobe("member_317"),
    ProgSpec::uretprobe("member_318"),
    ProgSpec::uretprobe("member_319"),
    ProgSpec::uretprobe("member_320"),
    ProgSpec::uretprobe("member_321"),
    ProgSpec::uretprobe("member_322"),
    ProgSpec::uretprobe("member_323"),
    ProgSpec::uretprobe("member_324"),
    ProgSpec::uretprobe("member_325"),
    ProgSpec::uretprobe("member_326"),
    ProgSpec::uretprobe("member_327"),
    ProgSpec::uretprobe("member_328"),
    ProgSpec::uretprobe("member_329"),
    ProgSpec::uretprobe("member_330"),
    ProgSpec::uretprobe("member_331"),
    ProgSpec::uretprobe("member_332"),
    ProgSpec::uretprobe("member_333"),
    ProgSpec::uretprobe("member_334"),
    ProgSpec::uretprobe("member_335"),
    ProgSpec::uretprobe("member_336"),
    ProgSpec::uretprobe("member_337"),
    ProgSpec::uretprobe("member_338"),
    ProgSpec::uretprobe("member_339"),
    ProgSpec::uretprobe("member_340"),
    ProgSpec::uretprobe("member_341"),
    ProgSpec::uretprobe("member_342"),
    ProgSpec::uretprobe("member_343"),
    ProgSpec::uretprobe("member_344"),
    ProgSpec::uretprobe("member_345"),
    ProgSpec::uretprobe("member_346"),
    ProgSpec::uretprobe("member_347"),
    ProgSpec::uretprobe("member_348"),
    ProgSpec::uretprobe("member_349"),
    ProgSpec::uretprobe("member_350"),
    ProgSpec::uretprobe("member_351"),
    ProgSpec::uretprobe("member_352"),
    ProgSpec::uretprobe("member_353"),
    ProgSpec::uretprobe("member_354"),
    ProgSpec::uretprobe("member_355"),
    ProgSpec::uretprobe("member_356"),
    ProgSpec::uretprobe("member_357"),
    ProgSpec::uretprobe("member_358"),
    ProgSpec::uretprobe("member_359"),
    ProgSpec::uretprobe("member_360"),
    ProgSpec::uretprobe("member_361"),
    ProgSpec::uretprobe("member_362"),
    ProgSpec::uretprobe("member_363"),
    ProgSpec::uretprobe("member_364"),
    ProgSpec::uretprobe("member_365"),
    ProgSpec::uretprobe("member_366"),
    ProgSpec::uretprobe("member_367"),
    ProgSpec::uretprobe("member_368"),
    ProgSpec::uretprobe("member_369"),
    ProgSpec::uretprobe("member_370"),
    ProgSpec::uretprobe("member_371"),
    ProgSpec::uretprobe("member_372"),
    ProgSpec::uretprobe("member_373"),
    ProgSpec::uretprobe("member_374"),
    ProgSpec::uretprobe("member_375"),
    ProgSpec::uretprobe("member_376"),
    ProgSpec::uretprobe("member_377"),
    ProgSpec::uretprobe("member_378"),
    ProgSpec::uretprobe("member_379"),
    ProgSpec::uretprobe("member_380"),
    ProgSpec::uretprobe("member_381"),
    ProgSpec::uretprobe("member_382"),
    ProgSpec::uretprobe("member_383"),
    ProgSpec::uretprobe("member_384"),
    ProgSpec::uretprobe("member_385"),
    ProgSpec::uretprobe("member_386"),
    ProgSpec::uretprobe("member_387"),
    ProgSpec::uretprobe("member_388"),
    ProgSpec::uretprobe("member_389"),
    ProgSpec::uretprobe("member_390"),
    ProgSpec::uretprobe("member_391"),
    ProgSpec::uretprobe("member_392"),
    ProgSpec::uretprobe("member_393"),
    ProgSpec::uretprobe("member_394"),
    ProgSpec::uretprobe("member_395"),
    ProgSpec::uretprobe("member_396"),
    ProgSpec::uretprobe("member_397"),
    ProgSpec::uretprobe("member_398"),
    ProgSpec::uretprobe("member_399"),
    ProgSpec::uretprobe("member_400"),
    ProgSpec::uretprobe("member_401"),
    ProgSpec::uretprobe("member_402"),
    ProgSpec::uretprobe("member_403"),
    ProgSpec::uretprobe("member_404"),
    ProgSpec::uretprobe("member_405"),
    ProgSpec::uretprobe("member_406"),
    ProgSpec::uretprobe("member_407"),
    ProgSpec::uretprobe("member_408"),
    ProgSpec::uretprobe("member_409"),
    ProgSpec::uretprobe("member_410"),
    ProgSpec::uretprobe("member_411"),
    ProgSpec::uretprobe("member_412"),
    ProgSpec::uretprobe("member_413"),
    ProgSpec::uretprobe("member_414"),
    ProgSpec::uretprobe("member_415"),
    ProgSpec::uretprobe("member_416"),
    ProgSpec::uretprobe("member_417"),
    ProgSpec::uretprobe("member_418"),
    ProgSpec::uretprobe("member_419"),
    ProgSpec::uretprobe("member_420"),
    ProgSpec::uretprobe("member_421"),
    ProgSpec::uretprobe("member_422"),
    ProgSpec::uretprobe("member_423"),
    ProgSpec::uretprobe("member_424"),
    ProgSpec::uretprobe("member_425"),
    ProgSpec::uretprobe("member_426"),
    ProgSpec::uretprobe("member_427"),
    ProgSpec::uretprobe("member_428"),
    ProgSpec::uretprobe("member_429"),
    ProgSpec::uretprobe("member_430"),
    ProgSpec::uretprobe("member_431"),
    ProgSpec::uretprobe("member_432"),
    ProgSpec::uretprobe("member_433"),
    ProgSpec::uretprobe("member_434"),
    ProgSpec::uretprobe("member_435"),
    ProgSpec::uretprobe("member_436"),
    ProgSpec::uretprobe("member_437"),
    ProgSpec::uretprobe("member_438"),
    ProgSpec::uretprobe("member_439"),
    ProgSpec::uretprobe("member_440"),
    ProgSpec::uretprobe("member_441"),
    ProgSpec::uretprobe("member_442"),
    ProgSpec::uretprobe("member_443"),
    ProgSpec::uretprobe("member_444"),
    ProgSpec::uretprobe("member_445"),
    ProgSpec::uretprobe("member_446"),
    ProgSpec::uretprobe("member_447"),
    ProgSpec::uretprobe("member_448"),
    ProgSpec::uretprobe("member_449"),
    ProgSpec::uretprobe("member_450"),
    ProgSpec::uretprobe("member_451"),
    ProgSpec::uretprobe("member_452"),
    ProgSpec::uretprobe("member_453"),
    ProgSpec::uretprobe("member_454"),
    ProgSpec::uretprobe("member_455"),
    ProgSpec::uretprobe("member_456"),
    ProgSpec::uretprobe("member_457"),
    ProgSpec::uretprobe("member_458"),
    ProgSpec::uretprobe("member_459"),
    ProgSpec::uretprobe("member_460"),
    ProgSpec::uretprobe("member_461"),
    ProgSpec::uretprobe("member_462"),
    ProgSpec::uretprobe("member_463"),
    ProgSpec::uretprobe("member_464"),
    ProgSpec::uretprobe("member_465"),
    ProgSpec::uretprobe("member_466"),
    ProgSpec::uretprobe("member_467"),
    ProgSpec::uretprobe("member_468"),
    ProgSpec::uretprobe("member_469"),
    ProgSpec::uretprobe("member_470"),
    ProgSpec::uretprobe("member_471"),
    ProgSpec::uretprobe("member_472"),
    ProgSpec::uretprobe("member_473"),
    ProgSpec::uretprobe("member_474"),
    ProgSpec::uretprobe("member_475"),
    ProgSpec::uretprobe("member_476"),
    ProgSpec::uretprobe("member_477"),
    ProgSpec::uretprobe("member_478"),
    ProgSpec::uretprobe("member_479"),
    ProgSpec::uretprobe("member_480"),
    ProgSpec::uretprobe("member_481"),
    ProgSpec::uretprobe("member_482"),
    ProgSpec::uretprobe("member_483"),
    ProgSpec::uretprobe("member_484"),
    ProgSpec::uretprobe("member_485"),
    ProgSpec::uretprobe("member_486"),
    ProgSpec::uretprobe("member_487"),
    ProgSpec::uretprobe("member_488"),
    ProgSpec::uretprobe("member_489"),
    ProgSpec::uretprobe("member_490"),
    ProgSpec::uretprobe("member_491"),
    ProgSpec::uretprobe("member_492"),
    ProgSpec::uretprobe("member_493"),
    ProgSpec::uretprobe("member_494"),
    ProgSpec::uretprobe("member_495"),
    ProgSpec::uretprobe("member_496"),
    ProgSpec::uretprobe("member_497"),
    ProgSpec::uretprobe("member_498"),
    ProgSpec::uretprobe("member_499"),
    ProgSpec::uretprobe("member_500"),
    ProgSpec::uretprobe("member_501"),
    ProgSpec::uretprobe("member_502"),
    ProgSpec::uretprobe("member_503"),
    ProgSpec::uretprobe("member_504"),
    ProgSpec::uretprobe("member_505"),
    ProgSpec::uretprobe("member_506"),
    ProgSpec::uretprobe("member_507"),
    ProgSpec::uretprobe("member_508"),
    ProgSpec::uretprobe("member_509"),
    ProgSpec::uretprobe("member_510"),
    ProgSpec::uretprobe("member_511"),
];

/// A map-fd fixup site: byte offset of the insn + map name.
pub struct MapFixup {
    pub insn_off: usize,
    pub map: String,
}

/// One prepared program: relocated bytes (`.text` appended, call
/// relocs applied) + map fixups for `load()`.
pub struct PreparedProg {
    pub name: String,
    pub is_return: bool,
    pub insns: Vec<u8>,
    pub map_fixups: Vec<MapFixup>,
    /// Linked subprograms in insn order (main first): the BTF
    /// synthesis input. Callbacks (function-pointer targets) are
    /// flagged — only progs with a callback take the BTF path in
    /// `load()`; every other prog loads exactly as before.
    pub subprogs: Vec<SubprogInfo>,
}

/// Pure preparation output (no fds — safe unprivileged).
pub struct Prepared {
    pub progs: Vec<PreparedProg>,
    pub maps: Vec<MapSpecLite>,
}

/// Map dims confirmed against the object (load input).
pub struct MapSpecLite {
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

/// Loaded fds (needs caps).
pub struct Loaded {
    pub progs: HashMap<String, OwnedFd>,
    pub maps: HashMap<String, OwnedFd>,
}

struct Sym {
    name: String,
    value: usize,
    size: usize,
    shndx: usize,
    is_func: bool,
    is_obj: bool,
    is_section: bool,
}

struct Reloc {
    off: usize,
    typ: u32,
    sym: usize,
}

fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[0..4].try_into().unwrap())
}

fn sec_bytes<'a>(
    elf: &goblin::elf::Elf<'a>,
    obj: &'a [u8],
    want: &str,
) -> anyhow::Result<&'a [u8]> {
    for s in &elf.section_headers {
        if &elf.shdr_strtab[s.sh_name] == want {
            let o = s.sh_offset as usize;
            let n = s.sh_size as usize;
            return obj
                .get(o..o + n)
                .ok_or_else(|| anyhow::anyhow!("section {want} out of bounds"));
        }
    }
    anyhow::bail!("section {want} missing")
}

fn sec_bytes_opt<'a>(elf: &goblin::elf::Elf<'a>, obj: &'a [u8], want: &str) -> Option<&'a [u8]> {
    sec_bytes(elf, obj, want).ok()
}

fn parse_syms(elf: &goblin::elf::Elf) -> Vec<Sym> {
    let mut out = Vec::new();
    for s in elf.syms.iter() {
        let ty = s.st_type();
        // Section symbols name via shstrtab, not strtab.
        let name = if ty == goblin::elf::sym::STT_SECTION {
            elf.section_headers
                .get(s.st_shndx)
                .map(|h| elf.shdr_strtab[h.sh_name].to_string())
                .unwrap_or_default()
        } else {
            elf.strtab.get_at(s.st_name).unwrap_or("").to_string()
        };
        out.push(Sym {
            name,
            value: s.st_value as usize,
            size: s.st_size as usize,
            shndx: s.st_shndx,
            is_func: ty == goblin::elf::sym::STT_FUNC,
            is_obj: ty == goblin::elf::sym::STT_OBJECT,
            is_section: ty == goblin::elf::sym::STT_SECTION,
        });
    }
    out
}

/// Parse a REL section (16B entries: r_offset, r_info).
fn parse_relocs(bytes: &[u8], sec: &str) -> anyhow::Result<Vec<Reloc>> {
    if bytes.len() % 16 != 0 {
        anyhow::bail!("rel section {sec}: bad size {}", bytes.len());
    }
    let mut out = Vec::new();
    for e in bytes.chunks_exact(16) {
        let off = u64::from_le_bytes(e[0..8].try_into().unwrap()) as usize;
        let info = u64::from_le_bytes(e[8..16].try_into().unwrap());
        out.push(Reloc {
            off,
            typ: (info & 0xffff_ffff) as u32,
            sym: (info >> 32) as usize,
        });
    }
    Ok(out)
}

fn sec_index(elf: &goblin::elf::Elf, want: &str) -> anyhow::Result<usize> {
    for (i, s) in elf.section_headers.iter().enumerate() {
        if &elf.shdr_strtab[s.sh_name] == want {
            return Ok(i);
        }
    }
    anyhow::bail!("section {want} missing")
}

/// BPF static-call opcode (sites carry src=1 + a reloc).
const BPF_CALL: u8 = 0x85;
/// `call` src reg marking a subprogram (pseudo) call, as opposed to
/// a helper call (`src == 0`, imm = helper id).
const BPF_PSEUDO_CALL: u8 = 1;
/// `ld_imm64` opcode: function-pointer sites (address-taken
/// callbacks for helpers like `bpf_loop`) are 16-byte insns carrying
/// an `R_BPF_64_64` reloc against a `.text` FUNC sym.
const BPF_LD_IMM64: u8 = 0x18;
/// `ld_imm64` src reg marking a relocated function address (the
/// kernel resolves the relative imm to a subprogram — the aya-obj
/// rule: same `target - pc - 1` encoding as a static call).
const BPF_PSEUDO_FUNC: u8 = 4;

/// Require a whole reloc site inside its owning function. The
/// ownership filters pin only the site start; without this a
/// two-slot site could cross into sibling bytes and resolve from
/// them. (Start-ownership is the caller's filter; this pins the
/// tail. The checked add also fails closed on offset overflow
/// before any site read.)
fn check_site_contained(
    off: usize,
    width: usize,
    owner_end: usize,
    owner_name: &str,
    prog: &str,
) -> anyhow::Result<()> {
    let end = off
        .checked_add(width)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: reloc @{off} site out of range"))?;
    if end > owner_end {
        anyhow::bail!("prog {prog}: reloc @{off} site crosses {owner_name} end");
    }
    Ok(())
}

/// Validate one `ld_imm64` map site: instruction-aligned offset
/// plus an unrelocated encoding (opcode, src 0, zero reserved
/// offset bytes). Shared by both map arms and the load-time fixup
/// path (func arms use the stricter `func_ptr_target`, which
/// additionally pins the imm — map sites take an fd imm at load,
/// so only the shape is pinned here).
fn check_ld_imm64_site(bytes: &[u8], off: usize, prog: &str) -> anyhow::Result<()> {
    if off % 8 != 0 {
        anyhow::bail!("prog {prog}: map site misaligned");
    }
    let end = off
        .checked_add(16)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: map site out of range"))?;
    let site = bytes
        .get(off..end)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: map site out of range"))?;
    if site[0] != BPF_LD_IMM64 || site[1] >> 4 != 0 {
        anyhow::bail!("prog {prog}: map site vs non-ld_imm64");
    }
    if site[2..4] != [0u8; 2] {
        anyhow::bail!("prog {prog}: map site reserved bytes set");
    }
    Ok(())
}

/// Resolve an `R_BPF_64_32` call reloc to a `.text` function name.
/// Named FUNC syms resolve by (value, name); STT_SECTION syms (the
/// toolchain's reduction for LOCAL callees — `call -1` + section
/// reloc, as in query_return→walk_dispatch) resolve as
/// section_base + (imm+1)*8, the aya-obj rule. Either way the
/// target MUST be a `.text` entry: mid-function landings are drift,
/// never a guess. The site must be instruction-aligned: a
/// misaligned offset reads a straddling window, never an insn.
fn call_target(
    syms: &[Sym],
    text_fns: &[(usize, usize, String)],
    text_idx: usize,
    site_sec: &[u8],
    r: &Reloc,
    prog: &str,
) -> anyhow::Result<String> {
    if r.off % 8 != 0 {
        anyhow::bail!("prog {prog}: call reloc site misaligned");
    }
    let rsym = syms
        .get(r.sym)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: bad reloc sym"))?;
    let site = site_sec
        .get(r.off..r.off + 8)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: call reloc out of range"))?;
    if site[0] != BPF_CALL {
        anyhow::bail!("prog {prog}: call reloc vs non-call insn");
    }
    if site[1] >> 4 != BPF_PSEUDO_CALL {
        // A reloc on a helper-form call would rewrite the helper id
        // into a relative target — a silent semantic change. Real
        // toolchains emit PSEUDO_CALL for static calls, always.
        anyhow::bail!("prog {prog}: call reloc vs helper call");
    }
    if !rsym.is_section {
        if !rsym.is_func || rsym.shndx != text_idx {
            anyhow::bail!("prog {prog}: call reloc vs non-entry {}", rsym.name);
        }
        return text_fns
            .iter()
            .find(|(v, _, n)| *v == rsym.value && *n == rsym.name)
            .map(|(_, _, n)| n.clone())
            .ok_or_else(|| anyhow::anyhow!("prog {prog}: call reloc vs non-entry {}", rsym.name));
    }
    if rsym.shndx != text_idx {
        anyhow::bail!("prog {prog}: call reloc vs non-.text section {}", rsym.name);
    }
    let imm = i32::from_le_bytes(site[4..8].try_into().unwrap()) as i64;
    let target_off = rsym.value as i64 + (imm + 1) * 8;
    let target_off = usize::try_from(target_off)
        .map_err(|_| anyhow::anyhow!("prog {prog}: call target out of range"))?;
    text_fns
        .iter()
        .find(|(v, _, _)| *v == target_off)
        .map(|(_, _, n)| n.clone())
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: call lands mid-function at {target_off:#x}"))
}

/// Rewrite one static-call imm: call site at `rel_off` (in the final
/// layout) targets `target_off` (in the final layout).
fn apply_call(
    insns: &mut [u8],
    rel_off: usize,
    target_off: usize,
    prog: &str,
) -> anyhow::Result<()> {
    if rel_off % 8 != 0 {
        anyhow::bail!("{prog}: call site misaligned");
    }
    let insn = insns
        .get_mut(rel_off..rel_off + 8)
        .ok_or_else(|| anyhow::anyhow!("{prog}: call reloc out of range"))?;
    if target_off % 8 != 0 {
        anyhow::bail!("{prog}: call target unaligned");
    }
    let pc = rel_off / 8;
    let imm = target_off as i64 / 8 - (pc as i64 + 1);
    let imm32: i32 = imm
        .try_into()
        .map_err(|_| anyhow::anyhow!("{prog}: call target out of range"))?;
    insn[4..8].copy_from_slice(&imm32.to_le_bytes());
    Ok(())
}

/// Resolve an `R_BPF_64_64` function-pointer reloc to a `.text`
/// function name. The site must be an aligned, unrelocated
/// `ld_imm64` (src 0, zero reserved offset bytes, zero imm64 —
/// anything else is an already-relocated or corrupt object); the
/// symbol must be a named global FUNC in `.text` (what the
/// toolchain emits for address-taken callbacks). The target MUST
/// be a `.text` entry: mid-function landings are drift, never a
/// guess.
fn func_ptr_target(
    syms: &[Sym],
    text_fns: &[(usize, usize, String)],
    text_idx: usize,
    site_sec: &[u8],
    r: &Reloc,
    prog: &str,
) -> anyhow::Result<String> {
    if r.off % 8 != 0 {
        anyhow::bail!("prog {prog}: func reloc site misaligned");
    }
    let rsym = syms
        .get(r.sym)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: bad reloc sym"))?;
    let site = site_sec
        .get(r.off..r.off + 16)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: func reloc out of range"))?;
    if site[0] != BPF_LD_IMM64 || site[1] >> 4 != 0 {
        anyhow::bail!("prog {prog}: func reloc vs non-ld_imm64 site");
    }
    if site[2..4] != [0u8; 2] {
        anyhow::bail!("prog {prog}: func reloc site reserved bytes set");
    }
    if site[4..16] != [0u8; 12] {
        anyhow::bail!("prog {prog}: func reloc vs relocated site");
    }
    if !rsym.is_func || rsym.shndx != text_idx {
        anyhow::bail!("prog {prog}: func reloc vs non-entry {}", rsym.name);
    }
    text_fns
        .iter()
        .find(|(v, _, n)| *v == rsym.value && *n == rsym.name)
        .map(|(_, _, n)| n.clone())
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: func reloc vs non-entry {}", rsym.name))
}

/// Rewrite one function-pointer site: the `imm` takes the same
/// relative encoding as a static call (`target - pc - 1`, in insns),
/// and the src nibble takes `BPF_PSEUDO_FUNC` (the dst reg is
/// preserved). The high half stays zero (asserted at resolve time).
/// The site is fully validated before any mutation: a failed
/// rewrite leaves the image untouched.
fn apply_func_ptr(
    insns: &mut [u8],
    rel_off: usize,
    target_off: usize,
    prog: &str,
) -> anyhow::Result<()> {
    if rel_off % 8 != 0 {
        anyhow::bail!("{prog}: func site misaligned");
    }
    let site = insns
        .get(rel_off..rel_off + 8)
        .ok_or_else(|| anyhow::anyhow!("{prog}: func reloc out of range"))?;
    if site[0] != BPF_LD_IMM64 || site[1] >> 4 != 0 {
        anyhow::bail!("{prog}: func site not an unrelocated ld_imm64");
    }
    if site[2..4] != [0u8; 2] {
        anyhow::bail!("{prog}: func site reserved bytes set");
    }
    apply_call(insns, rel_off, target_off, prog)?;
    let insn = insns
        .get_mut(rel_off..rel_off + 8)
        .ok_or_else(|| anyhow::anyhow!("{prog}: func reloc out of range"))?;
    insn[1] = (insn[1] & 0x0f) | (BPF_PSEUDO_FUNC << 4);
    Ok(())
}

/// Reject a linked image containing a subprogram call that was not
/// rewritten from a relocation (F-BPF-1 hardening).
///
/// The toolchain pre-resolves same-section local→local calls to
/// relative pseudo-calls WITHOUT relocs, and reachable-subset
/// linking (required: the verifier rejects unreachable trailing
/// insns) invalidates their offsets — observed as `window_byte`
/// mis-linked onto `memset`, surfacing in the guest as `invalid
/// size of register spill`. Helper calls (`src == 0`) need no
/// reloc and are ignored; every pseudo-call (`src ==
/// BPF_PSEUDO_CALL) must be in `rewritten` (byte offsets into
/// `insns` that `apply_call` patched from a reloc).
fn check_calls_rewritten(
    insns: &[u8],
    rewritten: &HashSet<usize>,
    prog: &str,
) -> anyhow::Result<()> {
    if insns.len() % 8 != 0 {
        anyhow::bail!("{prog}: linked insns not a whole count");
    }
    for (i, insn) in insns.chunks_exact(8).enumerate() {
        if insn[0] == BPF_CALL && insn[1] >> 4 == BPF_PSEUDO_CALL && !rewritten.contains(&(i * 8)) {
            anyhow::bail!(
                "{prog}: unrelocated static call at insn {i} \
                 (callee must be global or inlined)"
            );
        }
    }
    Ok(())
}

/// Reject a linked image containing a function pointer that was not
/// rewritten from a relocation (same hazard as
/// [`check_calls_rewritten`]): a pre-resolved `ld_imm64` with
/// `BPF_PSEUDO_FUNC` src but no reloc would silently point at a
/// stale offset after reachable-subset linking. The scan steps over
/// each `ld_imm64`'s second slot (its bytes are not opcodes);
/// map sites (src 0, rewritten later by `load()`) are ignored here.
fn check_func_ptrs_rewritten(
    insns: &[u8],
    rewritten: &HashSet<usize>,
    prog: &str,
) -> anyhow::Result<()> {
    if insns.len() % 8 != 0 {
        anyhow::bail!("{prog}: linked insns not a whole count");
    }
    let mut i = 0usize;
    while i * 8 < insns.len() {
        let insn = &insns[i * 8..i * 8 + 8];
        if insn[0] == BPF_LD_IMM64 {
            if insn[1] >> 4 == BPF_PSEUDO_FUNC && !rewritten.contains(&(i * 8)) {
                anyhow::bail!(
                    "{prog}: unrelocated function pointer at insn {i} \
                     (callee must be global)"
                );
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    Ok(())
}

/// One linked subprogram for BTF synthesis: the main entry (insn 0)
/// plus every included `.text` function in linked order. Callbacks
/// (function-pointer targets for helpers like `bpf_loop`) need the
/// callback proto; plain static callees take the void placeholder
/// (the verifier never signature-checks static calls).
pub struct SubprogInfo {
    pub name: String,
    pub insn_off: u32,
    pub is_callback: bool,
}

/// Synthesized BTF bytes plus the func_info table (`(insn_off,
/// type_id)` pairs in subprogram order).
pub type SynthBtf = (Vec<u8>, Vec<(u32, u32)>);

/// Synthesize minimal BTF + func_info for one linked image (P5b-D).
/// The toolchain emits no `.BTF` (the frozen object ban stays), so
/// helper-callback shapes (`bpf_loop`) get loader-built metadata:
/// a fixed type prefix (u64/u32 ints, a data pointer, main/callback/
/// static protos) plus one FUNC per subprog, and a func_info table
/// mapping each subprogram's insn offset to its FUNC id. Pure bytes;
/// the kernel re-validates everything at `BPF_BTF_LOAD`/`prog_load`
/// (fail-closed, loud). Fails closed on any malformed table.
pub fn synth_btf(subprogs: &[SubprogInfo]) -> anyhow::Result<SynthBtf> {
    if subprogs.is_empty() {
        anyhow::bail!("synth_btf: no subprograms");
    }
    if subprogs.len() > 256 {
        anyhow::bail!("synth_btf: too many subprograms ({})", subprogs.len());
    }
    if subprogs[0].insn_off != 0 {
        anyhow::bail!("synth_btf: main at 0, got {}", subprogs[0].insn_off);
    }
    for w in subprogs.windows(2) {
        if w[1].insn_off <= w[0].insn_off {
            anyhow::bail!("synth_btf: offsets not increasing");
        }
    }
    for s in subprogs {
        if s.name.is_empty() {
            anyhow::bail!("synth_btf: empty name");
        }
        if s.name.bytes().any(|b| b == 0) {
            anyhow::bail!("synth_btf: NUL in name");
        }
    }
    // String section: leading empty + fixed literals + names.
    let mut strs: Vec<u8> = vec![0];
    let mut off_of: Vec<u32> = Vec::with_capacity(subprogs.len() + 6);
    for lit in ["__u64", "__u32", "ctx", "pad", "arg0", "index", "cctx"] {
        off_of.push(strs.len() as u32);
        strs.extend_from_slice(lit.as_bytes());
        strs.push(0);
    }
    for s in subprogs {
        off_of.push(strs.len() as u32);
        strs.extend_from_slice(s.name.as_bytes());
        strs.push(0);
    }
    // Type section. Kinds per uapi/linux/btf.h: INT=1, PTR=2,
    // STRUCT=4, FUNC=12, FUNC_PROTO=13. The ctx arg is PTR to a
    // DEFINED struct with named params (the kernel rejects looser
    // shapes here: measured `Invalid arg#1` for PTR-to-scalar and
    // PTR-to-FWD with anonymous params on 7.0).
    let mut types: Vec<u8> = Vec::new();
    let mut rec = |name: u32, kind: u32, vlen: u32, size_or_type: u32, payload: &[u32]| {
        types.extend_from_slice(&name.to_le_bytes());
        types.extend_from_slice(&((kind << 24) | vlen).to_le_bytes());
        types.extend_from_slice(&size_or_type.to_le_bytes());
        for w in payload {
            types.extend_from_slice(&w.to_le_bytes());
        }
    };
    rec(off_of[0], 1, 0, 8, &[64]); // 1: INT __u64
    rec(off_of[1], 1, 0, 4, &[32]); // 2: INT __u32
    rec(off_of[2], 4, 1, 8, &[off_of[3], 1, 0]); // 3: STRUCT ctx { u64 pad; }
    rec(0, 2, 0, 3, &[]); // 4: PTR to ctx
    rec(0, 13, 1, 2, &[off_of[4], 4]); // 5: main proto u32 <- (ctx *arg0)
    rec(0, 13, 2, 1, &[off_of[5], 1, off_of[6], 1]); // 6: cb proto u64 <- (u64, u64)
    rec(0, 13, 0, 0, &[]); // 7: static proto void <- ()
    let mut info: Vec<(u32, u32)> = Vec::with_capacity(subprogs.len());
    for (i, s) in subprogs.iter().enumerate() {
        let proto = if i == 0 {
            5
        } else if s.is_callback {
            6
        } else {
            7
        };
        let id = 8 + i as u32;
        rec(off_of[7 + i], 12, 0, proto, &[]);
        info.push((s.insn_off, id));
    }
    // Header: magic, version, flags, hdr_len, type_off, type_len,
    // str_off, str_len.
    let mut btf: Vec<u8> = Vec::with_capacity(24 + types.len() + strs.len());
    btf.extend_from_slice(&0xEB9Fu16.to_le_bytes());
    btf.push(1);
    btf.push(0);
    btf.extend_from_slice(&24u32.to_le_bytes());
    btf.extend_from_slice(&0u32.to_le_bytes());
    btf.extend_from_slice(&(types.len() as u32).to_le_bytes());
    btf.extend_from_slice(&(types.len() as u32).to_le_bytes());
    btf.extend_from_slice(&(strs.len() as u32).to_le_bytes());
    btf.extend_from_slice(&types);
    btf.extend_from_slice(&strs);
    Ok((btf, info))
}

/// Pure preparation: parse, assert shape, relocate (map fds stay
/// symbolic — applied by `load()`).
pub fn prepare(obj: &[u8], maps: &[MapSpec], progs: &[ProgSpec]) -> anyhow::Result<Prepared> {
    let elf = goblin::Object::parse(obj).map_err(|e| anyhow::anyhow!("elf parse: {e}"))?;
    let goblin::Object::Elf(elf) = elf else {
        anyhow::bail!("not an ELF object");
    };
    if elf.header.e_machine != goblin::elf::header::EM_BPF {
        anyhow::bail!("not a BPF object (machine {})", elf.header.e_machine);
    }
    if !elf.little_endian {
        anyhow::bail!("big-endian BPF object unsupported");
    }
    for s in &elf.section_headers {
        let n = &elf.shdr_strtab[s.sh_name];
        if n == ".BTF" || n == ".BTF.ext" {
            anyhow::bail!("frozen shape forbids {n} (BTF-disabled objects only)");
        }
    }
    // License: .license governs when present (must be GPL-compatible),
    // else our objects default to GPL (same as aya).
    if let Some(lic) = sec_bytes_opt(&elf, obj, ".license") {
        let s = std::str::from_utf8(lic)
            .unwrap_or("")
            .trim_end_matches('\0');
        if !GPL_OK.contains(&s) {
            anyhow::bail!("license {s:?} not GPL-compatible");
        }
    }
    let syms = parse_syms(&elf);
    let maps_sec = sec_bytes(&elf, obj, "maps")?;
    let maps_idx = sec_index(&elf, "maps")?;

    // Maps: spec dims asserted against the in-object def records.
    let mut lites = Vec::new();
    for m in maps {
        let sym = syms
            .iter()
            .find(|s| s.is_obj && s.name == m.name && s.shndx == maps_idx)
            .ok_or_else(|| anyhow::anyhow!("map {} missing", m.name))?;
        if sym.size != MAP_DEF_SIZE {
            anyhow::bail!("map {}: def size {} != {MAP_DEF_SIZE}", m.name, sym.size);
        }
        let rec = maps_sec
            .get(sym.value..sym.value + MAP_DEF_SIZE)
            .ok_or_else(|| anyhow::anyhow!("map {} def out of range", m.name))?;
        let dims = [
            u32le(&rec[0..4]),
            u32le(&rec[4..8]),
            u32le(&rec[8..12]),
            u32le(&rec[12..16]),
            u32le(&rec[16..20]),
        ];
        let want = [m.map_type, m.key_size, m.value_size, m.max_entries, m.flags];
        if dims != want {
            anyhow::bail!("map {}: dims {dims:?} != spec {want:?}", m.name);
        }
        lites.push(MapSpecLite {
            name: m.name.to_string(),
            map_type: dims[0],
            key_size: dims[1],
            value_size: dims[2],
            max_entries: dims[3],
            flags: dims[4],
        });
    }
    // Unknown map symbols fail closed (an uncreated map would dangle).
    for s in &syms {
        if s.is_obj && s.shndx == maps_idx && !maps.iter().any(|m| m.name == s.name) {
            anyhow::bail!("map {} in object but not in spec", s.name);
        }
    }

    // Relocations per section (REL format).
    let mut relocs: HashMap<String, Vec<Reloc>> = HashMap::new();
    for s in &elf.section_headers {
        let n = &elf.shdr_strtab[s.sh_name];
        if let Some(tgt) = n.strip_prefix(".rel") {
            let o = s.sh_offset as usize;
            let e = o + s.sh_size as usize;
            let bytes = obj
                .get(o..e)
                .ok_or_else(|| anyhow::anyhow!("rel section {n} out of bounds"))?;
            relocs.insert(tgt.to_string(), parse_relocs(bytes, n)?);
        }
    }
    // Func ranges per section (reloc ownership check).
    let mut funcs: HashMap<String, Vec<(usize, usize, String)>> = HashMap::new();
    for (i, s) in elf.section_headers.iter().enumerate() {
        let n = &elf.shdr_strtab[s.sh_name];
        if n == "uprobe" || n == "uretprobe" {
            let mut v = Vec::new();
            for f in syms.iter().filter(|f| f.is_func && f.shndx == i) {
                v.push((f.value, f.value + f.size, f.name.clone()));
            }
            funcs.insert(n.to_string(), v);
        }
    }
    // `.text` subprograms (link candidates; may be absent).
    let text = sec_bytes_opt(&elf, obj, ".text").unwrap_or(&[]);
    let text_idx = sec_index(&elf, ".text").ok();
    let mut text_fns: Vec<(usize, usize, String)> = Vec::new();
    if let Some(tidx) = text_idx {
        for f in syms.iter().filter(|f| f.is_func && f.shndx == tidx) {
            if f.size == 0 || f.size % 8 != 0 {
                anyhow::bail!(".text fn {}: bad size {}", f.name, f.size);
            }
            if f.value % 8 != 0 {
                anyhow::bail!(".text fn {}: misaligned value", f.name);
            }
            if text_fns.iter().any(|t| t.2 == f.name) {
                anyhow::bail!(".text fn {}: duplicate name", f.name);
            }
            text_fns.push((f.value, f.value + f.size, f.name.clone()));
        }
    }
    // Owner indexes (built once): section relocs grouped by owning
    // function, plus the ownerless offsets in file order. The per-prog
    // loops below used to re-scan every section's func ranges per reloc
    // — O(progs x relocs x fns), ~54s on the 513-prog members object.
    // Same ownership predicate, run once per reloc (ranges are
    // disjoint, so first-hit == only-hit); the per-prog walk merges
    // owned + ownerless in file order, so error precedence is
    // identical to the old full scan, including multi-fault inputs.
    let mut sec_groups: HashMap<String, HashMap<String, Vec<(usize, usize)>>> = HashMap::new();
    let mut sec_ownerless: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    for (sec, ranges) in &funcs {
        let mut groups: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        let mut ownerless: Vec<(usize, usize)> = Vec::new();
        for (i, r) in relocs
            .get(sec)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .enumerate()
        {
            match ranges.iter().find(|(a, b, _)| *a <= r.off && r.off < *b) {
                Some((_, ob, oname)) => {
                    groups.entry(oname.clone()).or_default().push((i, *ob));
                }
                None => ownerless.push((i, r.off)),
            }
        }
        sec_groups.insert(sec.clone(), groups);
        sec_ownerless.insert(sec.clone(), ownerless);
    }
    let mut text_owner_map: HashMap<usize, (usize, usize, String)> = HashMap::new();
    for r in relocs.get(".text").map(Vec::as_slice).unwrap_or(&[]) {
        if let Some((a, b, n)) = text_fns.iter().find(|(a, b, _)| *a <= r.off && r.off < *b) {
            text_owner_map.insert(r.off, (*a, *b, n.clone()));
        }
    }
    // `.text` relocs grouped by owning fn (file order preserved per
    // fn — the closure walk below sees the same sequence as the old
    // filter-over-all scan).
    let mut text_by_fn: HashMap<String, Vec<usize>> = HashMap::new();
    if let Some(rs) = relocs.get(".text") {
        for (i, r) in rs.iter().enumerate() {
            if let Some((_, _, owner)) = text_owner_map.get(&r.off) {
                text_by_fn.entry(owner.clone()).or_default().push(i);
            }
        }
    }
    // `.text` fn ranges by name (names are unique — the duplicate
    // check above bails — so this matches the old linear finds).
    let mut text_fn_range: HashMap<String, (usize, usize)> = HashMap::new();
    for (a, b, n) in &text_fns {
        text_fn_range.insert(n.clone(), (*a, *b));
    }

    let mut out = Vec::new();
    for p in progs {
        let is_return = match p.section {
            "uprobe" => false,
            "uretprobe" => true,
            s => anyhow::bail!("prog {}: bad section {s}", p.name),
        };
        let sec = sec_bytes(&elf, obj, p.section)?;
        let sidx = sec_index(&elf, p.section)?;
        let sym = syms
            .iter()
            .find(|s| s.is_func && s.name == p.name && s.shndx == sidx)
            .ok_or_else(|| anyhow::anyhow!("prog {} missing", p.name))?;
        if sym.size == 0 || sym.size % 8 != 0 {
            anyhow::bail!("prog {}: bad size {}", p.name, sym.size);
        }
        if sym.value % 8 != 0 {
            anyhow::bail!("prog {}: misaligned value", p.name);
        }
        let main = sec
            .get(sym.value..sym.value + sym.size)
            .ok_or_else(|| anyhow::anyhow!("prog {} out of range", p.name))?;
        let mut fixups = Vec::new();
        // Main's owned relocs: map sites recorded, call and
        // function-pointer targets rooted.
        let mut roots: Vec<(usize, String)> = Vec::new(); // (local off, fn)
        let mut func_roots: Vec<(usize, String)> = Vec::new(); // (local off, fn)
        let sec_rs = relocs.get(p.section).map(Vec::as_slice).unwrap_or(&[]);
        let empty_group: &[(usize, usize)] = &[];
        // Owned relocs (file order) + ownerless relocs (file order);
        // the walk below merges both in file order (same encounter
        // order as the old full scan — sibling relocs skipped
        // without ever being visited).
        let own = sec_groups
            .get(p.section)
            .and_then(|g| g.get(p.name))
            .map(Vec::as_slice)
            .unwrap_or(empty_group);
        let less = sec_ownerless
            .get(p.section)
            .map(Vec::as_slice)
            .unwrap_or(empty_group);
        // One owned reloc's checks (the old loop body minus the
        // owner scan/sibling skip — grouping already selected;
        // `oname` there always equaled `p.name` here).
        let mut process = |r: &Reloc, ob: usize| -> anyhow::Result<()> {
            // Calls patch 8 bytes, `ld_imm64` sites (func and map)
            // 16: the whole site must sit inside its owner.
            let width = match r.typ {
                R_BPF_64_64 => 16,
                R_BPF_64_32 => 8,
                t => anyhow::bail!("prog {}: reloc type {t} unsupported", p.name),
            };
            check_site_contained(r.off, width, ob, p.name, p.name)?;
            let rsym = syms
                .get(r.sym)
                .ok_or_else(|| anyhow::anyhow!("prog {}: bad reloc sym", p.name))?;
            let local = r.off - sym.value;
            match r.typ {
                R_BPF_64_64 => {
                    if rsym.is_func {
                        let tidx = text_idx.ok_or_else(|| {
                            anyhow::anyhow!("prog {}: func reloc but no .text", p.name)
                        })?;
                        let target = func_ptr_target(&syms, &text_fns, tidx, sec, r, p.name)?;
                        func_roots.push((local, target));
                    } else {
                        if !(rsym.is_obj && maps.iter().any(|m| m.name == rsym.name)) {
                            anyhow::bail!("prog {}: map reloc vs {}", p.name, rsym.name);
                        }
                        check_ld_imm64_site(sec, r.off, p.name)?;
                        fixups.push(MapFixup {
                            insn_off: local,
                            map: rsym.name.clone(),
                        });
                    }
                }
                R_BPF_64_32 => {
                    let tidx = text_idx.ok_or_else(|| {
                        anyhow::anyhow!("prog {}: call reloc but no .text", p.name)
                    })?;
                    let target = call_target(&syms, &text_fns, tidx, sec, r, p.name)?;
                    roots.push((local, target));
                }
                t => anyhow::bail!("prog {}: reloc type {t} unsupported", p.name),
            }
            Ok(())
        };
        // `b` never advances: the first ownerless reloc reached
        // always bails (same as the old scan encountering it).
        let (mut a, b) = (0usize, 0usize);
        while a < own.len() || b < less.len() {
            let own_first = b >= less.len() || (a < own.len() && own[a].0 < less[b].0);
            if own_first {
                let (i, ob) = own[a];
                a += 1;
                process(&sec_rs[i], ob)?;
            } else {
                anyhow::bail!("prog {}: reloc @{} ownerless (drift)", p.name, less[b].1);
            }
        }
        // Reachable closure over `.text` call and function-pointer
        // relocs (transitive). Only reachable subprograms are linked:
        // the verifier rejects unreachable trailing insns, so blind
        // `.text` appends fail.
        let mut included: Vec<String> = Vec::new();
        let mut included_set: HashSet<String> = HashSet::new();
        let mut work: Vec<String> = roots
            .iter()
            .chain(func_roots.iter())
            .map(|(_, n)| n.clone())
            .collect();
        let text_rs = relocs.get(".text").map(Vec::as_slice).unwrap_or(&[]);
        while let Some(next) = work.pop() {
            if !included_set.insert(next.clone()) {
                continue;
            }
            included.push(next.clone());
            let (f0, f1) = text_fn_range
                .get(&next)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("prog {}: call vs unknown {next}", p.name))?;
            let empty: &[usize] = &[];
            for &i in text_by_fn.get(&next).map(Vec::as_slice).unwrap_or(empty) {
                let r = &text_rs[i];
                // Range guard retained: grouping already restricts
                // to this fn's relocs (same predicate, same file
                // order) — belt and suspenders.
                if f0 <= r.off && r.off < f1 {
                    let width = match r.typ {
                        R_BPF_64_32 => 8,
                        R_BPF_64_64 => 16,
                        // Unknown types bail in the apply loop below.
                        _ => continue,
                    };
                    check_site_contained(r.off, width, f1, &next, p.name)?;
                    if r.typ == R_BPF_64_32 {
                        let tidx = text_idx.ok_or_else(|| {
                            anyhow::anyhow!("prog {}: call reloc but no .text", p.name)
                        })?;
                        work.push(call_target(&syms, &text_fns, tidx, text, r, p.name)?);
                    } else if r.typ == R_BPF_64_64 {
                        let rsym = syms.get(r.sym).ok_or_else(|| {
                            anyhow::anyhow!("prog {}: bad text reloc sym", p.name)
                        })?;
                        if rsym.is_func {
                            let tidx = text_idx.ok_or_else(|| {
                                anyhow::anyhow!("prog {}: func reloc but no .text", p.name)
                            })?;
                            work.push(func_ptr_target(&syms, &text_fns, tidx, text, r, p.name)?);
                        }
                        // Map relocs pull no code.
                    }
                }
            }
        }
        included.sort_by_key(|n| text_fn_range.get(n).map(|(v, _)| *v));
        // Layout: main + included subprograms in `.text` order.
        let mut insns = main.to_vec();
        let mut base: HashMap<String, usize> = HashMap::new();
        for name in &included {
            let (f0, f1) = text_fn_range.get(name).copied().unwrap();
            let bytes = text
                .get(f0..f1)
                .ok_or_else(|| anyhow::anyhow!("prog {}: .text fn {name} out of range", p.name))?;
            base.insert(name.clone(), insns.len());
            insns.extend_from_slice(bytes);
        }
        // Apply calls and function pointers (main + included)
        // and included map sites. Every rewritten call/func site is
        // recorded: the linked image must contain no other
        // pseudo-call or pseudo-func (see `check_calls_rewritten`
        // and `check_func_ptrs_rewritten`).
        let mut rewritten: HashSet<usize> = HashSet::new();
        for (local, target) in &roots {
            let t = base
                .get(target)
                .ok_or_else(|| anyhow::anyhow!("prog {}: call vs unlinked {target}", p.name))?;
            apply_call(&mut insns, *local, *t, p.name)?;
            rewritten.insert(*local);
        }
        let mut callbacks: HashSet<String> = HashSet::new();
        for (local, target) in &func_roots {
            let t = base
                .get(target)
                .ok_or_else(|| anyhow::anyhow!("prog {}: func vs unlinked {target}", p.name))?;
            apply_func_ptr(&mut insns, *local, *t, p.name)?;
            rewritten.insert(*local);
            callbacks.insert(target.clone());
        }
        for r in relocs.get(".text").map(Vec::as_slice).unwrap_or(&[]) {
            let Some((f0, f1, owner)) = text_owner_map.get(&r.off) else {
                anyhow::bail!("prog {}: text reloc @{} ownerless (drift)", p.name, r.off);
            };
            let Some(obase) = base.get(owner.as_str()) else {
                continue; // subprogram unreachable from this prog
            };
            let width = match r.typ {
                R_BPF_64_64 => 16,
                R_BPF_64_32 => 8,
                t => anyhow::bail!("prog {}: text reloc type {t} unsupported", p.name),
            };
            check_site_contained(r.off, width, *f1, owner, p.name)?;
            let rsym = syms
                .get(r.sym)
                .ok_or_else(|| anyhow::anyhow!("prog {}: bad text reloc sym", p.name))?;
            match r.typ {
                R_BPF_64_64 => {
                    if rsym.is_func {
                        let tidx = text_idx.ok_or_else(|| {
                            anyhow::anyhow!("prog {}: func reloc but no .text", p.name)
                        })?;
                        let target = func_ptr_target(&syms, &text_fns, tidx, text, r, p.name)?;
                        if !included_set.contains(&target) {
                            anyhow::bail!("prog {}: func vs excluded {}", p.name, target);
                        }
                        let t = base.get(&target).ok_or_else(|| {
                            anyhow::anyhow!("prog {}: func vs unlinked {}", p.name, target)
                        })?;
                        let site = obase + (r.off - *f0);
                        apply_func_ptr(&mut insns, site, *t, p.name)?;
                        rewritten.insert(site);
                        callbacks.insert(target.clone());
                        continue;
                    }
                    if !(rsym.is_obj && maps.iter().any(|m| m.name == rsym.name)) {
                        anyhow::bail!("prog {}: text map reloc vs {}", p.name, rsym.name);
                    }
                    check_ld_imm64_site(text, r.off, p.name)?;
                    fixups.push(MapFixup {
                        insn_off: obase + (r.off - *f0),
                        map: rsym.name.clone(),
                    });
                }
                R_BPF_64_32 => {
                    let tidx = text_idx.ok_or_else(|| {
                        anyhow::anyhow!("prog {}: call reloc but no .text", p.name)
                    })?;
                    let target = call_target(&syms, &text_fns, tidx, text, r, p.name)?;
                    // Call targets must be entries (closure invariant).
                    if !included_set.contains(&target) {
                        anyhow::bail!("prog {}: call vs excluded {}", p.name, target);
                    }
                    let t = base.get(&target).ok_or_else(|| {
                        anyhow::anyhow!("prog {}: call vs unlinked {}", p.name, target)
                    })?;
                    let site = obase + (r.off - *f0);
                    apply_call(&mut insns, site, *t, p.name)?;
                    rewritten.insert(site);
                }
                t => anyhow::bail!("prog {}: text reloc type {t} unsupported", p.name),
            }
        }
        check_calls_rewritten(&insns, &rewritten, p.name)?;
        check_func_ptrs_rewritten(&insns, &rewritten, p.name)?;
        let mut subprogs = Vec::with_capacity(included.len() + 1);
        subprogs.push(SubprogInfo {
            name: p.name.to_string(),
            insn_off: 0,
            is_callback: false,
        });
        for name in &included {
            // Invariant: the layout loop above entered every included
            // name (same vec, same order).
            let off = base.get(name).copied().unwrap() / 8;
            subprogs.push(SubprogInfo {
                name: name.clone(),
                insn_off: off as u32,
                is_callback: callbacks.contains(name),
            });
        }
        out.push(PreparedProg {
            name: p.name.to_string(),
            is_return,
            insns,
            map_fixups: fixups,
            subprogs,
        });
    }
    Ok(Prepared {
        progs: out,
        maps: lites,
    })
}

/// Load a prepared object: create maps, apply map-fd fixups (with
/// the `BPF_PSEUDO_MAP_FD` assertion), load progs raw. Needs caps.
/// Verifier output travels in the error on failure.
/// Load one prepared program (map-fd fixups + quiet load with
/// a logging retry on failure). Shared by all-or-nothing
/// [`load`] and keep-good [`load_keep_good`]; `spill` gates the
/// full-verifier-log temp file.
fn load_prog(
    p: &PreparedProg,
    maps: &HashMap<String, OwnedFd>,
    spill: bool,
) -> anyhow::Result<OwnedFd> {
    use anyhow::Context as _;
    let mut insns = p.insns.clone();
    for f in &p.map_fixups {
        // Full 16-byte range first (checked: `Prepared` fields
        // are public, so a huge hand-built offset must ERR, not
        // panic on overflow), then shape, then patch. The borrow
        // below cannot overflow: the validator proved
        // `off + 16 <= len`.
        check_ld_imm64_site(&insns, f.insn_off, &p.name)?;
        let insn = insns
            .get_mut(f.insn_off..f.insn_off + 8)
            .ok_or_else(|| anyhow::anyhow!("{}: fixup out of range", p.name))?;
        // The compiler emits map sites with src=0; the reloc means
        // "this imm64 is a map" — the loader sets src AND fd.
        // Anything else is an already-relocated (or corrupt) object.
        let fd = maps
            .get(&f.map)
            .ok_or_else(|| anyhow::anyhow!("{}: unknown map {}", p.name, f.map))?;
        insn[1] = (insn[1] & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
        insn[4..8].copy_from_slice(&(fd.as_raw_fd() as u32).to_le_bytes());
    }
    let license = c"GPL";
    // Callback shapes only: synthesize BTF + func_info and load
    // it (the kernel needs the callback's FUNC_PROTO — without
    // it `bpf_loop` fails `missing btf func_info`). Every other
    // prog loads BTF-less exactly as before. The BTF fd outlives
    // both load attempts (drop closes it; loaded progs hold
    // their own refs).
    let mut btf_fd: Option<std::os::fd::OwnedFd> = None;
    let mut func_info_bytes: Vec<u8> = Vec::new();
    if p.subprogs.iter().any(|s| s.is_callback) {
        let (btf, info) =
            synth_btf(&p.subprogs).with_context(|| format!("synth_btf {}", p.name))?;
        for (off, id) in &info {
            func_info_bytes.extend_from_slice(&off.to_le_bytes());
            func_info_bytes.extend_from_slice(&id.to_le_bytes());
        }
        let mut btf_log = vec![0u8; 1 << 16];
        let fd = ossl_bpf_sys::btf_load(&btf, &mut btf_log).map_err(|e| {
            let detail = String::from_utf8_lossy(trim_nul(&btf_log))
                .chars()
                .take(1000)
                .collect::<String>();
            anyhow::anyhow!("btf_load {}: {e}\n{detail}", p.name)
        })?;
        btf_fd = Some(fd);
    }
    let prog_btf = |fd: &Option<std::os::fd::OwnedFd>| -> Option<ossl_bpf_sys::ProgBtf<'_>> {
        fd.as_ref().map(|f| ossl_bpf_sys::ProgBtf {
            btf_fd: std::os::fd::AsRawFd::as_raw_fd(f),
            func_info: &func_info_bytes,
        })
    };
    // Quiet load first: success needs no diagnostics, and a
    // large-but-valid verification can overflow a fixed log
    // buffer (`ENOSPC`) even when the program verifies. On
    // failure, retry with the log buffer to capture the
    // verifier's report (a 4 MiB buffer: failure explorations
    // run to ~0.9 MiB, and an overflowed buffer would eat the
    // very diagnostics the retry exists for).
    let fd = match ossl_bpf_sys::prog_load_kprobe_quiet(
        &insns,
        license,
        None,
        &p.name,
        prog_btf(&btf_fd),
    ) {
        Ok(fd) => fd,
        Err(_) => {
            let mut log = vec![0u8; 4 << 20];
            match ossl_bpf_sys::prog_load_kprobe(
                &insns,
                license,
                None,
                &mut log,
                &p.name,
                prog_btf(&btf_fd),
            ) {
                Ok(fd) => fd,
                Err(e) => {
                    let full = trim_nul(&log);
                    let detail = String::from_utf8_lossy(full)
                        .chars()
                        .take(2000)
                        .collect::<String>();
                    // Keep-good loads cap verifier-log spills (a pathological
                    // all-rejected object must not fill the temp dir).
                    let spill = spill.then(|| spill_verifier_log(&p.name, full)).flatten();
                    return Err(anyhow::anyhow!(
                        "prog_load {}: {e}\n{detail}{}",
                        p.name,
                        spill
                            .map(|p| format!("\n(full verifier log: {})", p.display()))
                            .unwrap_or_default()
                    ));
                }
            }
        }
    };
    Ok(fd)
}

pub fn load(prep: &Prepared) -> anyhow::Result<Loaded> {
    use anyhow::Context as _;
    let mut maps = HashMap::new();
    for m in &prep.maps {
        let fd = ossl_bpf_sys::map_create(
            m.map_type,
            m.key_size,
            m.value_size,
            m.max_entries,
            None,
            &m.name,
        )
        .with_context(|| format!("map_create {}", m.name))?;
        maps.insert(m.name.clone(), fd);
    }
    let mut progs = HashMap::new();
    for p in &prep.progs {
        let fd = load_prog(p, &maps, true)?;
        progs.insert(p.name.clone(), fd);
    }
    Ok(Loaded { progs, maps })
}

/// One rejected program under keep-good loading (the slot is
/// reported, never silently dropped — the oracle marks it
/// unobserved PARTIAL).
#[derive(Debug, Clone)]
pub struct FailedProg {
    pub prog: String,
    pub error: String,
}

/// Keep-good load: maps are all-or-nothing (shared by every
/// member — a map failure fails the load), but each program loads
/// independently — one rejection is recorded and the rest proceed.
/// Verifier-log spills are capped at 8 (a pathological
/// all-rejected object must not fill the temp dir; every failure
/// still carries its 2000-char summary in `error`).
pub fn load_keep_good(prep: &Prepared) -> anyhow::Result<(Loaded, Vec<FailedProg>)> {
    use anyhow::Context as _;
    let mut maps = HashMap::new();
    for m in &prep.maps {
        let fd = ossl_bpf_sys::map_create(
            m.map_type,
            m.key_size,
            m.value_size,
            m.max_entries,
            None,
            &m.name,
        )
        .with_context(|| format!("map_create {}", m.name))?;
        maps.insert(m.name.clone(), fd);
    }
    let mut progs = HashMap::new();
    let mut failed = Vec::new();
    for p in &prep.progs {
        match load_prog(p, &maps, failed.len() < 8) {
            Ok(fd) => {
                progs.insert(p.name.clone(), fd);
            }
            Err(e) => failed.push(FailedProg {
                prog: p.name.clone(),
                error: format!("{e:#}"),
            }),
        }
    }
    Ok((Loaded { progs, maps }, failed))
}

/// Member-chunk fd budget: 513 prog fds + 14 map fds + 513 link fds
/// (all held — drop = detach) + clones + stdio ≈ 1047 > the 1024
/// default (EMFILE observed at member_499). NEED is the fail-closed
/// floor; WANT is the unprivileged raise target under the hard cap.
pub const MEMBERS_FD_NEED: u64 = 4096;
pub const MEMBERS_FD_WANT: u64 = 8192;

/// Pure gate: is this soft RLIMIT_NOFILE enough for the chunk?
/// (Unit-tested; the effectful raise below is live-proven — every
/// member leg attaches through it, EMFILE would RED.)
pub const fn members_fd_budget_ok(soft: u64) -> bool {
    soft >= MEMBERS_FD_NEED
}

/// Raise/check own RLIMIT_NOFILE for the chunk budget (fail-closed:
/// errors when the hard cap itself is too small — no silent
/// half-attach). Unprivileged soft raise; idempotent.
pub fn ensure_members_fd_budget() -> anyhow::Result<()> {
    // SAFETY: getrlimit/setrlimit on valid pointers; rlim_t widths
    // are libc's. No threads are spawned here — the limit is
    // process-wide by design (the attach needs it process-wide).
    unsafe {
        let mut r = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r as *mut _) != 0 {
            anyhow::bail!("getrlimit NOFILE failed");
        }
        if r.rlim_cur < MEMBERS_FD_WANT {
            r.rlim_cur = std::cmp::min(MEMBERS_FD_WANT, r.rlim_max);
            if libc::setrlimit(libc::RLIMIT_NOFILE, &r as *const _) != 0 {
                anyhow::bail!("setrlimit NOFILE failed");
            }
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r as *mut _) != 0 {
                anyhow::bail!("getrlimit NOFILE re-read failed");
            }
        }
        if !members_fd_budget_ok(r.rlim_cur) {
            anyhow::bail!(
                "NOFILE {} below the {}-fd chunk budget (hard cap too small)",
                r.rlim_cur,
                MEMBERS_FD_NEED
            );
        }
    }
    Ok(())
}

/// Member-object EVENTS ring size in bytes (pinned here and in
/// `MEMBER_MAPS`; item 7 grew it to 16MiB — the 4MiB governor
/// policy value is now live, not the small-ring fixture half).
pub const MEMBER_RING_BYTES: u64 = 1 << 24;

/// Production session-control value (R18 §5): EXPECTED = attached
/// member count (1..=512 — item 6 programs fewer legitimately),
/// epoch 1, SKIP_ALL clear, governor = min(4MiB policy, ring/2)
/// per [`osslscope_ebpf_common::governor_for_ring`]. Rejects
/// out-of-range EXPECTED before any attach (the entry would skip
/// cause 7 on it — loud either way, but fail-fast is better).
pub fn default_ctrl(
    expected: u32,
    ring_bytes: u64,
) -> anyhow::Result<osslscope_ebpf_common::CtrlValue> {
    if !(1..=512).contains(&expected) {
        anyhow::bail!("EXPECTED {expected} outside 1..=512");
    }
    Ok(osslscope_ebpf_common::ctrl_value(
        expected,
        1,
        osslscope_ebpf_common::governor_for_ring(ring_bytes),
    ))
}

/// Program the scan-plane session control cell (`CTRL[0]`).
/// Live-proven (L1 reads it back — a failed write REDs there).
pub fn program_ctrl(
    maps: &HashMap<String, OwnedFd>,
    ctrl: &osslscope_ebpf_common::CtrlValue,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use aya::maps::{Array, Map, MapData};
    let fd = maps
        .get("CTRL")
        .context("CTRL map missing")?
        .try_clone()
        .context("clone CTRL")?;
    let data = MapData::from_fd(fd).context("CTRL mapdata")?;
    let map = Map::from_map_data(data).context("CTRL map")?;
    let mut arr =
        Array::<_, osslscope_ebpf_common::CtrlValue>::try_from(map).context("CTRL array shape")?;
    arr.set(0, *ctrl, 0).context("write CTRL[0]")?;
    Ok(())
}

/// Read back the session control cell (legs + future daemon).
pub fn read_ctrl(
    maps: &HashMap<String, OwnedFd>,
) -> anyhow::Result<osslscope_ebpf_common::CtrlValue> {
    use anyhow::Context as _;
    use aya::maps::{Array, Map, MapData};
    let fd = maps
        .get("CTRL")
        .context("CTRL map missing")?
        .try_clone()
        .context("clone CTRL")?;
    let data = MapData::from_fd(fd).context("CTRL mapdata")?;
    let map = Map::from_map_data(data).context("CTRL map")?;
    let arr =
        Array::<_, osslscope_ebpf_common::CtrlValue>::try_from(map).context("CTRL array shape")?;
    arr.get(&0, 0).context("read CTRL[0]")
}

/// A fully attached member chunk: loaded progs/maps + live links.
/// Drop order detaches members first (Vec drop), then entry, then
/// maps/progs (Loaded drop) — the reverse of construction.
pub struct MembersAttached {
    pub loaded: Loaded,
    pub entry: OwnedFd,
    pub members: Vec<OwnedFd>,
}

/// Normalize + validate a selective slot set (sorted, deduped;
/// rejects empty sets and slots ≥ 512 — a scan with no members
/// retires nothing, so attach nothing instead).
pub fn normalize_slots(slots: &[u32]) -> anyhow::Result<Vec<u32>> {
    let mut want: Vec<u32> = slots.to_vec();
    want.sort_unstable();
    want.dedup();
    if want.is_empty() {
        anyhow::bail!("selective attach with no members");
    }
    if want.iter().any(|&j| j >= 512) {
        anyhow::bail!("selective attach slot exceeds 511");
    }
    Ok(want)
}

/// Prog specs for a selective attach: the entry + exactly the
/// wanted members (selective prepare loads ONLY these programs —
/// never the full 513 — so unselected members cost no verify
/// time and cannot fail the attach).
pub fn member_specs_for_slots(slots: &[u32]) -> anyhow::Result<Vec<ProgSpec>> {
    let want = normalize_slots(slots)?;
    let mut specs = Vec::with_capacity(want.len() + 1);
    specs.push(MEMBER_PROGS[0]);
    for j in want {
        specs.push(MEMBER_PROGS[1 + j as usize]);
    }
    Ok(specs)
}

/// Selective member attach (item 6): entry + exactly `slots`
/// (cookie = slot), EXPECTED programmed from `ctrl` (which MUST
/// equal `slots.len()` — the retire equation counts attached
/// members; mismatch fails fast here, never silently in BPF).
/// Unattached slots are OUT OF SCOPE (the oracle reports them as
/// unobserved, never as holes — holes are missing evidence
/// WITHIN the attached set). The entry is always attached (the
/// CALLS census and the oracle's join root never drop). Order of
/// `slots` is normalized (sorted, deduped); empty sets are
/// rejected (a scan with no members retires nothing — attach
/// nothing instead).
/// One slot that did not attach under a selective attach
/// (load rejection or link failure — reported, never silent).
#[derive(Debug, Clone)]
pub struct FailedSlot {
    pub slot: u32,
    pub stage: &'static str,
    pub error: String,
}

/// Selective-attach outcome: what attached (with EXPECTED
/// programmed to the attached count) plus every failed slot.
pub struct SubsetAttached {
    pub attached: MembersAttached,
    /// Actually-attached slots, sorted (the oracle scope — failed
    /// slots are unobserved PARTIAL there, never holes).
    pub slots: Vec<u32>,
    pub failed: Vec<FailedSlot>,
}

pub fn attach_members_subset(
    obj: &std::path::Path,
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    ctrl: &osslscope_ebpf_common::CtrlValue,
    slots: &[u32],
) -> anyhow::Result<SubsetAttached> {
    use anyhow::Context as _;
    let bytes = std::fs::read(obj).with_context(|| format!("read {}", obj.display()))?;
    attach_members_subset_from_bytes(&bytes, exe, off, pid, ctrl, slots)
}

/// Selective attach over verified bytes (no path re-read — the
/// caller hashes these same bytes for provenance, so identity and
/// loading cannot drift).
pub fn attach_members_subset_from_bytes(
    bytes: &[u8],
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    ctrl: &osslscope_ebpf_common::CtrlValue,
    slots: &[u32],
) -> anyhow::Result<SubsetAttached> {
    use anyhow::Context as _;
    if bytes.len() as u64 > crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES {
        anyhow::bail!(
            "members snapshot {} bytes exceeds the onboarding cap",
            bytes.len()
        );
    }
    let want = normalize_slots(slots)?;
    if ctrl.expected as usize != want.len() {
        anyhow::bail!(
            "CTRL EXPECTED {} != {} wanted members",
            ctrl.expected,
            want.len()
        );
    }
    ensure_members_fd_budget()?;
    // Selective prepare: ONLY the entry + wanted members (never
    // the full 513 — unselected members cost no verify time and
    // cannot fail the attach).
    let specs = member_specs_for_slots(&want)?;
    let prep = prepare(bytes, &MEMBER_MAPS, &specs).context("prepare members.o subset")?;
    // Keep-good load: one rejection is recorded, the rest proceed.
    let (loaded, load_failed) = load_keep_good(&prep).context("load members.o subset")?;
    if !loaded.progs.contains_key("member_entry") {
        anyhow::bail!("selective attach: member_entry rejected, no census possible");
    }
    let entry = ossl_bpf_sys::link_create_uprobe_multi(
        loaded.progs["member_entry"].as_raw_fd(),
        exe,
        &[off],
        &[osslscope_ebpf_common::MEMBER_ENTRY_COOKIE],
        pid,
    )
    .context("attach member_entry")?;
    // Keep-good attach: one link failure is recorded, the rest
    // proceed. EXPECTED programs to the ATTACHED count (the
    // retire equation counts attached members, not wanted ones).
    let mut members = Vec::new();
    let mut attached_slots = Vec::new();
    let mut failed: Vec<FailedSlot> = load_failed
        .into_iter()
        .filter_map(|f| {
            f.prog
                .strip_prefix("member_")
                .and_then(|s| s.parse::<u32>().ok())
                .map(|slot| FailedSlot {
                    slot,
                    stage: "load",
                    error: f.error,
                })
        })
        .collect();
    for j in want {
        let name = format!("member_{j:03}");
        let Some(prog) = loaded.progs.get(&name) else {
            continue; // load rejection already recorded above
        };
        match ossl_bpf_sys::link_create_uretprobe_multi(
            prog.as_raw_fd(),
            exe,
            &[off],
            &[j as u64],
            pid,
        ) {
            Ok(link) => {
                members.push(link);
                attached_slots.push(j);
            }
            Err(e) => failed.push(FailedSlot {
                slot: j,
                stage: "attach",
                error: format!("{e:#}"),
            }),
        }
    }
    if attached_slots.is_empty() {
        anyhow::bail!("selective attach: every wanted member failed");
    }
    let mut actual_ctrl = *ctrl;
    actual_ctrl.expected = attached_slots.len() as u32;
    program_ctrl(&loaded.maps, &actual_ctrl).context("program CTRL")?;
    failed.sort_by_key(|f| f.slot);
    Ok(SubsetAttached {
        attached: MembersAttached {
            loaded,
            entry,
            members,
        },
        slots: attached_slots,
        failed,
    })
}

/// Production attach of the member chunk: fd budget → prepare →
/// load → program CTRL → attach entry (cookie 512) + members
/// (cookie = slot) at `off` in `exe` for `pid`. One entry point so
/// the legs dogfood the exact production path (L7's cookie fault
/// re-attaches a single member link surgically on top).
/// Live-proven by every member leg (L1 first).
pub fn attach_members(
    obj: &std::path::Path,
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    ctrl: &osslscope_ebpf_common::CtrlValue,
) -> anyhow::Result<MembersAttached> {
    use anyhow::Context as _;
    let bytes = std::fs::read(obj).with_context(|| format!("read {}", obj.display()))?;
    attach_members_from_bytes(&bytes, exe, off, pid, ctrl)
}

/// Full attach over verified bytes (no path re-read — the caller
/// hashes these same bytes for provenance, so identity and loading
/// cannot drift). All-or-nothing (a full-table scan with holes
/// from load failure refuses instead of half-observing).
pub fn attach_members_from_bytes(
    bytes: &[u8],
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    ctrl: &osslscope_ebpf_common::CtrlValue,
) -> anyhow::Result<MembersAttached> {
    use anyhow::Context as _;
    if bytes.len() as u64 > crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES {
        anyhow::bail!(
            "members snapshot {} bytes exceeds the onboarding cap",
            bytes.len()
        );
    }
    ensure_members_fd_budget()?;
    let prep = prepare(bytes, &MEMBER_MAPS, &MEMBER_PROGS).context("prepare members.o")?;
    let loaded = load(&prep).context("load members.o")?;
    program_ctrl(&loaded.maps, ctrl).context("program CTRL")?;
    let entry = ossl_bpf_sys::link_create_uprobe_multi(
        loaded.progs["member_entry"].as_raw_fd(),
        exe,
        &[off],
        &[osslscope_ebpf_common::MEMBER_ENTRY_COOKIE],
        pid,
    )
    .context("attach member_entry")?;
    let mut members = Vec::with_capacity(512);
    for j in 0..512u64 {
        let name = format!("member_{j:03}");
        let prog = loaded
            .progs
            .get(&name)
            .with_context(|| format!("prog {name} missing"))?;
        members.push(
            ossl_bpf_sys::link_create_uretprobe_multi(prog.as_raw_fd(), exe, &[off], &[j], pid)
                .with_context(|| format!("attach {name}"))?,
        );
    }
    Ok(MembersAttached {
        loaded,
        entry,
        members,
    })
}

/// Strip the kernel log buffer's NUL padding (the verifier writes a
/// C string into our 1 MiB buffer).
fn trim_nul(log: &[u8]) -> &[u8] {
    let mut end = log.len();
    while end > 0 && log[end - 1] == 0 {
        end -= 1;
    }
    &log[..end]
}

/// Best-effort spill of a FULL verifier log on `prog_load` failure
/// (F-DIAG-1): the in-error summary stays capped at 2000 chars, but
/// diagnosis needs the whole multi-hundred-KB text, so it lands in
/// a temp file whose path the error names. Returns the path written.
fn spill_verifier_log(prog: &str, log: &[u8]) -> Option<std::path::PathBuf> {
    let safe: String = prog
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = std::env::temp_dir().join(format!(
        "osslscope-verifier-{safe}-{}.log",
        std::process::id()
    ));
    std::fs::write(&path, log).ok()?;
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn u32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }
    fn u64(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    #[test]
    fn subset_from_bytes_refuses_over_cap_before_bpf() {
        // Finding 11 (loader layer): an over-cap caller buffer
        // refuses before prepare/load (no post-onboarding
        // enlargement bypass). Host-safe: the refusal precedes
        // all BPF work.
        let big = vec![0u8; (crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES + 1) as usize];
        let exe = std::ffi::CString::new("/exe").unwrap();
        let ctrl = osslscope_ebpf_common::ctrl_value(2, 1, 1 << 22);
        let e = attach_members_subset_from_bytes(&big, &exe, 0, 0, &ctrl, &[0, 1])
            .err()
            .expect("over-cap refuses");
        assert!(
            e.to_string().contains("exceeds the onboarding cap"),
            "{e:#}"
        );
    }

    #[test]
    fn selective_specs_cover_entry_plus_wanted_only() {
        // Normalized (sorted, deduped): entry + exactly the
        // wanted members — unselected members are never
        // prepared, loaded, or attached.
        let specs = member_specs_for_slots(&[3, 1, 1]).unwrap();
        let names: Vec<&str> = specs.iter().map(|s| s.name).collect();
        assert_eq!(names, ["member_entry", "member_001", "member_003"]);
        assert_eq!(specs[0].section, "uprobe");
        assert!(specs[1..].iter().all(|s| s.section == "uretprobe"));
        // Full-range edge: slot 511 resolves, 512 rejects.
        let specs = member_specs_for_slots(&[511]).unwrap();
        assert_eq!(specs[1].name, "member_511");
        assert!(member_specs_for_slots(&[512]).is_err());
        assert!(member_specs_for_slots(&[]).is_err());
        // Every slot resolves to its baked name (no off-by-one
        // in the frozen table index).
        for j in [0u32, 9, 10, 56, 255, 511] {
            let specs = member_specs_for_slots(&[j]).unwrap();
            assert_eq!(specs[1].name, MEMBER_PROGS[1 + j as usize].name);
        }
    }

    #[test]
    fn trim_nul_strips_padding_only() {
        assert_eq!(trim_nul(b"abc\0\0"), b"abc");
        assert_eq!(trim_nul(b"abc"), b"abc");
        assert_eq!(trim_nul(b"\0\0"), b"");
        assert_eq!(trim_nul(b""), b"");
        assert_eq!(trim_nul(b"a\0b\0"), b"a\0b");
    }

    #[test]
    fn verifier_spill_round_trips_full_log() {
        let body = vec![b'v'; 300_000];
        let path = spill_verifier_log("query_return", &body).unwrap();
        let back = std::fs::read(&path).unwrap();
        assert_eq!(back, body);
        assert!(path.to_string_lossy().contains("query_return"));
        std::fs::remove_file(&path).ok();
        // Hostile prog names cannot escape the temp dir.
        let evil = spill_verifier_log("../../x", b"e").unwrap();
        assert!(
            evil.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("osslscope-verifier-")
        );
        std::fs::remove_file(&evil).ok();
    }

    fn call_insn(src_pseudo: bool, imm: i32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = BPF_CALL;
        b[1] = if src_pseudo { BPF_PSEUDO_CALL << 4 } else { 0 };
        b[4..8].copy_from_slice(&imm.to_le_bytes());
        b
    }

    #[test]
    fn stale_static_calls_fail_closed() {
        let exit = [0x95u8, 0, 0, 0, 0, 0, 0, 0];
        let helper = call_insn(false, 14);
        let pseudo = call_insn(true, 205);
        let img = |insns: &[&[u8; 8]]| {
            let mut v = Vec::new();
            for i in insns {
                v.extend_from_slice(*i);
            }
            v
        };
        // Helper calls need no reloc.
        let ok = img(&[&helper, &exit]);
        check_calls_rewritten(&ok, &HashSet::new(), "p").unwrap();
        // Rewritten pseudo-calls pass.
        let ok = img(&[&pseudo, &exit]);
        check_calls_rewritten(&ok, &[0usize].into_iter().collect(), "p").unwrap();
        // Unrewritten pseudo-calls fail, naming the insn.
        let bad = img(&[&pseudo, &exit]);
        let e = check_calls_rewritten(&bad, &HashSet::new(), "p").unwrap_err();
        assert!(
            e.to_string().contains("unrelocated static call at insn 0"),
            "{e:#}"
        );
        // A rewritten set covering the wrong offset does not help.
        let bad = img(&[&exit, &pseudo]);
        let e = check_calls_rewritten(&bad, &[0usize].into_iter().collect(), "p").unwrap_err();
        assert!(
            e.to_string().contains("unrelocated static call at insn 1"),
            "{e:#}"
        );
        // Ragged images fail rather than scan short.
        let e = check_calls_rewritten(&[0u8; 7], &HashSet::new(), "p").unwrap_err();
        assert!(e.to_string().contains("not a whole count"), "{e:#}");
    }

    /// Minimal BPF relocatable: 1 uprobe prog (ld_map/call/exit),
    /// .text sub (ld_map/exit), 1 map def, relocs for all three.
    /// Layout (offsets): ehdr 0/64, uprobe 64/32, .text 96/24, maps
    /// 120/28, .reluprobe 148/32, .rel.text 180/16, symtab 196/96,
    /// strtab 292/26, shstrtab 320/62, shdrs 384/576.
    fn min_elf() -> Vec<u8> {
        let mut b = vec![0u8; 392 + 9 * 64];
        // ELF header.
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // 64-bit
        b[5] = 1; // LE
        b[6] = 1; // version
        b[16..18].copy_from_slice(&u16(1)); // ET_REL
        b[18..20].copy_from_slice(&u16(247)); // EM_BPF
        b[40..48].copy_from_slice(&u64(392)); // shoff
        b[58..60].copy_from_slice(&u16(64)); // shentsize
        b[60..62].copy_from_slice(&u16(9)); // shnum
        b[62..64].copy_from_slice(&u16(8)); // shstrndx
        // uprobe: ld_imm64 r1,map + call + exit.
        b[64..80].copy_from_slice(&[0x18, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[80..88].copy_from_slice(&[0x85, 0x10, 0, 0, 0, 0, 0, 0]);
        b[88..96].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // .text: ld_imm64 r1,map + exit.
        b[96..112].copy_from_slice(&[0x18, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[112..120].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // maps: ARRAY u32->u64 max 1.
        for (i, v) in [2u32, 4, 8, 1, 0, 0, 0].iter().enumerate() {
            b[120 + i * 4..124 + i * 4].copy_from_slice(&u32(*v));
        }
        // .reluprobe: map ref @0 (sym 3), call @16 (sym 2).
        b[148..156].copy_from_slice(&u64(0));
        b[156..164].copy_from_slice(&u64(3 << 32 | 1));
        b[164..172].copy_from_slice(&u64(16));
        b[172..180].copy_from_slice(&u64(2 << 32 | 10));
        // .rel.text: map ref @0 (sym 3).
        b[180..188].copy_from_slice(&u64(0));
        b[188..196].copy_from_slice(&u64(3 << 32 | 1));
        // symtab: null, uprobe_func, memsub, MYMAP.
        let mut sym = |o: usize, name: u32, info: u8, shndx: u16, val: u64, size: u64| {
            b[o..o + 4].copy_from_slice(&u32(name));
            b[o + 4] = info;
            b[o + 6..o + 8].copy_from_slice(&u16(shndx));
            b[o + 8..o + 16].copy_from_slice(&u64(val));
            b[o + 16..o + 24].copy_from_slice(&u64(size));
        };
        sym(196, 0, 0, 0, 0, 0);
        sym(220, 1, 0x12, 1, 0, 32);
        sym(244, 13, 0x12, 2, 0, 24);
        sym(268, 20, 0x11, 3, 0, 28);
        // strtab.
        let s = b"\0uprobe_func\0memsub\0MYMAP\0";
        b[292..292 + s.len()].copy_from_slice(s);
        // shstrtab.
        let t = b"\0uprobe\0.text\0maps\0.reluprobe\0.rel.text\0.symtab\0.strtab\0.shstrtab\0";
        b[320..320 + t.len()].copy_from_slice(t);
        // Section headers: null, uprobe, .text, maps, .reluprobe,
        // .rel.text, symtab, strtab, shstrtab.
        let mut sh = |i: usize,
                      name: u32,
                      ty: u32,
                      flags: u64,
                      off: u64,
                      size: u64,
                      link: u32,
                      info: u32,
                      entsize: u64| {
            let o = 392 + i * 64;
            b[o..o + 4].copy_from_slice(&u32(name));
            b[o + 4..o + 8].copy_from_slice(&u32(ty));
            b[o + 8..o + 16].copy_from_slice(&u64(flags));
            b[o + 24..o + 32].copy_from_slice(&u64(off));
            b[o + 32..o + 40].copy_from_slice(&u64(size));
            b[o + 40..o + 44].copy_from_slice(&u32(link));
            b[o + 44..o + 48].copy_from_slice(&u32(info));
            b[o + 48..o + 56].copy_from_slice(&u64(8));
            b[o + 56..o + 64].copy_from_slice(&u64(entsize));
        };
        sh(0, 0, 0, 0, 0, 0, 0, 0, 0);
        sh(1, 1, 1, 6, 64, 32, 0, 0, 0);
        sh(2, 8, 1, 6, 96, 24, 0, 0, 0);
        sh(3, 14, 1, 3, 120, 28, 0, 0, 0);
        sh(4, 19, 9, 0, 148, 32, 6, 1, 16);
        sh(5, 30, 9, 0, 180, 16, 6, 2, 16);
        sh(6, 40, 2, 0, 196, 96, 7, 1, 24);
        sh(7, 48, 3, 0, 292, 26, 0, 0, 0);
        sh(8, 56, 3, 0, 320, 65, 0, 0, 0);
        b
    }

    /// Key offsets into [`mixed_elf`] for tests that patch it (the
    /// builder lays out sequentially, so tests take offsets from
    /// here instead of duplicating the layout).
    struct MixedLayout {
        symtab_off: usize,
        reltext_off: usize,
        cb_name_off: u32,
    }

    /// Mixed callback graph: main calls `wrap` (static), `wrap`
    /// takes `cb`'s address (func-ptr, backward over `dead`), `cb`
    /// bumps the map and calls `helper` (static, forward over
    /// `dead`+`wrap`), and `dead` is unreferenced between `cb` and
    /// `wrap` so its exclusion shifts linked offsets. `.text`
    /// order: cb @0/24, dead @24/8, wrap @32/16, helper @48/8;
    /// main is 16B (`call` + `exit`). Syms: null, main, cb, dead,
    /// wrap, helper, MYMAP.
    fn mixed_elf() -> (Vec<u8>, MixedLayout) {
        let uprobe_off = 64usize;
        let text_off = uprobe_off + 16;
        let maps_off = text_off + 56;
        let reluprobe_off = maps_off + 28;
        let reltext_off = reluprobe_off + 16;
        let symtab_off = reltext_off + 48;
        let strtab_off = symtab_off + 7 * 24;
        let strtab: &[u8] = b"\0main\0cb\0dead\0wrap\0helper\0MYMAP\0";
        // Name offsets into strtab: main=1, cb=6, dead=9, wrap=14,
        // helper=19, MYMAP=26.
        let shstrtab_off = strtab_off + strtab.len();
        let shstr: &[u8] =
            b"\0uprobe\0.text\0maps\0.reluprobe\0.rel.text\0.symtab\0.strtab\0.shstrtab\0";
        let shoff = (shstrtab_off + shstr.len() + 7) & !7;
        let mut b = vec![0u8; shoff + 9 * 64];
        // ELF header.
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&u16(1));
        b[18..20].copy_from_slice(&u16(247));
        b[40..48].copy_from_slice(&u64(shoff as u64));
        b[58..60].copy_from_slice(&u16(64));
        b[60..62].copy_from_slice(&u16(9));
        b[62..64].copy_from_slice(&u16(8));
        // uprobe main: pseudo-call + exit.
        b[uprobe_off..uprobe_off + 8].copy_from_slice(&[0x85, 0x10, 0, 0, 0, 0, 0, 0]);
        b[uprobe_off + 8..uprobe_off + 16].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // .text cb: ld_imm64 r1,map + call.
        b[text_off..text_off + 16]
            .copy_from_slice(&[0x18, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[text_off + 16..text_off + 24].copy_from_slice(&[0x85, 0x10, 0, 0, 0, 0, 0, 0]);
        // .text dead: exit (unreferenced).
        b[text_off + 24..text_off + 32].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // .text wrap: ld_imm64 r2,cb.
        b[text_off + 32..text_off + 48]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // .text helper: exit.
        b[text_off + 48..text_off + 56].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // maps: ARRAY u32->u64 max 1.
        for (i, v) in [2u32, 4, 8, 1, 0, 0, 0].iter().enumerate() {
            b[maps_off + i * 4..maps_off + i * 4 + 4].copy_from_slice(&u32(*v));
        }
        // .reluprobe: call @0 (sym 4 = wrap).
        b[reluprobe_off..reluprobe_off + 8].copy_from_slice(&u64(0));
        b[reluprobe_off + 8..reluprobe_off + 16].copy_from_slice(&u64(4 << 32 | 10));
        // .rel.text: map @0 (sym 6), call @16 (sym 5 = helper),
        // func @32 (sym 2 = cb).
        b[reltext_off..reltext_off + 8].copy_from_slice(&u64(0));
        b[reltext_off + 8..reltext_off + 16].copy_from_slice(&u64(6 << 32 | 1));
        b[reltext_off + 16..reltext_off + 24].copy_from_slice(&u64(16));
        b[reltext_off + 24..reltext_off + 32].copy_from_slice(&u64(5 << 32 | 10));
        b[reltext_off + 32..reltext_off + 40].copy_from_slice(&u64(32));
        b[reltext_off + 40..reltext_off + 48].copy_from_slice(&u64(2 << 32 | 1));
        // symtab.
        let mut sym = |o: usize, name: u32, info: u8, shndx: u16, val: u64, size: u64| {
            b[o..o + 4].copy_from_slice(&u32(name));
            b[o + 4] = info;
            b[o + 6..o + 8].copy_from_slice(&u16(shndx));
            b[o + 8..o + 16].copy_from_slice(&u64(val));
            b[o + 16..o + 24].copy_from_slice(&u64(size));
        };
        sym(symtab_off, 0, 0, 0, 0, 0);
        sym(symtab_off + 24, 1, 0x12, 1, 0, 16);
        sym(symtab_off + 48, 6, 0x12, 2, 0, 24);
        sym(symtab_off + 72, 9, 0x12, 2, 24, 8);
        sym(symtab_off + 96, 14, 0x12, 2, 32, 16);
        sym(symtab_off + 120, 19, 0x12, 2, 48, 8);
        sym(symtab_off + 144, 26, 0x11, 3, 0, 28);
        b[strtab_off..strtab_off + strtab.len()].copy_from_slice(strtab);
        b[shstrtab_off..shstrtab_off + shstr.len()].copy_from_slice(shstr);
        // Section headers: null, uprobe, .text, maps, .reluprobe,
        // .rel.text, symtab, strtab, shstrtab.
        let mut sh = |i: usize,
                      name: u32,
                      ty: u32,
                      flags: u64,
                      off: u64,
                      size: u64,
                      link: u32,
                      info: u32,
                      entsize: u64| {
            let o = shoff + i * 64;
            b[o..o + 4].copy_from_slice(&u32(name));
            b[o + 4..o + 8].copy_from_slice(&u32(ty));
            b[o + 8..o + 16].copy_from_slice(&u64(flags));
            b[o + 24..o + 32].copy_from_slice(&u64(off));
            b[o + 32..o + 40].copy_from_slice(&u64(size));
            b[o + 40..o + 44].copy_from_slice(&u32(link));
            b[o + 44..o + 48].copy_from_slice(&u32(info));
            b[o + 48..o + 56].copy_from_slice(&u64(8));
            b[o + 56..o + 64].copy_from_slice(&u64(entsize));
        };
        sh(0, 0, 0, 0, 0, 0, 0, 0, 0);
        sh(1, 1, 1, 6, uprobe_off as u64, 16, 0, 0, 0);
        sh(2, 8, 1, 6, text_off as u64, 56, 0, 0, 0);
        sh(3, 14, 1, 3, maps_off as u64, 28, 0, 0, 0);
        sh(4, 19, 9, 0, reluprobe_off as u64, 16, 6, 1, 16);
        sh(5, 30, 9, 0, reltext_off as u64, 48, 6, 2, 16);
        sh(6, 40, 2, 0, symtab_off as u64, 168, 7, 1, 24);
        sh(7, 48, 3, 0, strtab_off as u64, strtab.len() as u64, 0, 0, 0);
        sh(
            8,
            56,
            3,
            0,
            shstrtab_off as u64,
            shstr.len() as u64,
            0,
            0,
            0,
        );
        (
            b,
            MixedLayout {
                symtab_off,
                reltext_off,
                cb_name_off: 6,
            },
        )
    }

    #[test]
    fn prepare_links_mixed_callback_graph() {
        // main -call-> wrap -funcptr-> cb -call-> helper, with
        // `dead` unreferenced between cb and wrap: linked layout is
        // main(16) + cb(24) + wrap(16) + helper(8) = 64B, and the
        // func-ptr imm goes negative (backward over dead).
        let (obj, _) = mixed_elf();
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "main",
                section: "uprobe",
            }],
        )
        .unwrap();
        let p = &prep.progs[0];
        assert_eq!(p.insns.len(), 64);
        let subs: Vec<(&str, u32, bool)> = p
            .subprogs
            .iter()
            .map(|s| (s.name.as_str(), s.insn_off, s.is_callback))
            .collect();
        assert_eq!(
            subs,
            vec![
                ("main", 0, false),
                ("cb", 2, true),
                ("wrap", 5, false),
                ("helper", 7, false),
            ]
        );
        // main call @0 -> wrap @5insns: PSEUDO_CALL nibble +
        // imm = 5-0-1.
        assert_eq!(p.insns[1], 0x10);
        assert_eq!(&p.insns[4..8], &4i32.to_le_bytes());
        // wrap func site @40 -> cb @2insns: dst r2 + PSEUDO_FUNC,
        // imm = 2-5-1 (backward).
        assert_eq!(p.insns[41], 0x02 | (BPF_PSEUDO_FUNC << 4));
        assert_eq!(&p.insns[44..48], &(-4i32).to_le_bytes());
        // cb call @32 -> helper @7insns: PSEUDO_CALL nibble +
        // imm = 7-4-1.
        assert_eq!(p.insns[33], 0x10);
        assert_eq!(&p.insns[36..40], &2i32.to_le_bytes());
        // One map fixup: cb's site at linked offset 16.
        assert_eq!(p.map_fixups.len(), 1);
        assert_eq!(p.map_fixups[0].insn_off, 16);
        assert_eq!(p.map_fixups[0].map, "MYMAP");
        // `dead` is excluded: the subprog offs already prove
        // compaction (helper sits 8B below its naive .text+main
        // position), and every unpatched image byte matches its
        // source — only the three asserted reloc sites differ.
        let text = &obj[80..136];
        assert_eq!(&p.insns[0..4], &obj[64..68]);
        assert_eq!(&p.insns[8..16], &obj[72..80]);
        assert_eq!(&p.insns[16..36], &text[0..20]);
        assert_eq!(p.insns[40], text[32]);
        assert_eq!(&p.insns[48..56], &text[40..48]);
        assert_eq!(&p.insns[56..64], &text[48..56]);
    }

    #[test]
    fn prepare_rejects_duplicate_targeting_second() {
        // Strengthened dup regression: valid main intact, two `cb`
        // bodies with distinct bytes at different offsets (0 and
        // 48), and the func-ptr reloc repointed at the SECOND.
        // Name-only linking would resolve (48, "cb") but link the
        // first body with agreeing func_info — silent substitution.
        let (mut obj, layout) = mixed_elf();
        // Rename helper (sym 5) to "cb".
        obj[layout.symtab_off + 5 * 24..layout.symtab_off + 5 * 24 + 4]
            .copy_from_slice(&u32(layout.cb_name_off));
        // Repoint the func-ptr reloc (3rd .rel.text entry) at sym 5.
        obj[layout.reltext_off + 2 * 16 + 8..layout.reltext_off + 2 * 16 + 16]
            .copy_from_slice(&u64(5 << 32 | 1));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "main",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("duplicate"), "{e:#}");
    }

    #[test]
    fn prepare_patches_calls_and_records_map_fixups() {
        let obj = min_elf();
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        assert_eq!(prep.progs.len(), 1);
        let p = &prep.progs[0];
        // main (32B) + .text (24B).
        assert_eq!(p.insns.len(), 56);
        // Two map fixups: main @0, text @32.
        assert_eq!(p.map_fixups.len(), 2);
        assert_eq!(p.map_fixups[0].insn_off, 0);
        assert_eq!(p.map_fixups[1].insn_off, 32);
        // Call @16: target=(32+0)/8=4, pc=2 → imm=1.
        assert_eq!(&p.insns[20..24], &1i32.to_le_bytes());
        // Map-def dims confirmed.
        assert_eq!(prep.maps[0].max_entries, 1);
    }

    #[test]
    fn prepare_rewrites_func_pointers_pseudo() {
        // The uprobe call site @16 becomes an ld_imm64 of the sub's
        // address (the `bpf_loop` callback shape): the linked site
        // takes the relative imm plus the PSEUDO_FUNC src nibble.
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        let p = &prep.progs[0];
        assert_eq!(p.insns.len(), 56);
        // Dst reg preserved, src nibble PSEUDO_FUNC, imm = 4-2-1 = 1.
        assert_eq!(p.insns[17], 0x02 | (BPF_PSEUDO_FUNC << 4));
        assert_eq!(&p.insns[20..24], &1i32.to_le_bytes());
        // High half untouched.
        assert_eq!(&p.insns[24..32], &[0u8; 8]);
    }

    #[test]
    fn prepare_rejects_duplicate_text_names() {
        // Two `.text` FUNCs sharing a name would resolve by value
        // but link by first-name-match (silent substitution), so
        // the loader rejects the shape outright. Repurpose sym1 as
        // a second `memsub` FUNC in `.text` (the dup check fires
        // before per-prog validation, so the missing uprobe sym
        // never masks it).
        let mut obj = min_elf();
        obj[220..224].copy_from_slice(&u32(13)); // name "memsub"
        obj[226..228].copy_from_slice(&u16(2)); // shndx .text
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("duplicate"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_bad_func_pointers() {
        let spec = || {
            (
                vec![MapSpec {
                    name: "MYMAP",
                    map_type: 2,
                    key_size: 4,
                    value_size: 8,
                    max_entries: 1,
                    flags: 0,
                }],
                vec![ProgSpec {
                    name: "uprobe_func",
                    section: "uprobe",
                }],
            )
        };
        // Func reloc against a non-.text FUNC (the prog itself).
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(1 << 32 | 1));
        let (maps, progs) = spec();
        let e = prepare(&obj, &maps, &progs).err().expect("must fail");
        assert!(e.to_string().contains("non-entry"), "{e:#}");
        // Func reloc against a non-ld_imm64 site (the call shape).
        let mut obj = min_elf();
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let (maps, progs) = spec();
        let e = prepare(&obj, &maps, &progs).err().expect("must fail");
        assert!(e.to_string().contains("non-ld_imm64"), "{e:#}");
        // Func reloc against an already-relocated site (nonzero imm).
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let (maps, progs) = spec();
        let e = prepare(&obj, &maps, &progs).err().expect("must fail");
        assert!(e.to_string().contains("relocated site"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_misaligned_func_site() {
        // A func-ptr reloc at misaligned @12 whose straddling bytes
        // decode as a valid unrelocated ld_imm64: start-only
        // ownership plus shape checks would link it.
        let mut obj = min_elf();
        obj[164..172].copy_from_slice(&u64(12));
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        obj[64 + 12] = 0x18;
        obj[64 + 13] = 0x02;
        obj[64 + 16..64 + 28].fill(0);
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // The resolver fires first (roots resolve before apply).
        assert!(
            e.to_string().contains("func reloc site misaligned"),
            "{e:#}"
        );
    }

    #[test]
    fn prepare_rejects_func_site_crossing_fn_end() {
        // The site start is owned but its 16 bytes cross the
        // function's end (shrunk to 16): resolving from the whole
        // section would use sibling bytes.
        let mut obj = min_elf();
        obj[236..244].copy_from_slice(&u64(16));
        obj[164..172].copy_from_slice(&u64(8));
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        obj[64 + 8] = 0x18;
        obj[64 + 9] = 0x02;
        obj[64 + 16..64 + 24].fill(0);
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("crosses"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_helper_call_with_reloc() {
        // A call reloc on a helper-form call (src 0, not
        // PSEUDO_CALL): linking would rewrite the helper id into a
        // relative target — a silent semantic change. Pin the
        // helper-form byte explicitly (min_elf itself emits
        // PSEUDO_CALL).
        let mut obj = min_elf();
        obj[81] = 0x00;
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("helper call"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_misaligned_call_site() {
        // A call reloc at misaligned @18 whose straddling bytes
        // start with a CALL opcode: shape checks alone would link it.
        let mut obj = min_elf();
        obj[164..172].copy_from_slice(&u64(18));
        obj[64 + 18] = 0x85;
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("misalign"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_func_site_reserved_bytes() {
        // An otherwise valid func-ptr site with the first slot's
        // reserved offset bytes set.
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("reserved"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_misaligned_text_value() {
        // A `.text` entry at a misaligned value would link a
        // mid-instruction slice.
        let mut obj = min_elf();
        obj[252..260].copy_from_slice(&u64(4));
        obj[260..268].copy_from_slice(&u64(8));
        obj[180..188].copy_from_slice(&u64(4));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("misalign"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_misaligned_prog_value() {
        // A prog entry at a misaligned value would link a
        // mid-instruction main.
        let mut obj = min_elf();
        obj[228..236].copy_from_slice(&u64(4));
        obj[236..244].copy_from_slice(&u64(24));
        obj[148..156].copy_from_slice(&u64(8));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("misalign"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_map_site_crossing_fn_end() {
        // Map sites are `ld_imm64` too (16 bytes): a map reloc at
        // @24 in a 32-byte function crosses the end.
        let mut obj = min_elf();
        obj[148..156].copy_from_slice(&u64(24));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("crosses"), "{e:#}");
    }

    #[test]
    fn prepare_accepts_call_site_at_exact_fit() {
        // An 8-byte call site ending exactly at the function end is
        // contained (pins the call width against the 16-byte
        // `ld_imm64` width).
        let mut obj = min_elf();
        obj[164..172].copy_from_slice(&u64(24));
        obj[64 + 24] = 0x85;
        obj[64 + 25] = 0x10;
        // The reloc moved: clear the stale call bytes (an unowned
        // pseudo-call is drift and must not linger).
        obj[64 + 16..64 + 24].fill(0);
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        assert_eq!(prep.progs[0].insns.len(), 56);
    }

    #[test]
    fn prepare_rejects_misaligned_map_site() {
        // Map reloc at misaligned @4 (contained: 4+16=20 <= 32):
        // map arms must enforce alignment like call/func sites.
        let mut obj = min_elf();
        obj[148..156].copy_from_slice(&u64(4));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // Exact phrase: proves the map arm fired (not another check).
        assert!(e.to_string().contains("map site misaligned"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_map_site_reserved_bytes() {
        // Main map site with the first slot's reserved offset bytes
        // set: map arms must check them like func sites.
        let mut obj = min_elf();
        obj[64 + 2] = 1;
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // Exact phrase: proves the map arm fired (not another check).
        assert!(
            e.to_string().contains("map site reserved bytes set"),
            "{e:#}"
        );
    }

    #[test]
    fn prepare_rejects_misaligned_text_map_site() {
        // `.text` map reloc at misaligned @4 (contained in memsub):
        // the apply-loop map arm must enforce alignment.
        let mut obj = min_elf();
        obj[180..188].copy_from_slice(&u64(4));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // Exact phrase: proves the apply-loop map arm fired.
        assert!(e.to_string().contains("map site misaligned"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_text_map_site_reserved_bytes() {
        // `.text` map site with reserved offset bytes set: the
        // apply-loop map arm must check them.
        let mut obj = min_elf();
        obj[96 + 2] = 1;
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // Exact phrase: proves the apply-loop map arm fired.
        assert!(
            e.to_string().contains("map site reserved bytes set"),
            "{e:#}"
        );
    }

    #[test]
    fn load_rejects_huge_fixup_off_caps_free() {
        // `Prepared` fields are public: a hand-built fixup at
        // `MAX-7` (aligned) must ERR, not panic on `off + 8`
        // overflow in debug. No maps: the validator bails before
        // any fd use, so no caps are needed.
        let prep = Prepared {
            maps: Vec::new(),
            progs: vec![PreparedProg {
                name: "p".to_string(),
                is_return: false,
                insns: vec![0u8; 32],
                map_fixups: vec![MapFixup {
                    insn_off: usize::MAX - 7,
                    map: "NOPE".to_string(),
                }],
                subprogs: vec![SubprogInfo {
                    name: "p".to_string(),
                    insn_off: 0,
                    is_callback: false,
                }],
            }],
        };
        let e = load(&prep).err().expect("must fail");
        assert!(e.to_string().contains("out of range"), "{e:#}");
    }

    #[test]
    fn check_ld_imm64_site_rejects_huge_off() {
        // Aligned `MAX-15`: `off + 16` overflows — must ERR, not
        // panic in debug.
        let e = check_ld_imm64_site(&[0u8; 32], usize::MAX - 15, "p").unwrap_err();
        assert!(e.to_string().contains("out of range"), "{e:#}");
    }

    #[test]
    fn check_site_contained_rejects_offset_overflow() {
        // All current callers pre-constrain the offset via
        // ownership filters; this pins the fail-closed contract
        // for future callers (without the checked add this input
        // panics in debug / wraps in release).
        let e = check_site_contained(usize::MAX, 16, 32, "f", "p").unwrap_err();
        assert!(e.to_string().contains("site out of range"), "{e:#}");
    }

    #[test]
    fn apply_call_rejects_misaligned_site() {
        // Unreachable via `prepare` (reloc offset and prog value
        // are both aligned there); pinned directly.
        let mut insns = vec![0u8; 16];
        let e = apply_call(&mut insns, 4, 8, "t").err().expect("must fail");
        assert!(e.to_string().contains("call site misaligned"), "{e:#}");
    }

    #[test]
    fn apply_func_ptr_rejects_misaligned_site() {
        let mut insns = vec![0u8; 24];
        insns[4] = 0x18;
        insns[5] = 0x02;
        let before = insns.clone();
        let e = apply_func_ptr(&mut insns, 4, 16, "t")
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("misalign"), "{e:#}");
        assert_eq!(insns, before, "no mutation on failure");
    }

    #[test]
    fn apply_func_ptr_rejects_reserved_bytes() {
        let mut insns = vec![0u8; 16];
        insns[0] = 0x18;
        insns[1] = 0x02;
        insns[2] = 1;
        let before = insns.clone();
        let e = apply_func_ptr(&mut insns, 0, 8, "t")
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("reserved"), "{e:#}");
        assert_eq!(insns, before, "no mutation on failure");
    }

    #[test]
    fn stale_func_pointers_fail_closed() {
        let exit = [0x95u8, 0, 0, 0, 0, 0, 0, 0];
        let zeros = [0u8; 8];
        // A PSEUDO_FUNC site without a rewrite record fails, naming
        // the insn; map sites (src 0) are ignored here.
        let mut bad = Vec::new();
        bad.extend_from_slice(&[0x18, 0x02 | (BPF_PSEUDO_FUNC << 4), 0, 0, 1, 0, 0, 0]);
        bad.extend_from_slice(&zeros);
        bad.extend_from_slice(&exit);
        let e = check_func_ptrs_rewritten(&bad, &HashSet::new(), "p").unwrap_err();
        assert!(
            e.to_string()
                .contains("unrelocated function pointer at insn 0"),
            "{e:#}"
        );
        let mut ok = Vec::new();
        ok.extend_from_slice(&[0x18, 0x02 | (BPF_PSEUDO_FUNC << 4), 0, 0, 1, 0, 0, 0]);
        ok.extend_from_slice(&zeros);
        ok.extend_from_slice(&exit);
        check_func_ptrs_rewritten(&ok, &[0usize].into_iter().collect(), "p").unwrap();
        // The second slot's bytes are not opcodes: 0x85 there must
        // not scan as a call (and 0x18 there must not recurse).
        let mut second = Vec::new();
        second.extend_from_slice(&[0x18, 0x01, 0, 0, 0, 0, 0, 0]);
        second.extend_from_slice(&[0x85, 0x10, 0, 0, 0, 0, 0, 0]);
        second.extend_from_slice(&exit);
        check_func_ptrs_rewritten(&second, &HashSet::new(), "p").unwrap();
        // Ragged images fail rather than scan short.
        let e = check_func_ptrs_rewritten(&[0u8; 7], &HashSet::new(), "p").unwrap_err();
        assert!(e.to_string().contains("not a whole count"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_dim_mismatch_and_missing_syms() {
        let obj = min_elf();
        let r = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 999,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        );
        assert!(r.is_err());
        let r = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "nope",
                section: "uprobe",
            }],
        );
        assert!(r.is_err());
    }

    /// Minimal BTF walker for synthesis tests: parses the header,
    /// walks the type section by (kind, vlen), splits the string
    /// section. Returns (types, strings) where each type is
    /// (kind, name, size_or_type, payload words).
    fn walk_btf(btf: &[u8]) -> (Vec<(u32, u32, u32, Vec<u32>)>, Vec<Vec<u8>>) {
        assert!(btf.len() >= 24, "btf shorter than header");
        let u16le = |o: usize| u16::from_le_bytes([btf[o], btf[o + 1]]) as u32;
        let u32le = |o: usize| u32::from_le_bytes([btf[o], btf[o + 1], btf[o + 2], btf[o + 3]]);
        assert_eq!(u16le(0), 0xEB9F, "bad magic");
        assert_eq!(btf[2], 1, "bad version");
        // Header layout: magic(0:2) version(2) flags(3) hdr_len(4:8)
        // type_off(8:12) type_len(12:16) str_off(16:20) str_len(20:24).
        let hdr_len = u32le(4) as usize;
        let type_off = hdr_len + u32le(8) as usize;
        let type_len = u32le(12) as usize;
        let str_off = hdr_len + u32le(16) as usize;
        let str_len = u32le(20) as usize;
        assert!(type_off + type_len <= btf.len(), "type section overrun");
        assert!(str_off + str_len <= btf.len(), "string section overrun");
        let mut types = Vec::new();
        let mut o = type_off;
        while o < type_off + type_len {
            let name = u32le(o);
            let info = u32le(o + 4);
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let size_or_type = u32le(o + 8);
            o += 12;
            let words = match kind {
                1 => {
                    // INT: one data word.
                    let w = vec![u32le(o)];
                    o += 4;
                    w
                }
                2 => {
                    // PTR: no payload.
                    assert_eq!(vlen, 0, "ptr with vlen");
                    Vec::new()
                }
                4 => {
                    // STRUCT members: vlen triples.
                    let mut w = Vec::new();
                    for _ in 0..vlen {
                        w.push(u32le(o));
                        w.push(u32le(o + 4));
                        w.push(u32le(o + 8));
                        o += 12;
                    }
                    w
                }
                12 | 13 => {
                    // FUNC (vlen 0) / FUNC_PROTO params: vlen pairs.
                    let mut w = Vec::new();
                    for _ in 0..vlen {
                        w.push(u32le(o));
                        w.push(u32le(o + 4));
                        o += 8;
                    }
                    w
                }
                _ => panic!("unexpected kind {kind} in synthesized btf"),
            };
            types.push((kind, name, size_or_type, words));
        }
        let strings: Vec<Vec<u8>> = btf[str_off..str_off + str_len]
            .split(|b| *b == 0)
            .map(|s| s.to_vec())
            .collect();
        (types, strings)
    }

    #[test]
    fn synth_btf_callback_shape_layout() {
        // main @0 + one callback @24: fixed type prefix (INT u64,
        // INT u32, STRUCT ctx, PTR, main proto, callback proto,
        // static proto) plus one FUNC per subprog; func_info maps
        // insn offsets to the matching FUNC ids.
        let (btf, info) = synth_btf(&[
            SubprogInfo {
                name: "main".into(),
                insn_off: 0,
                is_callback: false,
            },
            SubprogInfo {
                name: "cb".into(),
                insn_off: 24,
                is_callback: true,
            },
        ])
        .unwrap();
        assert_eq!(info, vec![(0u32, 8u32), (24u32, 9u32)]);
        let (types, strings) = walk_btf(&btf);
        assert_eq!(types.len(), 9, "7 prefix + 2 funcs");
        // Kinds: INT=1, PTR=2, STRUCT=4, FUNC_PROTO=13, FUNC=12.
        let kinds: Vec<u32> = types.iter().map(|t| t.0).collect();
        assert_eq!(kinds, vec![1, 1, 4, 2, 13, 13, 13, 12, 12]);
        // INT widths.
        assert_eq!((types[0].2, types[0].3[0]), (8, 64));
        assert_eq!((types[1].2, types[1].3[0]), (4, 32));
        // STRUCT ctx { u64 pad; } + PTR to it.
        assert_eq!(types[2].2, 8);
        assert_eq!(types[2].3.len(), 3);
        assert_eq!(types[3].2, 3);
        // Main proto: u32 <- (ctx *arg0). Callback proto with named
        // params. Params are (name_off, type) pairs per
        // uapi/linux/btf.h.
        assert_eq!(types[4].2, 2);
        assert_eq!(types[4].3.len(), 2);
        assert_eq!(types[4].3[1], 4);
        assert_eq!(types[5].2, 1);
        assert_eq!(types[5].3.len(), 4);
        assert_eq!((types[5].3[1], types[5].3[3]), (1, 1));
        // Static proto: void <- ().
        assert_eq!((types[6].2, types[6].3.len()), (0, 0));
        // FUNCs bind the right protos.
        assert_eq!((types[7].2, types[8].2), (5, 6));
        // Names resolve in the string section.
        let s = |off: u32| {
            // String offsets are relative to the string section; find
            // it via the header (hdr_len 24 + str_off field).
            let base = 24 + u32::from_le_bytes([btf[16], btf[17], btf[18], btf[19]]) as usize;
            let mut end = base + off as usize;
            while btf[end] != 0 {
                end += 1;
            }
            std::str::from_utf8(&btf[base + off as usize..end])
                .unwrap()
                .to_string()
        };
        assert_eq!(s(types[0].1), "__u64");
        assert_eq!(s(types[1].1), "__u32");
        assert_eq!(s(types[2].1), "ctx");
        assert_eq!(s(types[2].3[0]), "pad");
        assert_eq!(s(types[4].3[0]), "arg0");
        assert_eq!(s(types[5].3[0]), "index");
        assert_eq!(s(types[5].3[2]), "cctx");
        assert_eq!(s(types[7].1), "main");
        assert_eq!(s(types[8].1), "cb");
        // String section is NUL-separated with a leading empty entry.
        assert_eq!(strings[0], b"");
        let joined = strings.concat();
        for want in [
            b"__u64".as_slice(),
            b"__u32",
            b"ctx",
            b"pad",
            b"arg0",
            b"index",
            b"cctx",
            b"main",
            b"cb",
        ] {
            assert!(
                joined.windows(want.len()).any(|w| w == want),
                "missing {want:?}"
            );
        }
    }

    #[test]
    fn prepare_records_subprog_table() {
        // Plain static-call shape: main + one static callee, no
        // callbacks — the table still records (main @0, callee @4).
        let obj = min_elf();
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        let subs: Vec<(String, u32, bool)> = prep.progs[0]
            .subprogs
            .iter()
            .map(|s| (s.name.clone(), s.insn_off, s.is_callback))
            .collect();
        assert_eq!(
            subs,
            vec![
                ("uprobe_func".to_string(), 0, false),
                ("memsub".to_string(), 4, false),
            ]
        );
        // Function-pointer shape: the reloc target is a callback.
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        let subs: Vec<(String, u32, bool)> = prep.progs[0]
            .subprogs
            .iter()
            .map(|s| (s.name.clone(), s.insn_off, s.is_callback))
            .collect();
        assert_eq!(
            subs,
            vec![
                ("uprobe_func".to_string(), 0, false),
                ("memsub".to_string(), 4, true),
            ]
        );
    }

    #[test]
    fn synth_btf_rejects_bad_inputs() {
        let sub = |name: &str, off: u32, cb: bool| SubprogInfo {
            name: name.into(),
            insn_off: off,
            is_callback: cb,
        };
        // Empty: no main.
        let e = synth_btf(&[]).err().expect("must fail");
        assert!(e.to_string().contains("no subprograms"), "{e:#}");
        // First offset must be 0 (main).
        let e = synth_btf(&[sub("main", 8, false)])
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("main at 0"), "{e:#}");
        // Offsets strictly increasing.
        let e = synth_btf(&[sub("main", 0, false), sub("cb", 0, true)])
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("increasing"), "{e:#}");
        // Empty name.
        let e = synth_btf(&[sub("", 0, false)]).err().expect("must fail");
        assert!(e.to_string().contains("empty name"), "{e:#}");
        // NUL in name would corrupt the string section.
        let e = synth_btf(&[sub("a\0b", 0, false)])
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("NUL"), "{e:#}");
        // Absurd subprog count.
        let many: Vec<SubprogInfo> = (0..300).map(|i| sub("s", i * 8, false)).collect();
        let e = synth_btf(&many).err().expect("must fail");
        assert!(e.to_string().contains("too many"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_non_bpf_machine() {
        let mut obj = min_elf();
        obj[18..20].copy_from_slice(&u16(62)); // EM_X86_64
        let r = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        );
        assert!(r.is_err());
    }

    fn t_sym(name: &str, value: usize, shndx: usize, func: bool, sec: bool) -> Sym {
        Sym {
            name: name.to_string(),
            value,
            size: 8,
            shndx,
            is_func: func,
            is_obj: false,
            is_section: sec,
        }
    }

    fn call_site(imm: i32) -> Vec<u8> {
        let mut b = vec![0x95u8; 16]; // exit padding
        b[0] = 0x85;
        b[1] = 0x10; // PSEUDO_CALL, like a real toolchain
        b[4..8].copy_from_slice(&imm.to_le_bytes());
        b
    }

    #[test]
    fn call_target_section_rule() {
        // Mirrors the real shape: .text[0] = local callee, .text[0x330]
        // = named builtin; section sym value 0.
        let fns = vec![
            (0usize, 528usize, "walk".to_string()),
            (0x330usize, 0x370usize, "memset".to_string()),
        ];
        let syms = vec![
            t_sym(".text", 0, 2, false, true),
            t_sym("memset", 0x330, 2, true, false),
            t_sym("uprobe_func", 0, 4, true, false),
        ];
        // Named path: (value, name) entry.
        let site = call_site(-1);
        let r = Reloc {
            off: 0,
            typ: R_BPF_64_32,
            sym: 1,
        };
        assert_eq!(
            call_target(&syms, &fns, 2, &site, &r, "p").unwrap(),
            "memset"
        );
        // Section path, placeholder imm: base + 0 = entry@0.
        let r = Reloc {
            off: 0,
            typ: R_BPF_64_32,
            sym: 0,
        };
        assert_eq!(call_target(&syms, &fns, 2, &site, &r, "p").unwrap(), "walk");
        // Section path, folded offset: imm = X/8 - 1 lands on memset.
        let site = call_site(0x330 / 8 - 1);
        assert_eq!(
            call_target(&syms, &fns, 2, &site, &r, "p").unwrap(),
            "memset"
        );
        // Mid-function landing is drift, never a guess.
        let site = call_site(8 / 8 - 1);
        assert!(call_target(&syms, &fns, 2, &site, &r, "p").is_err());
        // Non-call site is drift.
        let mut site = call_site(-1);
        site[0] = 0x95;
        assert!(call_target(&syms, &fns, 2, &site, &r, "p").is_err());
        // Named non-.text func is drift.
        let r = Reloc {
            off: 0,
            typ: R_BPF_64_32,
            sym: 2,
        };
        let site = call_site(-1);
        assert!(call_target(&syms, &fns, 2, &site, &r, "p").is_err());
    }

    #[test]
    fn count_shape_carries_window_cells() {
        // T07 count ABI v2: the loader spec must name the WINDOW
        // interval map with exactly the dims the BPF object
        // declares (ARRAY, u32 key, u64 value, 2 cells); anything
        // else fails `prepare` against the real object instead of
        // running deadline-blind.
        let window = COUNT_MAPS
            .iter()
            .find(|m| m.name == "WINDOW")
            .expect("COUNT_MAPS names WINDOW");
        assert_eq!(window.map_type, 2);
        assert_eq!(window.key_size, 4);
        assert_eq!(window.value_size, 8);
        assert_eq!(window.max_entries, 2);
        assert_eq!(window.flags, 0);
        assert_eq!(
            window.max_entries,
            osslscope_ebpf_common::WINDOW_CELLS,
            "spec dims track the shared ABI"
        );
    }

    #[test]
    fn members_fd_budget_predicate() {
        // Pure gate for the chunk's fd budget (513 prog + 14 map +
        // 513 link fds + clones ≈ 1047 > the 1024 default): soft
        // limits below NEED fail closed before any attach.
        assert!(!members_fd_budget_ok(1024), "default 1024 insufficient");
        assert!(!members_fd_budget_ok(MEMBERS_FD_NEED - 1));
        assert!(members_fd_budget_ok(MEMBERS_FD_NEED));
        assert!(members_fd_budget_ok(MEMBERS_FD_WANT));
        assert!(MEMBERS_FD_WANT >= MEMBERS_FD_NEED);
    }

    #[test]
    fn member_map_count_covers_scan_plane() {
        // The spec count is the prepare-time contract: 6 retained
        // maps + the 7 scan-plane maps + item-5 BUCKET (stage D
        // dropped PENDING — R18 §6.1 — → 13, then +1 → 14).
        assert_eq!(MEMBER_MAPS.len(), 14);
        assert!(
            MEMBER_MAPS.iter().all(|m| m.name != "PENDING_QUERY"),
            "PENDING dropped in D"
        );
        for name in [
            "SCAN", "SEQ", "BIRTH", "RCOUNT", "T_CACHE", "CTRL", "ATTEMPT",
        ] {
            assert!(
                MEMBER_MAPS.iter().any(|m| m.name == name),
                "spec names {name}"
            );
        }
    }

    #[test]
    fn default_ctrl_programs_occupancy_policy() {
        // Stage C (R18 §2/§5): EXPECTED/epoch/gov program the
        // occupancy policy; EXPECTED 0 and 513 fail fast (the entry
        // would skip cause 7 on them).
        let c = default_ctrl(512, MEMBER_RING_BYTES).unwrap();
        assert_eq!(
            (c.expected, c.skip_all, c.epoch, c.governor),
            (512, 0, 1, 4 << 20),
            "16MiB ring: 4MiB policy live"
        );
        let c2 = default_ctrl(512, 1 << 21).unwrap();
        assert_eq!(c2.governor, 1 << 20, "2MiB ring: small-ring fixture half");
        let sub = default_ctrl(7, MEMBER_RING_BYTES).unwrap();
        assert_eq!(sub.expected, 7, "item-6 selective EXPECTED allowed");
        assert!(default_ctrl(0, MEMBER_RING_BYTES).is_err());
        assert!(default_ctrl(513, MEMBER_RING_BYTES).is_err());
    }

    #[test]
    fn attach_subset_validates_before_load() {
        // Item 6: slot/EXPECTED validation precedes the fd budget
        // and load — these fail offline (no object needed): empty
        // slots, slot 512, and EXPECTED != slots.len() (the
        // retire equation counts attached members; mismatch fails
        // fast here, never silently in BPF).
        use std::ffi::CString;
        let exe = CString::new("/nonexistent").unwrap();
        let obj = std::path::Path::new("/nonexistent.o");
        let ctrl4 = default_ctrl(4, MEMBER_RING_BYTES).unwrap();
        let ctrl5 = default_ctrl(5, MEMBER_RING_BYTES).unwrap();
        assert!(attach_members_subset(obj, &exe, 0, 1, &ctrl4, &[]).is_err());
        assert!(attach_members_subset(obj, &exe, 0, 1, &ctrl4, &[0, 512]).is_err());
        assert!(attach_members_subset(obj, &exe, 0, 1, &ctrl5, &[0, 1, 2, 3]).is_err());
    }
}
