// SPDX-License-Identifier: GPL-2.0-only
//! Producer/source maps shared by both BPF objects. Every map is declared
//! exactly once here; `provider_observation` and `focused_count` each include
//! this module, and the host loader injects the same FDs by map name so both
//! programs observe one relationship pool, one dictionary set and one control
//! cell. Maps no program in an object references are dropped from that object
//! by the linker; the loader tolerates their absence per object.
use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray, PerCpuHashMap},
};
use osslscope_bpf_contract::{
    attribution::{
        BindPendingKey, BindPendingValue, DigestKey, ExactNameKey, PartitionKey, PartitionValue,
        ProducerControl, RelKey, RelValue, SegmentIndexKey, SelectorDictionaryKey,
        SelectorDictionaryValue, SiteBindValue, ThreadIdentityKey, ThreadIdentityValue,
        TypedAdmission, TypedSiteKey,
    },
    source::{
        SourceConfig, SourceControl, SourceDomain, SourceGuard, SourceObserver, SourcePair,
        SourceRequest, SourceSlot,
    },
};

#[map]
pub static ATTR_STATE: Array<SourceControl> = Array::with_max_entries(1, 0);
#[map]
pub static SOURCE_CONFIG: Array<SourceConfig> = Array::with_max_entries(1, 0);
#[map]
pub static REL: HashMap<RelKey, RelValue> = HashMap::with_max_entries(8192, 0);
#[map]
pub static SOURCE_GUARD: HashMap<u64, SourceGuard> = HashMap::with_max_entries(8192, 0);
#[map]
pub static SOURCE_REQUEST: HashMap<u64, SourceRequest> = HashMap::with_max_entries(4096, 0);
#[map]
pub static SOURCE_PAIR: Array<SourcePair> = Array::with_max_entries(1, 0);
#[map]
pub static SOURCE_DOMAIN: HashMap<u32, SourceDomain> = HashMap::with_max_entries(64, 0);
#[map]
pub static SOURCE_OBSERVER: Array<SourceObserver> = Array::with_max_entries(1, 0);
#[map]
/// Per-CPU staging cells. Cell 0 is the volatile scratch: bind plans,
/// digest/key staging and `RelValue` builds all reuse it, each phase
/// clobbering the last. Cell 1 carries the commit-tail argument block
/// across the ordered tail steps (X flip, U index, OWNER_SELECTOR, OWNER),
/// which cell-0 value builds would otherwise clobber between steps. Loader
/// spec `ITER_SLOT` entries must match (see `source_owner::MAPS`).
pub static ITER_SLOT: PerCpuArray<SourceSlot> = PerCpuArray::with_max_entries(2, 0);

/// Host-programmed typed admission: which exact (site, process, image) may
/// execute which reviewed role. Configuration, not relationship evidence.
#[map]
pub static TYPED_ADMISSION: HashMap<TypedSiteKey, TypedAdmission> =
    HashMap::with_max_entries(1024, 0);
/// Host-programmed per-site binding: observer site ID, source epoch and the
/// retained object containing the firing callback. Configuration.
#[map]
pub static SITE_BIND: HashMap<TypedSiteKey, SiteBindValue> = HashMap::with_max_entries(1024, 0);
/// Complete 304-byte typed pending transactions, sharing the 4096/depth-8
/// pending budget with the legacy provider pending map.
#[map]
pub static BIND_PENDING: HashMap<BindPendingKey, BindPendingValue> =
    HashMap::with_max_entries(4096, 0);
/// Kernel-private exact-name index: complete byte key to observer request ID.
#[map]
pub static EXACT_NAME: HashMap<ExactNameKey, u64> = HashMap::with_max_entries(2048, 0);
/// Digest conflict index: (object, operation, digest) to request ID, with 0
/// marking a persistent within-session digest collision. Never a substitute
/// for exact-byte comparison.
#[map]
pub static DIGEST_INDEX: HashMap<DigestKey, u64> = HashMap::with_max_entries(2048, 0);
/// Public-safe dictionary projection: session selector IDs to retained
/// object/operation/encoding/digest rows. Read by the host fold.
#[map]
pub static SELECTOR_DICT: HashMap<SelectorDictionaryKey, SelectorDictionaryValue> =
    HashMap::with_max_entries(1024, 0);
/// Observer thread incarnations: fresh nonzero IDs per (process, TID),
/// retired synchronously by the exit root before kernel TID reuse.
#[map]
pub static THREAD_IDENTITY: HashMap<ThreadIdentityKey, ThreadIdentityValue> =
    HashMap::with_max_entries(4096, 0);
/// Per-CPU attributed partition aggregates, written only by the same focused
/// handler after a successful physical store in the same count generation.
#[map]
pub static PARTITION: PerCpuHashMap<PartitionKey, PartitionValue> =
    PerCpuHashMap::with_max_entries(8192, 0);
/// Producer control cell: session/cut coordinates, ID allocator and the
/// relation/loss epochs. Mode transitions run only through the qualified
/// source-acquisition path; kernel poison paths advance the epochs.
#[map]
pub static ATTRIB_CONTROL: Array<ProducerControl> = Array::with_max_entries(1, 0);
/// Segment index: one immutable attribution tuple to its nonzero segment ID,
/// allocated once and reused by every later hit with the same tuple.
#[map]
pub static SEGMENT_INDEX: HashMap<SegmentIndexKey, u64> = HashMap::with_max_entries(8192, 0);
/// Producer loss ledger, per finite cause. Userspace drains it with the
/// partition map; saturation is recorded here, never silent.
#[map]
pub static PRODUCER_LOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);
