// SPDX-License-Identifier: GPL-3.0-or-later
//! No target-memory reads or pathname-based attachment. All locators and
//! addresses are private transient inputs and deliberately lack Debug/serde.
use super::schema::{APIS, ObjectHash, ObservationApi, ObservationBudget, ObservationGap};
use super::static_tables::{
    self, DynamicAlgorithmId, StaticTableProvenance, TableDiscovery, TableLimits, TableStorage,
};
use crate::inventory::{
    self, IdentityStatus, ModuleInfo, NamespaceId, NamespaceIds, ProcessRecord,
};
use std::cell::{Cell, OnceCell, RefCell};
use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_MAPS: usize = 4_194_304;
const MAX_OBJECT: u64 = 134_217_728;
const MAX_HEADERS: usize = 4096;
const MAX_SYMBOLS: u64 = 262_144;
const MAX_STRINGS: u64 = 16 * 1024 * 1024;
// A parser can retain at most one executable range per program header and
// one offset per finite API. Reserve this conservative upper bound before
// hashing, reads, or construction, including source-only inspection.
const PARSER_STATE_BYTES: usize = MAX_HEADERS * std::mem::size_of::<Segment>()
    + APIS.len() * std::mem::size_of::<(ObservationApi, u64)>()
    + std::mem::size_of::<ElfObject>()
    + 64;

#[cfg(test)]
thread_local! {
    pub(super) static EXPIRE_ACQUIRE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static EXPIRE_CANDIDATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
static GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    native: u64,
    inode: u64,
    size: u64,
    mode: u32,
    links: u64,
    mt: i64,
    mn: i64,
    ct: i64,
    cn: i64,
}
impl Stamp {
    fn of(m: &Metadata) -> Self {
        Self {
            native: m.dev(),
            inode: m.ino(),
            size: m.len(),
            mode: m.mode(),
            links: m.nlink(),
            mt: m.mtime(),
            mn: m.mtime_nsec(),
            ct: m.ctime(),
            cn: m.ctime_nsec(),
        }
    }
}
struct Mapping {
    start: u64,
    end: u64,
    offset: u64,
    native: u64,
    inode: u64,
}
struct Segment {
    offset: u64,
    address: u64,
    size: u64,
}
struct ElfObject {
    hash: ObjectHash,
    segments: Vec<Segment>,
    exports: Vec<(ObservationApi, u64)>,
}
// Internal retry classification: shared capacity is not part of a retained
// file fingerprint. Public diagnostics keep their existing finite gap labels.
#[derive(Debug)]
enum ParseError {
    Gap(ObservationGap),
    SharedCapacity(ObservationGap),
}
impl From<ObservationGap> for ParseError {
    fn from(gap: ObservationGap) -> Self {
        Self::Gap(gap)
    }
}
impl ParseError {
    fn gap(self) -> ObservationGap {
        match self {
            Self::Gap(gap) | Self::SharedCapacity(gap) => gap,
        }
    }
}
struct Object {
    parse_deferred: Cell<bool>,
    file: File,
    stamp: Stamp,
    expected: Option<ModuleInfo>,
    parsed: OnceCell<Result<ElfObject, ObservationGap>>,
    tables: OnceCell<Result<TableDiscovery, ObservationGap>>,
}
impl Object {
    fn parsed(&self, budget: &ObservationBudget) -> Result<&ElfObject, ObservationGap> {
        if self.parsed.get().is_none() {
            // This marker describes this attempt only. An authority/deadline
            // failure must not inherit an earlier shared-capacity refusal.
            self.parse_deferred.set(false);
            self.unchanged()?;
            let mut fd = self
                .file
                .try_clone()
                .map_err(|_| ObservationGap::BackingUnavailable)?;
            let parsed = match parse_object(&mut fd, self.expected.as_ref(), budget) {
                Err(ParseError::SharedCapacity(gap)) => {
                    self.parse_deferred.set(true);
                    return Err(gap);
                }
                Err(ParseError::Gap(ObservationGap::SnapshotLag)) => {
                    return Err(ObservationGap::SnapshotLag);
                }
                Err(ParseError::Gap(gap)) => Err(gap),
                Ok(parsed) => Ok(parsed),
            };
            self.parse_deferred.set(false);
            let _ = self.parsed.set(parsed);
        }
        self.parsed
            .get()
            .expect("cached nontransient parse")
            .as_ref()
            .map_err(|gap| *gap)
    }
    fn tables(&self, budget: &ObservationBudget) -> Result<&TableDiscovery, ObservationGap> {
        if self.tables.get().is_none() {
            let tables =
                static_tables::discover_tables_budgeted(&self.file, TableLimits::default(), budget)
                    .map_err(|g| match g {
                        static_tables::TableGap::Deadline => ObservationGap::SnapshotLag,
                        static_tables::TableGap::Resource => ObservationGap::ReadLimit,
                        static_tables::TableGap::Changed => ObservationGap::ObjectChanged,
                        static_tables::TableGap::Io => ObservationGap::BackingUnavailable,
                        _ => ObservationGap::MalformedElf,
                    });
            if matches!(tables, Err(ObservationGap::SnapshotLag)) {
                return Err(ObservationGap::SnapshotLag);
            }
            let _ = self.tables.set(tables);
        }
        self.tables
            .get()
            .expect("cached nontransient discovery")
            .as_ref()
            .map_err(|gap| *gap)
    }

    fn unchanged(&self) -> Result<(), ObservationGap> {
        if Stamp::of(
            &self
                .file
                .metadata()
                .map_err(|_| ObservationGap::ObjectChanged)?,
        ) != self.stamp
        {
            return Err(ObservationGap::ObjectChanged);
        }
        Ok(())
    }
}
#[derive(Clone)]
enum SiteCustody {
    Mapped {
        process: Rc<Process>,
        maps: Rc<Vec<u8>>,
    },
    Startup(Rc<StartupProcess>),
}
impl SiteCustody {
    fn pid(&self) -> u32 {
        match self {
            Self::Mapped { process, .. } => process.pid,
            Self::Startup(p) => p.pid,
        }
    }
    fn starttime(&self) -> u64 {
        match self {
            Self::Mapped { process, .. } => process.starttime,
            Self::Startup(p) => p.starttime,
        }
    }
    fn validate(&self) -> Result<(), ObservationGap> {
        match self {
            Self::Mapped { process, maps } => {
                process.validate()?;
                if !same_executable_mappings(
                    maps,
                    &read_at(&process.directory, b"maps", MAX_MAPS)?,
                )? {
                    return Err(ObservationGap::ProcessChanged);
                }
                Ok(())
            }
            Self::Startup(p) => p.validate(),
        }
    }
}
/// Sealed by the held OwnedTarget constructor. Exec is allowed, but PID and
/// namespace changes are not. Static shapes mint entry-only sites; separately
/// validated operational exports can mint scalar-only startup capabilities.
pub(crate) struct StartupProcess {
    original: crate::pin::StartupGroupRetention,
    directory: File,
    pid: u32,
    starttime: u64,
    namespaces: NamespaceIds,
    generation: u64,
}
impl StartupProcess {
    pub(crate) fn held(child: &crate::target::OwnedTarget) -> Result<Rc<Self>, ObservationGap> {
        let original = child
            .startup_group()
            .map_err(|_| ObservationGap::ProcessChanged)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(format!("/proc/{}", child.pid()))
            .map_err(|_| ObservationGap::ProcessUnavailable)?;
        let value = Rc::new(Self {
            original,
            pid: child.pid(),
            starttime: starttime(&directory)?,
            namespaces: namespaces(&directory)?,
            directory,
            generation: GENERATION.fetch_add(1, Ordering::Relaxed),
        });
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), ObservationGap> {
        let mut pfd = libc::pollfd {
            fd: self.original.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 0) } != 0 {
            return Err(ObservationGap::ProcessUnavailable);
        }
        if starttime(&self.directory)? != self.starttime {
            return Err(ObservationGap::ProcessChanged);
        }
        if namespaces(&self.directory)? != self.namespaces {
            return Err(ObservationGap::NamespaceChanged);
        }
        Ok(())
    }
}
/// Retain and parse the exact file already opened by bounded dependency discovery.
/// Operational capabilities require an independently validated public export.
pub(crate) fn startup_candidates(
    process: Rc<StartupProcess>,
    file: File,
    budget: &ObservationBudget,
) -> Result<(Vec<VerifiedStaticCandidate>, Vec<StartupApiSite>, bool), ObservationGap> {
    process.validate()?;
    budget.object()?;
    let metadata = file
        .metadata()
        .map_err(|_| ObservationGap::BackingUnavailable)?;
    if !metadata.is_file() || metadata.len() > MAX_OBJECT {
        return Err(ObservationGap::ReadLimit);
    }
    let object = Rc::new(Object {
        parse_deferred: Cell::new(false),
        file,
        stamp: Stamp::of(&metadata),
        expected: None,
        parsed: OnceCell::new(),
        tables: OnceCell::new(),
    });
    let parsed = object.parsed(budget)?;
    let mut apis = Vec::new();
    for &(api, offset) in &parsed.exports {
        if let ObservationApi::Operational(api) = api {
            // Consider all public roles, including legacy target-reading APIs,
            // before minting even a scalar-only startup capability.
            if parsed
                .exports
                .iter()
                .any(|&(other, at)| at == offset && other != ObservationApi::Operational(api))
            {
                continue;
            }
            budget.state(256)?;
            apis.push(StartupApiSite {
                api,
                site: VerifiedSite {
                    custody: SiteCustody::Startup(process.clone()),
                    object: object.clone(),
                    offset,
                    generation: process.generation,
                    hash: parsed.hash.clone(),
                },
            });
        }
    }
    let tables =
        static_tables::discover_tables_budgeted(&object.file, TableLimits::default(), budget)
            .map_err(|g| match g {
                static_tables::TableGap::Resource => ObservationGap::ReadLimit,
                static_tables::TableGap::Changed => ObservationGap::ObjectChanged,
                _ => ObservationGap::MalformedElf,
            })?;
    let mut candidates = Vec::new();
    for locator in tables.candidates() {
        budget.state(std::mem::size_of::<VerifiedStaticCandidate>() * 2)?;
        candidates.push(VerifiedStaticCandidate {
            site: VerifiedSite {
                custody: SiteCustody::Startup(process.clone()),
                object: object.clone(),
                offset: locator.file_offset,
                generation: process.generation,
                hash: parsed.hash.clone(),
            },
            algorithm: locator.algorithm,
            known_algorithm: locator.hint,
            alias_quality: locator.quality,
            operation_hint: None,
            function_id: locator.function_id,
            storage: locator.storage,
            provenance: locator.provenance,
            partial: locator.partial,
        });
    }
    object.unchanged()?;
    process.validate()?;
    Ok((candidates, apis, !tables.gaps().is_empty()))
}

/// Explicit privileged event operand, never a transport value.
pub struct TransientCodeAddress(u64);
impl TransientCodeAddress {
    pub fn from_kernel_event(address: u64) -> Self {
        Self(address)
    }
}
/// Descriptor-backed site. Keep this value alive until its links are closed.
/// It cannot be serialized or formatted, and exposes no pathname.
#[derive(Clone)]
pub struct VerifiedSite {
    custody: SiteCustody,
    object: Rc<Object>,
    offset: u64,
    generation: u64,
    hash: ObjectHash,
}
impl VerifiedSite {
    pub(crate) fn pid(&self) -> u32 {
        self.custody.pid()
    }
    pub(crate) fn starttime(&self) -> u64 {
        self.custody.starttime()
    }
    pub(crate) fn is_startup(&self) -> bool {
        matches!(self.custody, SiteCustody::Startup(_))
    }
    /// Bookkeeping bridge between independently retained authorities. Both
    /// representatives must be revalidated by the counter before comparison;
    /// this cannot construct a site or grant a public ABI capability.
    pub(crate) fn matches_retained(&self, previous: &Self) -> Result<bool, ObservationGap> {
        let SiteCustody::Mapped { process, .. } = &self.custody else {
            return Ok(false);
        };
        let (pid, starttime, namespaces) = match &previous.custody {
            SiteCustody::Mapped { process, .. } => {
                (process.pid, process.starttime, &process.namespaces)
            }
            SiteCustody::Startup(original) => {
                (original.pid, original.starttime, &original.namespaces)
            }
        };
        Ok(process.pid == pid
            && process.starttime == starttime
            && &process.namespaces == namespaces
            && self.object.stamp == previous.object.stamp
            && self.hash == previous.hash
            && self.offset == previous.offset)
    }
    pub fn attachment_fd(&self) -> BorrowedFd<'_> {
        self.object.file.as_fd()
    }
    pub fn file_offset(&self) -> u64 {
        self.offset
    }
    pub fn native_device(&self) -> u64 {
        self.object.stamp.native
    }
    pub fn inode(&self) -> u64 {
        self.object.stamp.inode
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn object_hash(&self) -> &ObjectHash {
        &self.hash
    }
    pub fn revalidate_object(&self) -> Result<(), ObservationGap> {
        self.custody.validate()?;
        self.object.unchanged()
    }
}
/// A file-derived shape grants entry-count authority only, never a callable ABI.
#[derive(Clone)]
pub struct VerifiedStaticCandidate {
    site: VerifiedSite,
    algorithm: Option<DynamicAlgorithmId>,
    known_algorithm: Option<u16>,
    alias_quality: super::AliasQuality,
    operation_hint: Option<u32>,
    function_id: u32,
    storage: TableStorage,
    provenance: StaticTableProvenance,
    partial: bool,
}
impl VerifiedStaticCandidate {
    pub fn site(&self) -> &VerifiedSite {
        &self.site
    }
    pub fn pid(&self) -> u32 {
        self.site.custody.pid()
    }
    pub fn starttime(&self) -> u64 {
        self.site.custody.starttime()
    }
    pub fn known_algorithm(&self) -> Option<u16> {
        self.known_algorithm
    }
    pub fn alias_quality(&self) -> super::AliasQuality {
        self.alias_quality
    }
    pub fn algorithm(&self) -> Option<DynamicAlgorithmId> {
        self.algorithm
    }
    pub fn operation_hint(&self) -> Option<u32> {
        self.operation_hint
    }
    pub fn function_id(&self) -> u32 {
        self.function_id
    }
    pub fn storage(&self) -> TableStorage {
        self.storage
    }
    pub fn provenance(&self) -> StaticTableProvenance {
        self.provenance
    }
    pub fn partial(&self) -> bool {
        self.partial
    }
}
/// Only retained ELF public-export validation can construct this capability.
pub(crate) struct StartupApiSite {
    api: crate::api_activity::ApiId,
    site: VerifiedSite,
}
impl StartupApiSite {
    pub(crate) fn into_parts(self) -> (crate::api_activity::ApiId, VerifiedSite) {
        (self.api, self.site)
    }
}
pub struct ApiSite {
    pub api: ObservationApi,
    pub site: VerifiedSite,
}
/// Procdir/pidfd and descriptors remain owned through all cloned sites.
#[derive(Default)]
struct StaticDiscovery {
    mapping: usize,
    locator: usize,
    emitted: bool,
    candidates: Vec<VerifiedStaticCandidate>,
}
pub struct VerifiedProcess {
    process: Rc<Process>,
    mappings: Vec<(Mapping, Rc<Object>)>,
    maps: Rc<Vec<u8>>,
    generation: u64,
    budget: ObservationBudget,
    gaps: RefCell<std::collections::BTreeSet<ObservationGap>>,
    static_discovery: RefCell<StaticDiscovery>,
    // Inventory hints excluded from this acquisition. Stronger later metadata
    // can request fresh custody, but cannot promote these old locators.
    refused_inventory: Vec<(u64, u64)>,
}
struct Process {
    _admission: Option<super::schema::ProcessAdmission>,
    directory: File,
    pid: u32,
    pidfd: File,
    executable: File,
    exe_stamp: Stamp,
    starttime: u64,
    namespaces: NamespaceIds,
}
impl Process {
    fn validate(&self) -> Result<(), ObservationGap> {
        live(&self.pidfd)?;
        if starttime(&self.directory)? != self.starttime {
            return Err(ObservationGap::ProcessChanged);
        }
        if namespaces(&self.directory)? != self.namespaces {
            return Err(ObservationGap::NamespaceChanged);
        }
        let current = open_at(&self.directory, b"exe")?;
        if Stamp::of(
            &current
                .metadata()
                .map_err(|_| ObservationGap::ProcessChanged)?,
        ) != self.exe_stamp
            || Stamp::of(
                &self
                    .executable
                    .metadata()
                    .map_err(|_| ObservationGap::ProcessChanged)?,
            ) != self.exe_stamp
        {
            return Err(ObservationGap::ProcessChanged);
        }
        live(&self.pidfd)
    }
}
impl VerifiedProcess {
    /// Verified executable VMA bounds; private relocation admission only.
    pub(crate) fn executable_ranges(&self) -> Result<Vec<(u64, u64)>, ObservationGap> {
        self.revalidate()?;
        if self.mappings.len() > 128 {
            return Err(ObservationGap::SiteLimit);
        }
        Ok(self
            .mappings
            .iter()
            .map(|(m, _)| (m.start, m.end))
            .collect())
    }
    pub(crate) fn api_discovery_deferred(&self) -> bool {
        self.mappings.iter().any(|(_, object)| {
            object.parse_deferred.get()
                && object
                    .expected
                    .as_ref()
                    .is_some_and(|info| !info.exports.is_empty())
        })
    }
    pub fn retained_objects(&self) -> usize {
        let mut identities = std::collections::BTreeSet::new();
        for (_, object) in &self.mappings {
            identities.insert((object.stamp.native, object.stamp.inode));
        }
        identities.len()
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn gaps(&self) -> Vec<ObservationGap> {
        self.gaps.borrow().iter().copied().collect()
    }
    pub(crate) fn retained_incarnation(&self) -> ProcessIncarnation {
        ProcessIncarnation(self.process.clone())
    }
    pub(crate) fn inventory_authority_advanced(&self, record: &ProcessRecord) -> bool {
        record.modules.iter().any(|module| {
            module.identity_status == IdentityStatus::Verified
                && self
                    .refused_inventory
                    .contains(&(module.info.device, module.info.inode))
        })
    }
    pub fn revalidate(&self) -> Result<(), ObservationGap> {
        self.process.validate()?;
        if !same_executable_mappings(
            &self.maps,
            &read_at(&self.process.directory, b"maps", MAX_MAPS)?,
        )? {
            return Err(ObservationGap::ProcessChanged);
        }
        for (_, object) in &self.mappings {
            object.unchanged()?;
        }
        self.process.validate()
    }
    pub fn resolve_api(&self, api: ObservationApi) -> Vec<ApiSite> {
        if api.export_name().is_none() {
            return Vec::new();
        }
        if let Err(gap) = self.revalidate() {
            self.gaps.borrow_mut().insert(gap);
            return Vec::new();
        }
        let mut sites = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for (mapping, object) in &self.mappings {
            // Eager resolution is limited to inventoried API sources; unknown
            // code is parsed only when a learned address identifies its VMA.
            if object
                .expected
                .as_ref()
                .is_none_or(|info| info.exports.is_empty())
            {
                continue;
            }
            let parsed = match object.parsed(&self.budget) {
                Ok(parsed) => parsed,
                Err(gap) => {
                    self.gaps.borrow_mut().insert(gap);
                    continue;
                }
            };
            for &(found, offset) in &parsed.exports {
                if found != api || !mapping_contains_offset(mapping, offset) {
                    continue;
                }
                if seen.insert((object.stamp.native, object.stamp.inode, offset)) {
                    sites.push(ApiSite {
                        api,
                        site: VerifiedSite {
                            custody: SiteCustody::Mapped {
                                process: self.process.clone(),
                                maps: self.maps.clone(),
                            },
                            object: object.clone(),
                            offset,
                            generation: self.generation,
                            hash: parsed.hash.clone(),
                        },
                    });
                }
            }
        }
        sites
    }
    /// Discover once per retained file, then bind every locator to the verified
    /// executable mapping. Parsing never supplies process or attachment authority.
    pub fn static_candidates(
        &self,
        budget: &ObservationBudget,
    ) -> Result<Vec<VerifiedStaticCandidate>, ObservationGap> {
        self.revalidate()?;
        let mut discovery = self.static_discovery.borrow_mut();
        while discovery.mapping < self.mappings.len() {
            let index = discovery.mapping;
            let object = &self.mappings[index].1;
            if self.mappings[..index]
                .iter()
                .any(|(_, prior)| Rc::ptr_eq(prior, object))
            {
                discovery.mapping += 1;
                continue;
            }
            object.unchanged()?;
            let tables = match object.tables(budget) {
                Ok(t) => t,
                Err(ObservationGap::SnapshotLag) => return Err(ObservationGap::SnapshotLag),
                Err(g) => {
                    self.gaps.borrow_mut().insert(g);
                    discovery.mapping += 1;
                    continue;
                }
            };
            if !tables.gaps().is_empty() {
                self.gaps
                    .borrow_mut()
                    .insert(ObservationGap::DispatchPartial);
            }
            let parsed = match object.parsed(budget) {
                Ok(p) => p,
                Err(ObservationGap::SnapshotLag) => return Err(ObservationGap::SnapshotLag),
                Err(g) if object.parse_deferred.get() => {
                    self.gaps.borrow_mut().insert(g);
                    return Err(ObservationGap::SnapshotLag);
                }
                Err(g) => {
                    self.gaps.borrow_mut().insert(g);
                    discovery.mapping += 1;
                    continue;
                }
            };
            for locator in tables.candidates().skip(discovery.locator) {
                if !self.mappings.iter().any(|(m, o)| {
                    Rc::ptr_eq(o, object) && mapping_contains_offset(m, locator.file_offset)
                }) {
                    discovery.locator += 1;
                    continue;
                }
                // Charge both retained progress and the one emitted batch. On
                // expiry leave the cursor at the first uncharged candidate.
                budget.state(std::mem::size_of::<VerifiedStaticCandidate>() * 2)?;
                discovery.candidates.push(VerifiedStaticCandidate {
                    site: VerifiedSite {
                        custody: SiteCustody::Mapped {
                            process: self.process.clone(),
                            maps: self.maps.clone(),
                        },
                        object: object.clone(),
                        offset: locator.file_offset,
                        generation: self.generation,
                        hash: parsed.hash.clone(),
                    },
                    algorithm: locator.algorithm,
                    known_algorithm: locator.hint,
                    alias_quality: locator.quality,
                    operation_hint: None,
                    function_id: locator.function_id,
                    storage: locator.storage,
                    provenance: locator.provenance,
                    partial: locator.partial,
                });
                discovery.locator += 1;
                #[cfg(test)]
                EXPIRE_CANDIDATE.with(|flag| {
                    if flag.replace(false) {
                        budget.set_deadline(std::time::Instant::now());
                    }
                });
            }
            object.unchanged()?;
            discovery.mapping += 1;
            discovery.locator = 0;
        }
        self.revalidate()?;
        if discovery.emitted {
            budget.state(
                discovery.candidates.len() * std::mem::size_of::<VerifiedStaticCandidate>(),
            )?;
        }
        discovery.emitted = true;
        Ok(discovery.candidates.clone())
    }
    pub fn relocate(&self, address: TransientCodeAddress) -> Result<VerifiedSite, ObservationGap> {
        self.revalidate()?;
        let mut matches = self
            .mappings
            .iter()
            .filter(|(map, _)| address.0 >= map.start && address.0 < map.end);
        let (map, object) = matches.next().ok_or(ObservationGap::SymbolUnavailable)?;
        if matches.next().is_some() {
            return Err(ObservationGap::AmbiguousSite);
        }
        let offset = map
            .offset
            .checked_add(address.0 - map.start)
            .ok_or(ObservationGap::MalformedElf)?;
        let parsed = object.parsed(&self.budget)?;
        if parsed
            .segments
            .iter()
            .filter(|s| offset >= s.offset && offset - s.offset < s.size)
            .count()
            != 1
        {
            return Err(ObservationGap::SymbolUnavailable);
        }
        object.unchanged()?;
        Ok(VerifiedSite {
            custody: SiteCustody::Mapped {
                process: self.process.clone(),
                maps: self.maps.clone(),
            },
            object: object.clone(),
            offset,
            generation: self.generation,
            hash: parsed.hash.clone(),
        })
    }
}
fn mapping_contains_offset(map: &Mapping, offset: u64) -> bool {
    offset >= map.offset && offset - map.offset < map.end - map.start
}

/// Fresh process identity retention without requiring privileged map_files
/// access. This value grants no site or target-memory authority.
pub(crate) struct ProcessIncarnation(Rc<Process>);
impl ProcessIncarnation {
    pub(crate) fn validate_record(&self, record: &ProcessRecord) -> Result<(), ObservationGap> {
        if self.0.pid != record.pid || self.0.starttime != record.starttime {
            return Err(ObservationGap::ProcessChanged);
        }
        if self.0.namespaces != record.namespaces {
            return Err(ObservationGap::NamespaceChanged);
        }
        self.0.validate()
    }
}
pub(crate) fn acquire_incarnation(
    record: &ProcessRecord,
) -> Result<ProcessIncarnation, ObservationGap> {
    if record.pid == 0 || record.pid > i32::MAX as u32 {
        return Err(ObservationGap::ProcessUnavailable);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/{}", record.pid))
        .map_err(|_| ObservationGap::ProcessUnavailable)?;
    if starttime(&directory)? != record.starttime {
        return Err(ObservationGap::ProcessChanged);
    }
    if namespaces(&directory)? != record.namespaces
        || record.namespaces.pid.is_none()
        || record.namespaces.mount.is_none()
    {
        return Err(ObservationGap::NamespaceChanged);
    }
    // SAFETY: positive PID and zero flags; ownership transfers exactly once.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, record.pid as libc::pid_t, 0) };
    if raw < 0 {
        return Err(ObservationGap::ProcessUnavailable);
    }
    let pidfd = unsafe { File::from_raw_fd(raw as i32) };
    let executable = open_at(&directory, b"exe")?;
    let exe_stamp = Stamp::of(
        &executable
            .metadata()
            .map_err(|_| ObservationGap::ProcessUnavailable)?,
    );
    let process = Rc::new(Process {
        _admission: None,
        directory,
        pid: record.pid,
        pidfd,
        executable,
        exe_stamp,
        starttime: record.starttime,
        namespaces: record.namespaces.clone(),
    });
    process.validate()?;
    Ok(ProcessIncarnation(process))
}
pub fn acquire(
    record: &ProcessRecord,
    limits: &mut ObservationBudget,
) -> Result<VerifiedProcess, ObservationGap> {
    acquire_with_incarnation(record, limits, None)
}
/// Share only one exact incarnation's admission. Maps, native files, parser
/// state and all reads are freshly acquired and charged; old Count owners keep
/// their own allocations/custody alive without any budget refund.
pub(crate) fn acquire_with_incarnation(
    record: &ProcessRecord,
    limits: &mut ObservationBudget,
    retained: Option<&ProcessIncarnation>,
) -> Result<VerifiedProcess, ObservationGap> {
    let mut admission = if retained.is_none() {
        Some(limits.process()?)
    } else {
        None
    };
    #[cfg(test)]
    EXPIRE_ACQUIRE.with(|flag| {
        if flag.replace(false) {
            limits.set_deadline(std::time::Instant::now());
        }
    });
    let process = if let Some(retained) = retained {
        retained.validate_record(record)?;
        retained.0.clone()
    } else {
        acquire_incarnation(record)?.0
    };
    let refused_count = record
        .modules
        .iter()
        .filter(|m| m.identity_status == IdentityStatus::LocatorCandidate)
        .count();
    limits.state(
        refused_count
            .checked_mul(std::mem::size_of::<(u64, u64)>())
            .ok_or(ObservationGap::StateLimit)?,
    )?;
    let mut refused_inventory = Vec::with_capacity(refused_count);
    refused_inventory.extend(
        record
            .modules
            .iter()
            .filter(|m| m.identity_status == IdentityStatus::LocatorCandidate)
            .map(|m| (m.info.device, m.info.inode)),
    );
    limits.state(MAX_MAPS)?;
    let maps = Rc::new(read_at(&process.directory, b"maps", MAX_MAPS)?);
    let mut mappings = Vec::new();
    let mut objects: Vec<Rc<Object>> = Vec::new();
    let mut refused = None;
    let mut gaps = std::collections::BTreeSet::new();
    // Match inventory's per-process mapping/open attempt cap. Two bounded
    // passes prioritize known API sources without retaining every raw VMA.
    const MAX_ATTEMPTS: usize = 1024;
    limits.state(MAX_ATTEMPTS * std::mem::size_of::<Mapping>())?;
    let mut selected = Vec::with_capacity(MAX_ATTEMPTS);
    for relevant in [true, false] {
        for line in maps.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let Some(map) = parse_mapping(line)? else {
                continue;
            };
            let known = record
                .modules
                .iter()
                .any(|m| !m.info.exports.is_empty() && m.info.inode == map.inode);
            if known != relevant {
                continue;
            }
            if selected.len() >= MAX_ATTEMPTS {
                gaps.insert(ObservationGap::ObjectLimit);
                break;
            }
            selected.push(map);
        }
    }
    for map in selected {
        // Association is established before native-device deduplication.
        let name = format!("map_files/{:x}-{:x}", map.start, map.end);
        let file = match open_at(&process.directory, name.as_bytes()) {
            Ok(file) => file,
            Err(_) => {
                refused = Some(ObservationGap::BackingUnavailable);
                gaps.insert(ObservationGap::BackingUnavailable);
                continue;
            }
        };
        let metadata = file
            .metadata()
            .map_err(|_| ObservationGap::BackingUnavailable)?;
        if !metadata.is_file() || !association(&file, &metadata, &map) {
            refused = Some(ObservationGap::IdentityUnverified);
            gaps.insert(ObservationGap::IdentityUnverified);
            continue;
        }
        let stamp = Stamp::of(&metadata);
        let object = if let Some(existing) = objects.iter().find(|o| o.stamp == stamp) {
            existing.clone()
        } else {
            if let Err(gap) = limits.object() {
                if gap == ObservationGap::SnapshotLag {
                    return Err(gap);
                }
                gaps.insert(gap);
                break;
            }
            limits.state(4096)?;
            let expected = record
                .modules
                .iter()
                .find(|m| {
                    m.identity_status == IdentityStatus::Verified
                        && m.info.device == stamp.native
                        && m.info.inode == stamp.inode
                })
                .map(|m| m.info.clone());
            // Explicit inventory candidates must never become attachable.
            if record.modules.iter().any(|m| {
                m.identity_status == IdentityStatus::LocatorCandidate
                    && m.info.device == stamp.native
                    && m.info.inode == stamp.inode
            }) {
                refused = Some(ObservationGap::IdentityUnverified);
                gaps.insert(ObservationGap::IdentityUnverified);
                continue;
            }
            let object = Rc::new(Object {
                parse_deferred: Cell::new(false),
                file,
                stamp,
                expected,
                parsed: OnceCell::new(),
                tables: OnceCell::new(),
            });
            objects.push(object.clone());
            object
        };
        limits.state(std::mem::size_of::<Mapping>() + 32)?;
        mappings.push((map, object));
    }
    if mappings.is_empty() {
        return Err(refused.unwrap_or(ObservationGap::BackingUnavailable));
    }
    // Spend reads on known sources first; unrelated executable objects stay lazy.
    for object in &objects {
        if object
            .expected
            .as_ref()
            .is_some_and(|info| !info.exports.is_empty())
        {
            if let Err(gap) = object.parsed(limits) {
                if gap == ObservationGap::SnapshotLag {
                    return Err(gap);
                }
                gaps.insert(gap);
            }
        }
    }
    let mut verified = VerifiedProcess {
        process,
        mappings,
        maps,
        generation: GENERATION.fetch_add(1, Ordering::Relaxed),
        budget: limits.clone(),
        gaps: RefCell::new(gaps),
        static_discovery: RefCell::default(),
        refused_inventory,
    };
    verified.revalidate()?;
    if let Some(mut admission) = admission.take() {
        admission.retain();
        Rc::get_mut(&mut verified.process)
            .expect("fresh process custody")
            ._admission = Some(admission);
    }
    Ok(verified)
}
fn association(file: &File, metadata: &Metadata, map: &Mapping) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: borrowed descriptor and properly sized output; read on success.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return false;
    }
    let filesystem = unsafe { stat.assume_init() }.f_type;
    matches!(
        filesystem,
        0xef53
            | 0x58465342
            | 0x9123683e
            | 0x01021994
            | 0x858458f6
            | 0x958458f6
            | 0x73717368
            | 0xf2f52010
            | 0x3153464a
            | 0x2fc12fc1
    ) && metadata.ino() == map.inode
        && (metadata.dev() == map.native || filesystem == 0x9123683e)
}
fn open_at(directory: &File, name: &[u8]) -> Result<File, ObservationGap> {
    let name = CString::new(name).map_err(|_| ObservationGap::ProcessUnavailable)?;
    // SAFETY: owned live directory/name; returned descriptor transferred once.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
        )
    };
    if raw < 0 {
        Err(ObservationGap::ProcessUnavailable)
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}
fn read_at(directory: &File, name: &[u8], max: usize) -> Result<Vec<u8>, ObservationGap> {
    let mut file = open_at(directory, name)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ObservationGap::ProcessUnavailable)?;
    // Keep the overflow probe on the stack, not in a growing retained vector.
    let mut extra = [0u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| ObservationGap::ProcessUnavailable)?
        != 0
    {
        return Err(ObservationGap::ReadLimit);
    }
    Ok(bytes)
}

fn number(bytes: &[u8], radix: u32) -> Result<u64, ObservationGap> {
    if bytes.is_empty() || !bytes.iter().all(|b| (*b as char).is_digit(radix)) {
        return Err(ObservationGap::MalformedMaps);
    }
    u64::from_str_radix(
        std::str::from_utf8(bytes).map_err(|_| ObservationGap::MalformedMaps)?,
        radix,
    )
    .map_err(|_| ObservationGap::MalformedMaps)
}
fn starttime(directory: &File) -> Result<u64, ObservationGap> {
    let bytes = read_at(directory, b"stat", 65536)?;
    let end = bytes
        .iter()
        .rposition(|b| *b == b')')
        .ok_or(ObservationGap::ProcessUnavailable)?;
    let field = bytes[end + 1..]
        .split(u8::is_ascii_whitespace)
        .filter(|b| !b.is_empty())
        .nth(19)
        .ok_or(ObservationGap::ProcessUnavailable)?;
    number(field, 10).map_err(|_| ObservationGap::ProcessUnavailable)
}
fn namespaces(directory: &File) -> Result<NamespaceIds, ObservationGap> {
    let id = |name: &[u8]| {
        let file = open_at(directory, name).map_err(|_| ObservationGap::NamespaceChanged)?;
        let m = file
            .metadata()
            .map_err(|_| ObservationGap::NamespaceChanged)?;
        Ok(Some(NamespaceId {
            device: m.dev(),
            inode: m.ino(),
        }))
    };
    Ok(NamespaceIds {
        pid: id(b"ns/pid")?,
        mount: id(b"ns/mnt")?,
    })
}
fn live(pidfd: &File) -> Result<(), ObservationGap> {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd, zero timeout; never signals a target.
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 || poll.revents != 0 {
        return Err(ObservationGap::ProcessUnavailable);
    }
    Ok(())
}
fn same_executable_mappings(before: &[u8], after: &[u8]) -> Result<bool, ObservationGap> {
    // Only executable file-backed rows can authorize retained trace sites.
    // Keep each complete validated row as a conservative change fence, including
    // permissions and association text; this never promotes a pathname to proof.
    // Anonymous/non-executable rows are parsed but cannot change this identity.
    fn relevant(bytes: &[u8]) -> impl Iterator<Item = Result<&[u8], ObservationGap>> {
        bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .filter_map(|line| match parse_mapping(line) {
                Ok(Some(_)) => Some(Ok(line)),
                Ok(None) => None,
                Err(gap) => Some(Err(gap)),
            })
    }
    let mut before = relevant(before);
    let mut after = relevant(after);
    loop {
        match (before.next().transpose()?, after.next().transpose()?) {
            (None, None) => return Ok(true),
            (Some(left), Some(right)) if left == right => (),
            _ => return Ok(false),
        }
    }
}

fn parse_mapping(line: &[u8]) -> Result<Option<Mapping>, ObservationGap> {
    if line.contains(&0) {
        return Err(ObservationGap::MalformedMaps);
    }
    let mut fields = line
        .split(u8::is_ascii_whitespace)
        .filter(|b| !b.is_empty());
    let mut next = || fields.next().ok_or(ObservationGap::MalformedMaps);
    let range = next()?;
    let perms = next()?;
    let offset = number(next()?, 16)?;
    let dev = next()?;
    let inode = number(next()?, 10)?;
    let split = |bytes: &[u8], separator| {
        bytes
            .iter()
            .position(|b| *b == separator)
            .ok_or(ObservationGap::MalformedMaps)
    };
    let at = split(range, b'-')?;
    let start = number(&range[..at], 16)?;
    let end = number(&range[at + 1..], 16)?;
    let at = split(dev, b':')?;
    let major =
        u32::try_from(number(&dev[..at], 16)?).map_err(|_| ObservationGap::MalformedMaps)?;
    let minor =
        u32::try_from(number(&dev[at + 1..], 16)?).map_err(|_| ObservationGap::MalformedMaps)?;
    if start >= end
        || perms.len() != 4
        || !matches!(perms[0], b'r' | b'-')
        || !matches!(perms[1], b'w' | b'-')
        || !matches!(perms[2], b'x' | b'-')
        || !matches!(perms[3], b'p' | b's')
        || offset.checked_add(end - start).is_none()
    {
        return Err(ObservationGap::MalformedMaps);
    }
    if perms[2] != b'x' || inode == 0 {
        return Ok(None);
    }
    Ok(Some(Mapping {
        start,
        end,
        offset,
        native: libc::makedev(major, minor),
        inode,
    }))
}

/// Source-only inspection returns finite labels, never an attachable site.
pub fn inspect_exports(
    file: &mut File,
    budget: &mut ObservationBudget,
) -> Result<Vec<ObservationApi>, ObservationGap> {
    Ok(parse_object(file, None, budget)
        .map_err(ParseError::gap)?
        .exports
        .into_iter()
        .map(|(api, _)| api)
        .collect())
}
pub fn inspect_expected_exports(
    file: &mut File,
    expected: &ModuleInfo,
    budget: &mut ObservationBudget,
) -> Result<Vec<ObservationApi>, ObservationGap> {
    Ok(parse_object(file, Some(expected), budget)
        .map_err(ParseError::gap)?
        .exports
        .into_iter()
        .map(|(api, _)| api)
        .collect())
}
fn parse_object(
    file: &mut File,
    expected: Option<&ModuleInfo>,
    budget: &ObservationBudget,
) -> Result<ElfObject, ParseError> {
    let reservation = budget.reserve_state(PARSER_STATE_BYTES)?;
    let before = file
        .metadata()
        .map_err(|_| ObservationGap::BackingUnavailable)?;
    if !before.is_file() || before.len() > MAX_OBJECT {
        return Err(ObservationGap::ReadLimit.into());
    }
    if expected.is_some_and(|e| {
        e.device != before.dev() || e.inode != before.ino() || e.size_bytes != before.len()
    }) {
        return Err(ObservationGap::ObjectChanged.into());
    }
    // Reserve both non-overlapping phase needs before committing any IO work.
    // Export headroom can refuse even when inventory scratch fits; acquiring it
    // now prevents re-reading completed inventory on every blocked retry.
    let inventory_bytes = inventory::elf::parser_scratch_bytes(before.len())
        .map_err(|_| ObservationGap::ReadLimit)?;
    let export_bytes = MAX_STRINGS as usize + MAX_SYMBOLS as usize * 24 + (1 << 20);
    let _inventory = budget
        .memory
        .as_ref()
        .map(|pool| {
            pool.reserve(inventory_bytes)
                .ok_or(ParseError::SharedCapacity(ObservationGap::ReadLimit))
        })
        .transpose()?;
    let _export_headroom = budget
        .memory
        .as_ref()
        .map(|pool| {
            pool.reserve(export_bytes.saturating_sub(inventory_bytes))
                .ok_or(ParseError::SharedCapacity(ObservationGap::StateLimit))
        })
        .transpose()?;
    // inspect_file reads at most size+1; its externally held lease above covers
    // parser scratch while its independent structural and descriptor checks run.
    budget.read(
        before
            .len()
            .checked_add(1)
            .ok_or(ObservationGap::ReadLimit)?,
    )?;
    let info = inventory::elf::inspect_file(file, before.len()).map_err(|gap| match gap {
        inventory::GapReason::Changed => ObservationGap::ObjectChanged,
        inventory::GapReason::ReadLimit | inventory::GapReason::TooLarge => {
            ObservationGap::ReadLimit
        }
        _ => ObservationGap::MalformedElf,
    })?;
    if expected.is_some_and(|expected| *expected != info) {
        return Err(ObservationGap::ObjectChanged.into());
    }
    // The same maximum phase lease now covers export symbol/string scratch.
    let result = parse_exports(
        file,
        before.len(),
        budget,
        info.sha256
            .try_into()
            .map_err(|_| ObservationGap::MalformedElf)?,
    )?;
    if Stamp::of(&before) != Stamp::of(&file.metadata().map_err(|_| ObservationGap::ObjectChanged)?)
    {
        return Err(ObservationGap::ObjectChanged.into());
    }
    reservation.retain();
    Ok(result)
}
fn bytes(
    file: &File,
    offset: u64,
    size: usize,
    len: u64,
    budget: &ObservationBudget,
) -> Result<Vec<u8>, ObservationGap> {
    if offset.checked_add(size as u64).is_none_or(|end| end > len) {
        return Err(ObservationGap::MalformedElf);
    }
    budget.read(size as u64)?;
    let mut bytes = vec![0; size];
    file.read_exact_at(&mut bytes, offset)
        .map_err(|_| ObservationGap::MalformedElf)?;
    Ok(bytes)
}
fn word(bytes: &[u8], at: usize, size: usize) -> Result<u64, ObservationGap> {
    let slice = bytes
        .get(at..at.checked_add(size).ok_or(ObservationGap::MalformedElf)?)
        .ok_or(ObservationGap::MalformedElf)?;
    Ok(slice
        .iter()
        .enumerate()
        .fold(0, |value, (i, b)| value | ((*b as u64) << (8 * i))))
}
fn parse_exports(
    file: &File,
    len: u64,
    budget: &ObservationBudget,
    hash: ObjectHash,
) -> Result<ElfObject, ObservationGap> {
    let h = bytes(file, 0, 64, len, budget)?;
    if &h[..6] != b"\x7fELF\x02\x01" {
        return Err(ObservationGap::UnsupportedArchitecture);
    }
    if !matches!(word(&h, 16, 2)?, 2 | 3) || word(&h, 20, 4)? != 1 || word(&h, 52, 2)? != 64 {
        return Err(ObservationGap::MalformedElf);
    }
    let machine = word(&h, 18, 2)?;
    if !matches!(
        (std::env::consts::ARCH, machine),
        ("x86_64", 62) | ("aarch64", 183)
    ) {
        return Err(ObservationGap::UnsupportedArchitecture);
    }
    let phoff = word(&h, 32, 8)?;
    let phsize = word(&h, 54, 2)?;
    let phnum = word(&h, 56, 2)? as usize;
    if phnum > MAX_HEADERS || phsize != 56 {
        return Err(ObservationGap::MalformedElf);
    }
    let programs = bytes(file, phoff, phnum * 56, len, budget)?;
    let mut segments = Vec::with_capacity(phnum);
    for p in programs.chunks_exact(56) {
        if word(p, 0, 4)? != 1 {
            continue;
        }
        let offset = word(p, 8, 8)?;
        let address = word(p, 16, 8)?;
        let size = word(p, 32, 8)?;
        let memsize = word(p, 40, 8)?;
        if size > memsize
            || offset.checked_add(size).is_none_or(|end| end > len)
            || address.checked_add(memsize).is_none()
        {
            return Err(ObservationGap::MalformedElf);
        }
        if word(p, 4, 4)? & 1 != 0 {
            segments.push(Segment {
                offset,
                address,
                size,
            });
        }
    }
    // Section headers are optional; when present, do not accept malformed
    // definitions or BSS/data masquerading as defined dynamic functions.
    let shoff = word(&h, 40, 8)?;
    let sections = if shoff == 0 {
        Vec::new()
    } else {
        if word(&h, 58, 2)? != 64 {
            return Err(ObservationGap::MalformedElf);
        }
        let mut count = word(&h, 60, 2)?;
        if count == 0 {
            let first = bytes(file, shoff, 64, len, budget)?;
            count = word(&first, 32, 8)?;
        }
        if count > MAX_HEADERS as u64 {
            return Err(ObservationGap::ReadLimit);
        }
        bytes(file, shoff, count as usize * 64, len, budget)?
    };
    let mut exports: Vec<(ObservationApi, u64)> = Vec::with_capacity(APIS.len());
    if let Some(DynamicSymbols { symbols, names }) = dynamic_symbols(file, &programs, len, budget)?
    {
        for symbol in symbols.chunks_exact(24) {
            let info = symbol[4];
            let section = word(symbol, 6, 2)?;
            if info & 15 != 2
                || !matches!(info >> 4, 1 | 2)
                || symbol[5] & 3 > 0 && symbol[5] & 3 != 3
                || section == 0
                || section >= 0xff00
            {
                continue;
            }
            if !sections.is_empty() {
                let offset = section as usize * 64;
                let Some(header) = sections.get(offset..offset + 64) else {
                    continue;
                };
                if word(header, 4, 4)? == 8 || word(header, 8, 8)? & 6 != 6 {
                    continue;
                }
            }
            let name = word(symbol, 0, 4)? as usize;
            let Some(tail) = names.get(name..).filter(|tail| !tail.is_empty()) else {
                return Err(ObservationGap::MalformedElf);
            };
            let Some(api) = export_api_at(|index| tail.get(index).copied()) else {
                continue;
            };
            let address = word(symbol, 8, 8)?;
            let size = word(symbol, 16, 8)?.max(1);
            let mut matching = segments.iter().filter(|seg| {
                address >= seg.address
                    && address.checked_add(size).is_some_and(|end| {
                        seg.address
                            .checked_add(seg.size)
                            .is_some_and(|limit| end <= limit)
                    })
            });
            let Some(segment) = matching.next() else {
                continue;
            };
            if matching.next().is_some() {
                return Err(ObservationGap::AmbiguousSite);
            }
            let offset = segment
                .offset
                .checked_add(address - segment.address)
                .ok_or(ObservationGap::MalformedElf)?;
            if let Some((_, previous)) = exports.iter().find(|(found, _)| *found == api) {
                if *previous != offset {
                    return Err(ObservationGap::AmbiguousSite);
                }
            } else {
                exports.push((api, offset));
            }
        }
    }
    exports.sort_unstable_by_key(|(api, _)| *api);
    Ok(ElfObject {
        hash,
        segments,
        exports,
    })
}

fn virtual_offset(programs: &[u8], address: u64, size: u64) -> Result<u64, ObservationGap> {
    let mut found = None;
    for p in programs.chunks_exact(56) {
        if word(p, 0, 4)? != 1 {
            continue;
        }
        let base = word(p, 16, 8)?;
        let length = word(p, 32, 8)?;
        if address >= base
            && address
                .checked_add(size)
                .is_some_and(|end| base.checked_add(length).is_some_and(|limit| end <= limit))
        {
            let offset = word(p, 8, 8)?
                .checked_add(address - base)
                .ok_or(ObservationGap::MalformedElf)?;
            if found.replace(offset).is_some() {
                return Err(ObservationGap::AmbiguousSite);
            }
        }
    }
    found.ok_or(ObservationGap::MalformedElf)
}
struct DynamicSymbols {
    symbols: Vec<u8>,
    names: Vec<u8>,
}
fn dynamic_symbols(
    file: &File,
    programs: &[u8],
    len: u64,
    budget: &ObservationBudget,
) -> Result<Option<DynamicSymbols>, ObservationGap> {
    let dynamic: Vec<_> = programs
        .chunks_exact(56)
        .filter(|p| word(p, 0, 4) == Ok(2))
        .collect();
    if dynamic.is_empty() {
        return Ok(None);
    }
    if dynamic.len() != 1 {
        return Err(ObservationGap::MalformedElf);
    }
    let p = dynamic[0];
    let size = word(p, 32, 8)?;
    if size > 16384 * 16 || size % 16 != 0 {
        return Err(ObservationGap::ReadLimit);
    }
    let entries = bytes(file, word(p, 8, 8)?, size as usize, len, budget)?;
    let mut tags = std::collections::BTreeMap::new();
    let mut terminated = false;
    for row in entries.chunks_exact(16) {
        let tag = word(row, 0, 8)?;
        if tag == 0 {
            terminated = true;
            break;
        }
        if matches!(tag, 4 | 5 | 6 | 10 | 11 | 0x6ffffef5)
            && tags.insert(tag, word(row, 8, 8)?).is_some()
        {
            return Err(ObservationGap::MalformedElf);
        }
    }
    if !terminated {
        return Err(ObservationGap::MalformedElf);
    }
    let get = |tag| tags.get(&tag).copied().ok_or(ObservationGap::MalformedElf);
    let string_size = get(10)?;
    if string_size > MAX_STRINGS || get(11)? != 24 {
        return Err(ObservationGap::ReadLimit);
    }
    let count = if let Some(&address) = tags.get(&4) {
        let header = bytes(file, virtual_offset(programs, address, 8)?, 8, len, budget)?;
        let buckets = word(&header, 0, 4)?;
        let count = word(&header, 4, 4)?;
        if buckets > MAX_SYMBOLS || count > MAX_SYMBOLS {
            return Err(ObservationGap::ReadLimit);
        }
        virtual_offset(programs, address, 8 + (buckets + count) * 4)?;
        count
    } else if let Some(&address) = tags.get(&0x6ffffef5) {
        let header = bytes(
            file,
            virtual_offset(programs, address, 16)?,
            16,
            len,
            budget,
        )?;
        let buckets = word(&header, 0, 4)?;
        let first = word(&header, 4, 4)?;
        let bloom = word(&header, 8, 4)?;
        if buckets > MAX_SYMBOLS || first > MAX_SYMBOLS || bloom > MAX_SYMBOLS {
            return Err(ObservationGap::ReadLimit);
        }
        let bucket_address = address
            .checked_add(16 + bloom * 8)
            .ok_or(ObservationGap::MalformedElf)?;
        let table = bytes(
            file,
            virtual_offset(programs, bucket_address, buckets * 4)?,
            (buckets * 4) as usize,
            len,
            budget,
        )?;
        let mut largest = 0;
        for bucket in table.chunks_exact(4) {
            let index = word(bucket, 0, 4)?;
            if index != 0 && index < first {
                return Err(ObservationGap::MalformedElf);
            }
            largest = largest.max(index);
        }
        if largest == 0 {
            first
        } else {
            if largest >= MAX_SYMBOLS {
                return Err(ObservationGap::ReadLimit);
            }
            let chains = bucket_address
                .checked_add(buckets * 4)
                .ok_or(ObservationGap::MalformedElf)?;
            let mut index = largest;
            loop {
                if index >= MAX_SYMBOLS {
                    return Err(ObservationGap::ReadLimit);
                }
                let address = chains
                    .checked_add((index - first) * 4)
                    .ok_or(ObservationGap::MalformedElf)?;
                let chain = bytes(file, virtual_offset(programs, address, 4)?, 4, len, budget)?;
                index += 1;
                if word(&chain, 0, 4)? & 1 != 0 {
                    break;
                }
            }
            index
        }
    } else {
        return Err(ObservationGap::MalformedElf);
    };
    let symbols = bytes(
        file,
        virtual_offset(programs, get(6)?, count * 24)?,
        (count * 24) as usize,
        len,
        budget,
    )?;
    let names = bytes(
        file,
        virtual_offset(programs, get(5)?, string_size)?,
        string_size as usize,
        len,
        budget,
    )?;
    if names.first() != Some(&0) || names.last() != Some(&0) {
        return Err(ObservationGap::MalformedElf);
    }
    Ok(Some(DynamicSymbols { symbols, names }))
}

fn export_api_at(mut byte_at: impl FnMut(usize) -> Option<u8>) -> Option<ObservationApi> {
    // A caller-supplied name may be arbitrarily long or share its index with
    // every symbol. Inspect only finite public spellings plus the exact NUL.
    APIS.iter().copied().find(|api| {
        api.export_name().is_some_and(|name| {
            name.bytes()
                .chain(std::iter::once(0))
                .enumerate()
                .all(|(index, want)| byte_at(index) == Some(want))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooled_inventory_refusal_has_no_read_charge_and_retained_object_recovers() {
        pooled_parse_refusal(false);
    }
    #[test]
    fn pooled_export_refusal_has_no_read_charge_and_retained_object_recovers() {
        pooled_parse_refusal(true);
    }
    fn pooled_parse_refusal(export_checkpoint: bool) {
        let inventory =
            inventory::elf::parser_scratch_bytes(std::fs::metadata("/bin/true").unwrap().len())
                .unwrap();
        let export = MAX_STRINGS as usize + MAX_SYMBOLS as usize * 24 + (1 << 20);
        assert!(
            inventory < export,
            "small file isolates the export-headroom checkpoint"
        );
        for free in [if export_checkpoint {
            export - 1
        } else {
            inventory - 1
        }] {
            let file = File::open("/bin/true").unwrap();
            let object = Object {
                parse_deferred: Cell::new(false),
                stamp: Stamp::of(&file.metadata().unwrap()),
                file,
                expected: None,
                parsed: OnceCell::new(),
                tables: OnceCell::new(),
            };
            let pool = crate::observation_memory::MemoryPool::new(64 << 20);
            let busy = pool.reserve((64 << 20) - free).unwrap();
            let mut budget = ObservationBudget::default();
            budget.memory = Some(pool);
            for _ in 0..3 {
                assert!(object.parsed(&budget).is_err());
                assert_eq!(
                    budget.elf_read_bytes(),
                    0,
                    "shared capacity refused before IO must not consume cumulative read work; free={free}"
                );
                assert!(
                    object.parsed.get().is_none(),
                    "temporary refusal is not a stable parse result"
                );
            }
            drop(busy);
            object
                .parsed(&budget)
                .expect("same retained descriptor must recover");
            let performed = budget.elf_read_bytes();
            assert!(performed > 0);
            object.parsed(&budget).unwrap();
            assert_eq!(
                budget.elf_read_bytes(),
                performed,
                "completed IO remains charged but is not repeated"
            );
        }
    }
    #[test]
    fn pooled_marker_cannot_mask_later_file_or_deadline_failure() {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!(
            "osslscope-parser-failure-transition-{}",
            std::process::id()
        ));
        for changed in [true, false] {
            std::fs::copy("/bin/true", &path).unwrap();
            let file = File::open(&path).unwrap();
            let object = Object {
                parse_deferred: Cell::new(false),
                stamp: Stamp::of(&file.metadata().unwrap()),
                file,
                expected: None,
                parsed: OnceCell::new(),
                tables: OnceCell::new(),
            };
            let pool = crate::observation_memory::MemoryPool::new(64 << 20);
            let busy = pool.reserve(48 << 20).unwrap();
            let mut budget = ObservationBudget::default();
            budget.memory = Some(pool);
            assert_eq!(
                object.parsed(&budget).err(),
                Some(ObservationGap::ReadLimit)
            );
            assert!(object.parse_deferred.get());
            drop(busy);
            let expected = if changed {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"changed")
                    .unwrap();
                ObservationGap::ObjectChanged
            } else {
                budget.set_deadline(std::time::Instant::now());
                ObservationGap::SnapshotLag
            };
            assert_eq!(object.parsed(&budget).err(), Some(expected));
            assert!(
                !object.parse_deferred.get(),
                "new failure is not a shared-capacity refusal"
            );
        }
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn pooled_retry_does_not_reclassify_malformed_or_per_session_read_limits() {
        let path =
            std::env::temp_dir().join(format!("osslscope-stable-parser-{}", std::process::id()));
        std::fs::write(&path, b"not ELF; stable malformed input").unwrap();
        for (file, max_reads, expected_gap, performed) in [
            (
                File::open(&path).unwrap(),
                1 << 20,
                ObservationGap::MalformedElf,
                true,
            ),
            (
                File::open("/bin/true").unwrap(),
                0,
                ObservationGap::ReadLimit,
                false,
            ),
        ] {
            let object = Object {
                parse_deferred: Cell::new(false),
                stamp: Stamp::of(&file.metadata().unwrap()),
                file,
                expected: None,
                parsed: OnceCell::new(),
                tables: OnceCell::new(),
            };
            let pool = crate::observation_memory::MemoryPool::new(64 << 20);
            let mut budget = ObservationBudget::new(super::super::ObservationLimits {
                max_elf_read_bytes: max_reads,
                ..Default::default()
            });
            budget.memory = Some(pool.clone());
            assert_eq!(object.parsed(&budget).err(), Some(expected_gap));
            assert!(object.parsed.get().is_some());
            assert!(!object.parse_deferred.get());
            let reads = budget.elf_read_bytes();
            assert_eq!(
                reads > 0,
                performed,
                "performed work remains cumulative even when parsing failed"
            );
            let busy = pool.reserve(64 << 20).unwrap();
            assert_eq!(object.parsed(&budget).err(), Some(expected_gap));
            drop(busy);
            assert_eq!(object.parsed(&budget).err(), Some(expected_gap));
            assert_eq!(budget.elf_read_bytes(), reads);
        }
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn deadline_errors_do_not_poison_retained_object_parsers() {
        let file = File::open("/bin/true").unwrap();
        let object = Object {
            parse_deferred: Cell::new(false),
            stamp: Stamp::of(&file.metadata().unwrap()),
            file,
            expected: None,
            parsed: OnceCell::new(),
            tables: OnceCell::new(),
        };
        let budget = ObservationBudget::default();
        budget.set_deadline(std::time::Instant::now());
        assert!(matches!(
            object.parsed(&budget),
            Err(ObservationGap::SnapshotLag)
        ));
        assert!(matches!(
            object.tables(&budget),
            Err(ObservationGap::SnapshotLag)
        ));
        assert!(object.parsed.get().is_none() && object.tables.get().is_none());
        budget.set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(5));
        object.parsed(&budget).unwrap();
        let table_result = object.tables(&budget).map(|_| ());
        assert_ne!(table_result, Err(ObservationGap::SnapshotLag));
        assert!(object.tables.get().is_some());
        let reads = budget.elf_read_bytes();
        object.parsed(&budget).unwrap();
        assert_eq!(object.tables(&budget).map(|_| ()), table_result);
        assert!(reads > 0);
        assert_eq!(budget.elf_read_bytes(), reads);
    }

    const CODE: &str = "1000-2000 r-xp 0000 08:01 10 /mapped/code\n";

    #[test]
    fn unrelated_anonymous_and_nonexec_mapping_changes_preserve_identity() {
        let before = format!(
            "{CODE}2000-3000 rw-p 0000 00:00 0 [heap]\n3000-4000 r--p 1000 08:01 10 /mapped/code\n"
        );
        let after = format!(
            "{CODE}4000-5000 --xp 0000 00:00 0 [arbitrary-observer-scratch]\n5000-6000 rw-p 9000 08:02 20 /unrelated/data\n6000-7000 r-xp 0000 00:00 0\n"
        );
        assert_eq!(
            same_executable_mappings(before.as_bytes(), after.as_bytes()),
            Ok(true)
        );
        assert_eq!(
            same_executable_mappings(after.as_bytes(), before.as_bytes()),
            Ok(true)
        );
        assert_eq!(
            same_executable_mappings(CODE.as_bytes(), after.as_bytes()),
            Ok(true)
        );
    }

    #[test]
    fn executable_file_mapping_fields_arrival_and_removal_are_identity() {
        for changed in [
            "1001-2000 r-xp 0000 08:01 10 /mapped/code\n",
            "1000-2001 r-xp 0000 08:01 10 /mapped/code\n",
            "1000-2000 --xp 0000 08:01 10 /mapped/code\n",
            "1000-2000 rwxp 0000 08:01 10 /mapped/code\n",
            "1000-2000 r-xs 0000 08:01 10 /mapped/code\n",
            "1000-2000 r--p 0000 08:01 10 /mapped/code\n",
            "1000-2000 r-xp 1000 08:01 10 /mapped/code\n",
            "1000-2000 r-xp 0000 09:01 10 /mapped/code\n",
            "1000-2000 r-xp 0000 08:02 10 /mapped/code\n",
            "1000-2000 r-xp 0000 08:01 11 /mapped/code\n",
            "1000-2000 r-xp 0000 08:01 0 /mapped/code\n",
            "",
        ] {
            assert_eq!(
                same_executable_mappings(CODE.as_bytes(), changed.as_bytes()),
                Ok(false)
            );
            assert_eq!(
                same_executable_mappings(changed.as_bytes(), CODE.as_bytes()),
                Ok(false)
            );
        }
        let added = format!("{CODE}3000-4000 r-xp 0000 08:01 20 /new/code\n");
        assert_eq!(
            same_executable_mappings(CODE.as_bytes(), added.as_bytes()),
            Ok(false)
        );
        assert_eq!(
            same_executable_mappings(added.as_bytes(), CODE.as_bytes()),
            Ok(false)
        );
    }

    #[test]
    fn mapping_association_changes_remain_a_conservative_fence() {
        let changed = CODE.replace("/mapped/code", "/renamed/code (deleted)");
        assert_eq!(
            same_executable_mappings(CODE.as_bytes(), changed.as_bytes()),
            Ok(false)
        );
        // Equal names cannot hide a replaced backing.
        let replaced = CODE.replace("08:01 10", "08:01 11");
        assert_eq!(
            same_executable_mappings(CODE.as_bytes(), replaced.as_bytes()),
            Ok(false)
        );
    }

    #[test]
    fn malformed_mapping_rows_fail_closed_during_projection() {
        for row in [
            "2000-1000 r-xp 0000 08:01 10 /mapped/code\n",
            "1000-2000 r-qp 0000 08:01 10 /mapped/code\n",
            "1000-2000 r-xp nope 08:01 10 /mapped/code\n",
            "1000-2000 r-xp 0000 no:01 10 /mapped/code\n",
            "1000-2000 r-xp 0000 08:01 no /mapped/code\n",
            "1000-2000 r-xp 0000 08:01 10 /mapped/\0code\n",
            "2000-1000 rw-p 0000 00:00 0\n",
        ] {
            assert_eq!(
                same_executable_mappings(CODE.as_bytes(), row.as_bytes()),
                Err(ObservationGap::MalformedMaps)
            );
            assert_eq!(
                same_executable_mappings(row.as_bytes(), CODE.as_bytes()),
                Err(ObservationGap::MalformedMaps)
            );
        }
    }

    #[test]
    fn shared_long_unknown_names_have_constant_finite_comparison_work() {
        // The same valid long unknown name is referenced repeatedly. Count
        // actual reader accesses, independently of any host timing threshold.
        let mut names = b"\0OSSL_PROVIDER_unquery_operation".to_vec();
        names.resize(65536, b'x');
        names.push(0);
        let longest = APIS
            .iter()
            .filter_map(|api| api.export_name())
            .map(str::len)
            .max()
            .unwrap();
        let mut accesses = 0;
        for _ in 0..129 {
            assert_eq!(
                export_api_at(|index| {
                    accesses += 1;
                    names.get(index + 1).copied()
                }),
                None
            );
        }
        assert!(
            accesses <= 129 * APIS.len() * (longest + 1),
            "name access work exceeded the finite spelling bound: {accesses}"
        );
        for api in APIS {
            let mut exact = api.export_name().unwrap().as_bytes().to_vec();
            exact.push(0);
            assert_eq!(export_api_at(|index| exact.get(index).copied()), Some(api));
            exact.pop();
            assert_eq!(export_api_at(|index| exact.get(index).copied()), None);
            exact.extend_from_slice(b"x\0");
            assert_eq!(export_api_at(|index| exact.get(index).copied()), None);
        }
    }
}
