//! SPDX-License-Identifier: GPL-3.0-or-later
//! Host-only classifier map activation policy.

use crate::discovery::harvest;
use anyhow::{Context as _, bail};
use aya::maps::{HashMap as AyaHashMap, Map, MapData};
use osslscope_ebpf_common as wire;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};

#[derive(Clone, Copy, Debug)]
pub(crate) enum ClassifierRole {
    Harvest,
    Members,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClassifierMapInfo {
    id: u32,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
}

trait ClassifierMapOps {
    fn info(&mut self, fd: BorrowedFd<'_>) -> anyhow::Result<ClassifierMapInfo>;
    fn update(&mut self, fd: BorrowedFd<'_>, key: &[u8; 8], value: &[u8]) -> anyhow::Result<()>;
    fn lookup(
        &mut self,
        fd: BorrowedFd<'_>,
        key: &[u8; 8],
        value_size: usize,
    ) -> anyhow::Result<Vec<u8>>;
    fn keys(&mut self, fd: BorrowedFd<'_>, capacity: u32) -> anyhow::Result<Vec<[u8; 8]>>;
    fn freeze(&mut self, fd: BorrowedFd<'_>) -> anyhow::Result<()>;
}

/// The only classifier activation policy: setup must succeed before the
/// closure that creates the first link is entered.
pub(crate) fn after_classifier_init<T>(
    initialize: impl FnOnce() -> anyhow::Result<()>,
    activate: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    initialize()?;
    activate()
}

pub(crate) fn initialize_classifier_maps(
    maps: &HashMap<String, OwnedFd>,
    role: ClassifierRole,
) -> anyhow::Result<()> {
    initialize_with(maps, role, &mut NativeOps)
}

pub(crate) fn initialize_classifier_maps_controlled(
    maps: &HashMap<String, OwnedFd>,
    role: ClassifierRole,
    links: &crate::capture_setup::SetupLinks,
) -> anyhow::Result<()> {
    let stage = match role {
        ClassifierRole::Harvest => crate::capture::BoundaryStage::Discovery,
        ClassifierRole::Members => crate::capture::BoundaryStage::Traversal,
    };
    initialize_with(maps, role, &mut BorrowedNativeOps(links, stage))
}
struct BorrowedNativeOps<'a>(
    &'a crate::capture_setup::SetupLinks,
    crate::capture::BoundaryStage,
);
impl ClassifierMapOps for BorrowedNativeOps<'_> {
    fn info(&mut self, fd: BorrowedFd<'_>) -> anyhow::Result<ClassifierMapInfo> {
        self.0.check_owned(self.1)?;
        let info = crate::loader::BorrowedMap::checked(fd, self.0, self.1)?.info;
        Ok(ClassifierMapInfo {
            id: info.id,
            map_type: info.map_type,
            key_size: info.key_size,
            value_size: info.value_size,
            max_entries: info.max_entries,
            flags: info.flags,
        })
    }
    fn update(&mut self, fd: BorrowedFd<'_>, key: &[u8; 8], value: &[u8]) -> anyhow::Result<()> {
        self.0.check_owned(self.1)?;
        let map = crate::loader::BorrowedMap::checked(fd, self.0, self.1)?;
        map.shape(&[1], 8, value.len())?;
        map.update(key, value)?;
        Ok(())
    }
    fn lookup(
        &mut self,
        fd: BorrowedFd<'_>,
        key: &[u8; 8],
        value_size: usize,
    ) -> anyhow::Result<Vec<u8>> {
        self.0.check_owned(self.1)?;
        let map = crate::loader::BorrowedMap::checked(fd, self.0, self.1)?;
        map.shape(&[1], 8, value_size)?;
        let mut value = vec![0; value_size];
        map.lookup(key, &mut value)?;
        Ok(value)
    }
    fn keys(&mut self, fd: BorrowedFd<'_>, capacity: u32) -> anyhow::Result<Vec<[u8; 8]>> {
        self.0.check_owned(self.1)?;
        let map = crate::loader::BorrowedMap::checked(fd, self.0, self.1)?;
        anyhow::ensure!(map.info.key_size == 8, "classifier key size");
        map.keys(capacity)?
            .into_iter()
            .map(|key| {
                key.try_into()
                    .map_err(|_| anyhow::anyhow!("classifier key size"))
            })
            .collect()
    }
    fn freeze(&mut self, fd: BorrowedFd<'_>) -> anyhow::Result<()> {
        self.0.check_owned(self.1)?;
        ossl_bpf_sys::map_freeze(fd.as_raw_fd()).context("BPF_MAP_FREEZE")
    }
}

/// Scoped handles let an activation closure move the existing Loaded owner
/// while initialization still addresses the same kernel map identities.
pub(crate) fn clone_classifier_handles(
    maps: &HashMap<String, OwnedFd>,
    role: ClassifierRole,
) -> anyhow::Result<HashMap<String, OwnedFd>> {
    let names: &[&str] = match role {
        ClassifierRole::Harvest => &["ALG_CLASS", "TRIP_CLASS"],
        ClassifierRole::Members => &["ALG_CLASS"],
    };
    names
        .iter()
        .map(|&name| {
            let fd = maps.get(name).context("classifier map missing")?;
            Ok((
                name.to_owned(),
                fd.try_clone().context("clone classifier map fd")?,
            ))
        })
        .collect()
}

#[derive(Clone)]
struct ExpectedMap {
    name: &'static str,
    value_size: u32,
    capacity: u32,
    id: u32,
    values: BTreeMap<[u8; 8], Vec<u8>>,
}

fn expected_alg_from(entries: Vec<(u64, wire::AlgClassValue)>) -> anyhow::Result<ExpectedMap> {
    let mut values = BTreeMap::new();
    for (hash, value) in entries {
        let len = usize::from(value.len);
        if len > wire::MAX_ALG_NAME
            || value.weak > 1
            || (value.class == wire::OTHER_CLASS) != (value.canon == wire::OTHER_CLASS)
            || (value.class == wire::OTHER_CLASS && value.weak != 1)
            || wire::fnv1a64(&value.name[..len]) != hash
        {
            bail!("invalid ALG_CLASS registry entry");
        }
        if values
            .insert(hash.to_le_bytes(), wire::alg_value_bytes(&value).to_vec())
            .is_some()
        {
            bail!("duplicate ALG_CLASS registry key");
        }
    }
    Ok(ExpectedMap {
        name: "ALG_CLASS",
        value_size: 42,
        capacity: 1024,
        id: 0,
        values,
    })
}

fn expected_trip_from(entries: Vec<(u64, wire::TripClassValue)>) -> anyhow::Result<ExpectedMap> {
    let mut values = BTreeMap::new();
    for (hash, value) in entries {
        let len = usize::from(value.len);
        if len > wire::MAX_TRIP_NAME || wire::fnv1a64(&value.name[..len]) != hash {
            bail!("invalid TRIP_CLASS registry entry");
        }
        if values
            .insert(hash.to_le_bytes(), wire::trip_value_bytes(&value).to_vec())
            .is_some()
        {
            bail!("duplicate TRIP_CLASS registry key");
        }
    }
    Ok(ExpectedMap {
        name: "TRIP_CLASS",
        value_size: 22,
        capacity: 64,
        id: 0,
        values,
    })
}

fn validate_shape(actual: ClassifierMapInfo, expected: &ExpectedMap) -> anyhow::Result<()> {
    if actual.id == 0
        || actual.map_type != 1
        || actual.key_size != 8
        || actual.value_size != expected.value_size
        || actual.max_entries != expected.capacity
        || actual.flags != 0
    {
        bail!("{} classifier map identity/shape invalid", expected.name);
    }
    Ok(())
}

fn readback<O: ClassifierMapOps>(
    maps: &HashMap<String, OwnedFd>,
    expected: &ExpectedMap,
    ops: &mut O,
) -> anyhow::Result<()> {
    let fd = maps
        .get(expected.name)
        .context("classifier map missing")?
        .as_fd();
    let keys = ops
        .keys(fd, expected.capacity)
        .map_err(|_| anyhow::anyhow!("classifier key enumeration failed"))?;
    if keys.len() > expected.capacity as usize || keys.len() != expected.values.len() {
        bail!("{} classifier key set differs", expected.name);
    }
    let mut seen = HashSet::with_capacity(keys.len());
    for key in keys {
        if !seen.insert(key) {
            bail!("{} classifier key repeated", expected.name);
        }
        let wanted = expected
            .values
            .get(&key)
            .context("classifier key unexpected")?;
        let actual = ops
            .lookup(fd, &key, expected.value_size as usize)
            .map_err(|_| anyhow::anyhow!("classifier readback failed"))?;
        if actual.len() != expected.value_size as usize || &actual != wanted {
            bail!("{} classifier value differs", expected.name);
        }
    }
    Ok(())
}

fn initialize_with<O: ClassifierMapOps>(
    maps: &HashMap<String, OwnedFd>,
    role: ClassifierRole,
    ops: &mut O,
) -> anyhow::Result<()> {
    let alg = harvest::build_alg_entries()?;
    let trip = if matches!(role, ClassifierRole::Harvest) {
        Some(harvest::build_trip_entries()?)
    } else {
        None
    };
    initialize_with_entries(maps, role, ops, alg, trip)
}

fn initialize_with_entries<O: ClassifierMapOps>(
    maps: &HashMap<String, OwnedFd>,
    role: ClassifierRole,
    ops: &mut O,
    alg: Vec<(u64, wire::AlgClassValue)>,
    trip: Option<Vec<(u64, wire::TripClassValue)>>,
) -> anyhow::Result<()> {
    let mut expected = vec![expected_alg_from(alg)?];
    if matches!(role, ClassifierRole::Harvest) {
        expected.push(expected_trip_from(
            trip.context("TRIP_CLASS registry missing")?,
        )?);
    }
    let mut ids = HashSet::new();
    for table in &mut expected {
        if table.values.len() > table.capacity as usize
            || table
                .values
                .values()
                .any(|v| v.len() != table.value_size as usize)
        {
            bail!("{} classifier registry exceeds map shape", table.name);
        }
        let fd = maps
            .get(table.name)
            .context("classifier map missing")?
            .as_fd();
        let info = ops
            .info(fd)
            .map_err(|_| anyhow::anyhow!("classifier map info failed"))?;
        validate_shape(info, table)?;
        if !ids.insert(info.id) {
            bail!("classifier map IDs repeat");
        }
        table.id = info.id;
    }
    for table in &expected {
        let fd = maps
            .get(table.name)
            .context("classifier map missing")?
            .as_fd();
        for (key, value) in &table.values {
            ops.update(fd, key, value)
                .map_err(|_| anyhow::anyhow!("populate {} classifier map failed", table.name))?;
        }
    }
    for table in &expected {
        readback(maps, table, ops)?;
    }
    for table in &expected {
        let fd = maps
            .get(table.name)
            .context("classifier map missing")?
            .as_fd();
        ops.freeze(fd)
            .map_err(|_| anyhow::anyhow!("freeze {} classifier map failed", table.name))?;
    }
    for table in &expected {
        let fd = maps
            .get(table.name)
            .context("classifier map missing")?
            .as_fd();
        let info = ops
            .info(fd)
            .map_err(|_| anyhow::anyhow!("classifier final map info failed"))?;
        validate_shape(info, table)?;
        if info.id != table.id {
            bail!("{} classifier map ID changed", table.name);
        }
        readback(maps, table, ops)?;
    }
    Ok(())
}

struct NativeOps;

impl NativeOps {
    fn data(fd: BorrowedFd<'_>) -> anyhow::Result<MapData> {
        let clone = fd.try_clone_to_owned().context("clone classifier map fd")?;
        MapData::from_fd(clone).context("classifier mapdata")
    }
}

impl ClassifierMapOps for NativeOps {
    fn info(&mut self, fd: BorrowedFd<'_>) -> anyhow::Result<ClassifierMapInfo> {
        let info = Self::data(fd)?.info().context("classifier map info")?;
        Ok(ClassifierMapInfo {
            id: info.id(),
            map_type: info.map_type().context("classifier map type")? as u32,
            key_size: info.key_size(),
            value_size: info.value_size(),
            max_entries: info.max_entries(),
            flags: info.map_flags(),
        })
    }

    fn update(&mut self, fd: BorrowedFd<'_>, key: &[u8; 8], value: &[u8]) -> anyhow::Result<()> {
        let map = Map::from_map_data(Self::data(fd)?).context("classifier map shape")?;
        match value.len() {
            42 => {
                let mut hash = AyaHashMap::<_, [u8; 8], [u8; 42]>::try_from(map)?;
                let bytes: [u8; 42] = value.try_into().context("algorithm value length")?;
                hash.insert(*key, bytes, 0)?;
            }
            22 => {
                let mut hash = AyaHashMap::<_, [u8; 8], [u8; 22]>::try_from(map)?;
                let bytes: [u8; 22] = value.try_into().context("trip value length")?;
                hash.insert(*key, bytes, 0)?;
            }
            _ => bail!("invalid classifier value length"),
        }
        Ok(())
    }

    fn lookup(
        &mut self,
        fd: BorrowedFd<'_>,
        key: &[u8; 8],
        value_size: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let map = Map::from_map_data(Self::data(fd)?).context("classifier map shape")?;
        match value_size {
            42 => Ok(AyaHashMap::<_, [u8; 8], [u8; 42]>::try_from(map)?
                .get(key, 0)?
                .to_vec()),
            22 => Ok(AyaHashMap::<_, [u8; 8], [u8; 22]>::try_from(map)?
                .get(key, 0)?
                .to_vec()),
            _ => bail!("invalid classifier value length"),
        }
    }

    fn keys(&mut self, fd: BorrowedFd<'_>, capacity: u32) -> anyhow::Result<Vec<[u8; 8]>> {
        let data = Self::data(fd)?;
        let info = data.info().context("classifier map info")?;
        let map = Map::from_map_data(data).context("classifier map shape")?;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        match info.value_size() {
            42 => {
                let hash = AyaHashMap::<_, [u8; 8], [u8; 42]>::try_from(map)?;
                for item in hash.keys().take(capacity as usize + 1) {
                    let key = item.context("classifier key iteration")?;
                    if !seen.insert(key) || out.len() >= capacity as usize {
                        bail!("classifier key iteration repeats or exceeds capacity");
                    }
                    out.push(key);
                }
            }
            22 => {
                let hash = AyaHashMap::<_, [u8; 8], [u8; 22]>::try_from(map)?;
                for item in hash.keys().take(capacity as usize + 1) {
                    let key = item.context("classifier key iteration")?;
                    if !seen.insert(key) || out.len() >= capacity as usize {
                        bail!("classifier key iteration repeats or exceeds capacity");
                    }
                    out.push(key);
                }
            }
            _ => bail!("invalid classifier value length"),
        }
        Ok(out)
    }

    fn freeze(&mut self, fd: BorrowedFd<'_>) -> anyhow::Result<()> {
        ossl_bpf_sys::map_freeze(fd.as_raw_fd()).context("BPF_MAP_FREEZE")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::fd::RawFd;
    use std::os::unix::net::UnixStream;

    struct FakeMap {
        info: ClassifierMapInfo,
        values: BTreeMap<[u8; 8], Vec<u8>>,
        frozen: bool,
    }

    #[derive(Default)]
    struct RecordingOps {
        maps: HashMap<RawFd, FakeMap>,
        peers: Vec<UnixStream>,
        events: Vec<(u32, &'static str)>,
        closed_checks: usize,
        fail: Option<(u32, &'static str)>,
        corrupt: Option<&'static str>,
    }

    impl RecordingOps {
        fn fixture(role: ClassifierRole) -> (HashMap<String, OwnedFd>, Self) {
            let mut handles = HashMap::new();
            let mut ops = Self::default();
            for (name, id, value_size, capacity) in
                [("ALG_CLASS", 101, 42, 1024), ("TRIP_CLASS", 102, 22, 64)]
            {
                if name == "TRIP_CLASS" && matches!(role, ClassifierRole::Members) {
                    continue;
                }
                let (stream, peer) = UnixStream::pair().unwrap();
                let fd: OwnedFd = stream.into();
                ops.peers.push(peer);
                ops.maps.insert(
                    fd.as_raw_fd(),
                    FakeMap {
                        info: ClassifierMapInfo {
                            id,
                            map_type: 1,
                            key_size: 8,
                            value_size,
                            max_entries: capacity,
                            flags: 0,
                        },
                        values: BTreeMap::new(),
                        frozen: false,
                    },
                );
                handles.insert(name.to_owned(), fd);
            }
            (handles, ops)
        }

        fn touch(&mut self, fd: BorrowedFd<'_>, stage: &'static str) -> anyhow::Result<u32> {
            let clone = fd.try_clone_to_owned()?;
            let clone_number = clone.as_raw_fd();
            // Each fixture socket has a unique inode. A concurrent test may
            // reuse the numeric slot, but it cannot still refer to this map.
            let mut before: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: fstat writes to a valid stat buffer for a live fd.
            assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut before) }, 0);
            drop(clone);
            // Check immediately: later operations may reuse the numeric slot.
            // SAFETY: F_GETFD only queries a numeric descriptor.
            let mut after: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: fstat either reports EBADF or fills this valid buffer.
            if unsafe { libc::fstat(clone_number, &mut after) } == 0 {
                assert_ne!((before.st_dev, before.st_ino), (after.st_dev, after.st_ino));
            } else {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF)
                );
            }
            self.closed_checks += 1;
            let id = self.maps[&fd.as_raw_fd()].info.id;
            self.events.push((id, stage));
            if self.fail == Some((id, stage)) {
                bail!("TARGET_CANARY private observed value");
            }
            Ok(id)
        }

        fn clones_closed(&self) {
            assert_eq!(self.closed_checks, self.events.len());
        }
    }

    /// Loader host policy tests use the real initializer on its scoped
    /// classifier handles, with only the kernel map operations modeled.
    pub(crate) fn host_initialize_members(
        handles: &HashMap<String, OwnedFd>,
        fail_stage: Option<&'static str>,
    ) -> anyhow::Result<()> {
        let mut ops = RecordingOps::default();
        for (name, fd) in handles {
            assert_eq!(name, "ALG_CLASS");
            ops.maps.insert(
                fd.as_raw_fd(),
                FakeMap {
                    info: ClassifierMapInfo {
                        id: 101,
                        map_type: 1,
                        key_size: 8,
                        value_size: 42,
                        max_entries: 1024,
                        flags: 0,
                    },
                    values: BTreeMap::new(),
                    frozen: false,
                },
            );
        }
        ops.fail = fail_stage.map(|stage| (101, stage));
        let result = initialize_with(handles, ClassifierRole::Members, &mut ops);
        if result.is_ok() {
            assert_eq!(ops.maps.len(), 1);
            assert!(ops.maps.values().all(|map| map.frozen));
        }
        ops.clones_closed();
        result
    }

    impl ClassifierMapOps for RecordingOps {
        fn info(&mut self, fd: BorrowedFd<'_>) -> anyhow::Result<ClassifierMapInfo> {
            let final_read = self.maps[&fd.as_raw_fd()].frozen;
            self.touch(fd, if final_read { "final_info" } else { "info" })?;
            let mut info = self.maps[&fd.as_raw_fd()].info;
            if self.corrupt == Some("id_drift") && final_read {
                info.id += 1;
            }
            Ok(info)
        }
        fn update(
            &mut self,
            fd: BorrowedFd<'_>,
            key: &[u8; 8],
            value: &[u8],
        ) -> anyhow::Result<()> {
            self.touch(fd, "update")?;
            let map = self.maps.get_mut(&fd.as_raw_fd()).unwrap();
            if map.frozen {
                bail!("already frozen");
            }
            map.values.insert(*key, value.to_vec());
            Ok(())
        }
        fn lookup(
            &mut self,
            fd: BorrowedFd<'_>,
            key: &[u8; 8],
            value_size: usize,
        ) -> anyhow::Result<Vec<u8>> {
            let final_read = self.maps[&fd.as_raw_fd()].frozen;
            self.touch(fd, if final_read { "final_lookup" } else { "lookup" })?;
            let mut value = self.maps[&fd.as_raw_fd()]
                .values
                .get(key)
                .context("missing")?
                .clone();
            if self.corrupt == Some("wrong_value") && !final_read {
                value[0] ^= 1;
            }
            assert_eq!(value.len(), value_size);
            Ok(value)
        }
        fn keys(&mut self, fd: BorrowedFd<'_>, capacity: u32) -> anyhow::Result<Vec<[u8; 8]>> {
            let final_read = self.maps[&fd.as_raw_fd()].frozen;
            self.touch(fd, if final_read { "final_keys" } else { "keys" })?;
            let mut keys: Vec<_> = self.maps[&fd.as_raw_fd()].values.keys().copied().collect();
            if !final_read {
                match self.corrupt {
                    Some("missing") => {
                        keys.pop();
                    }
                    Some("extra") => {
                        keys.push(u64::MAX.to_le_bytes());
                    }
                    Some("repeat") => {
                        keys[1] = keys[0];
                    }
                    Some("over_capacity") => {
                        keys.resize(capacity as usize + 1, [255; 8]);
                    }
                    _ => {}
                }
            }
            Ok(keys)
        }
        fn freeze(&mut self, fd: BorrowedFd<'_>) -> anyhow::Result<()> {
            self.touch(fd, "freeze")?;
            if self.corrupt == Some("already_frozen") {
                bail!("already frozen");
            }
            let map = self.maps.get_mut(&fd.as_raw_fd()).unwrap();
            if map.frozen {
                bail!("already frozen");
            }
            map.frozen = true;
            if self.corrupt == Some("post_freeze_value") {
                map.values.values_mut().next().unwrap()[0] ^= 1;
            }
            Ok(())
        }
    }

    fn run_model(
        maps: &HashMap<String, OwnedFd>,
        role: ClassifierRole,
        ops: &mut RecordingOps,
    ) -> (bool, anyhow::Result<()>) {
        let mut activated = false;
        let result = after_classifier_init(
            || initialize_with(maps, role, ops),
            || {
                activated = true;
                Ok(())
            },
        );
        (activated, result)
    }

    #[test]
    fn complete_images_freeze_before_activation() {
        for role in [ClassifierRole::Harvest, ClassifierRole::Members] {
            let (maps, mut ops) = RecordingOps::fixture(role);
            let (activated, result) = run_model(&maps, role, &mut ops);
            result.unwrap();
            assert!(activated);
            let first_update = ops.events.iter().position(|e| e.1 == "update").unwrap();
            let first_keys = ops.events.iter().position(|e| e.1 == "keys").unwrap();
            let first_freeze = ops.events.iter().position(|e| e.1 == "freeze").unwrap();
            let first_final = ops.events.iter().position(|e| e.1 == "final_info").unwrap();
            assert!(ops.events[..first_update].iter().all(|e| e.1 == "info"));
            assert!(
                ops.events[first_update..first_keys]
                    .iter()
                    .all(|e| e.1 == "update")
            );
            assert!(
                ops.events[first_keys..first_freeze]
                    .iter()
                    .all(|e| matches!(e.1, "keys" | "lookup"))
            );
            assert!(
                ops.events[first_freeze..first_final]
                    .iter()
                    .all(|e| e.1 == "freeze")
            );
            for (name, fd) in &maps {
                let model = &ops.maps[&fd.as_raw_fd()];
                assert!(model.frozen, "{name}");
                let expected: BTreeMap<[u8; 8], Vec<u8>> = if name == "ALG_CLASS" {
                    harvest::build_alg_entries()
                        .unwrap()
                        .into_iter()
                        .map(|(k, v)| (k.to_le_bytes(), wire::alg_value_bytes(&v).to_vec()))
                        .collect()
                } else {
                    harvest::build_trip_entries()
                        .unwrap()
                        .into_iter()
                        .map(|(k, v)| (k.to_le_bytes(), wire::trip_value_bytes(&v).to_vec()))
                        .collect()
                };
                assert_eq!(model.values, expected, "{name}");
            }
            ops.clones_closed();
        }
    }

    #[test]
    fn every_map_operation_failure_refuses_activation_without_target_diagnostics() {
        for role in [ClassifierRole::Harvest, ClassifierRole::Members] {
            let ids: &[u32] = if matches!(role, ClassifierRole::Harvest) {
                &[101, 102]
            } else {
                &[101]
            };
            for &id in ids {
                for stage in [
                    "info",
                    "update",
                    "keys",
                    "lookup",
                    "freeze",
                    "final_info",
                    "final_keys",
                    "final_lookup",
                ] {
                    let (maps, mut ops) = RecordingOps::fixture(role);
                    ops.fail = Some((id, stage));
                    let (activated, result) = run_model(&maps, role, &mut ops);
                    let message = format!("{:#}", result.unwrap_err());
                    assert!(!activated, "{id} {stage}");
                    assert!(
                        !message.contains("TARGET_CANARY"),
                        "{id} {stage}: {message}"
                    );
                    assert!(
                        ops.events.iter().any(|event| *event == (id, stage)),
                        "{id} {stage}"
                    );
                    ops.clones_closed();
                }
            }
        }
    }

    #[test]
    fn wrong_sets_shapes_and_post_freeze_drift_refuse_activation() {
        for corrupt in [
            "missing",
            "extra",
            "repeat",
            "over_capacity",
            "wrong_value",
            "id_drift",
            "post_freeze_value",
            "already_frozen",
        ] {
            let (maps, mut ops) = RecordingOps::fixture(ClassifierRole::Harvest);
            ops.corrupt = Some(corrupt);
            let (activated, result) = run_model(&maps, ClassifierRole::Harvest, &mut ops);
            assert!(!activated && result.is_err(), "{corrupt}");
            ops.clones_closed();
        }
        for bad in [
            "zero_id",
            "wrong_type",
            "wrong_key",
            "wrong_value_size",
            "wrong_capacity",
            "flags",
            "same_id",
        ] {
            let (maps, mut ops) = RecordingOps::fixture(ClassifierRole::Harvest);
            let alg = maps["ALG_CLASS"].as_raw_fd();
            let trip = maps["TRIP_CLASS"].as_raw_fd();
            match bad {
                "zero_id" => ops.maps.get_mut(&alg).unwrap().info.id = 0,
                "wrong_type" => ops.maps.get_mut(&alg).unwrap().info.map_type = 2,
                "wrong_key" => ops.maps.get_mut(&alg).unwrap().info.key_size = 4,
                "wrong_value_size" => ops.maps.get_mut(&alg).unwrap().info.value_size = 41,
                "wrong_capacity" => ops.maps.get_mut(&alg).unwrap().info.max_entries = 2,
                "flags" => ops.maps.get_mut(&alg).unwrap().info.flags = 1,
                "same_id" => ops.maps.get_mut(&trip).unwrap().info.id = 101,
                _ => unreachable!(),
            }
            let (activated, result) = run_model(&maps, ClassifierRole::Harvest, &mut ops);
            assert!(!activated && result.is_err(), "{bad}");
            ops.clones_closed();
        }
    }

    #[test]
    fn duplicate_and_invalid_expected_entries_refuse_activation() {
        let (maps, mut ops) = RecordingOps::fixture(ClassifierRole::Members);
        let mut alg = harvest::build_alg_entries().unwrap();
        alg.push(alg[0]);
        let mut activated = false;
        let result = after_classifier_init(
            || initialize_with_entries(&maps, ClassifierRole::Members, &mut ops, alg, None),
            || {
                activated = true;
                Ok(())
            },
        );
        assert!(result.is_err() && !activated);
        assert!(ops.events.is_empty());
        let (maps, mut ops) = RecordingOps::fixture(ClassifierRole::Members);
        let mut alg = harvest::build_alg_entries().unwrap();
        alg[0].1.len = 37;
        let mut activated = false;
        let result = after_classifier_init(
            || initialize_with_entries(&maps, ClassifierRole::Members, &mut ops, alg, None),
            || {
                activated = true;
                Ok(())
            },
        );
        assert!(result.is_err() && !activated);
        assert!(ops.events.is_empty());
        ops.clones_closed();
        let (maps, mut ops) = RecordingOps::fixture(ClassifierRole::Harvest);
        let alg = harvest::build_alg_entries().unwrap();
        let mut trip = harvest::build_trip_entries().unwrap();
        trip.push(trip[0]);
        let mut activated = false;
        let result = after_classifier_init(
            || initialize_with_entries(&maps, ClassifierRole::Harvest, &mut ops, alg, Some(trip)),
            || {
                activated = true;
                Ok(())
            },
        );
        assert!(result.is_err() && !activated);
        assert!(ops.events.is_empty());
    }

    #[test]
    fn missing_role_map_and_partial_handle_clone_refuse_activation() {
        let (mut maps, mut ops) = RecordingOps::fixture(ClassifierRole::Harvest);
        let alg_fd = maps["ALG_CLASS"].as_raw_fd();
        let identity = std::fs::read_link(format!("/proc/self/fd/{alg_fd}"))
            .expect("fixture descriptor identity");
        let count_identity = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
                .filter(|link| link == &identity)
                .count()
        };
        assert_eq!(count_identity(), 1);
        maps.remove("TRIP_CLASS");
        assert!(clone_classifier_handles(&maps, ClassifierRole::Harvest).is_err());
        assert_eq!(
            count_identity(),
            1,
            "partially cloned role handles must close"
        );
        let (activated, result) = run_model(&maps, ClassifierRole::Harvest, &mut ops);
        assert!(!activated && result.is_err());
        ops.clones_closed();
    }

    #[test]
    fn classifier_failure_refuses_activation() {
        let mut activated = false;
        let result = after_classifier_init(
            || anyhow::bail!("classifier setup failed"),
            || {
                activated = true;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!activated);
    }
}
