// SPDX-License-Identifier: GPL-3.0-or-later
//! Observer-owned backing anchor. This is not registration or target authority.

use super::{ObjectHash, ObservationBudget, ObservationGap};
use sha2::Digest;

use std::{fs::File, os::fd::AsRawFd, ptr::NonNull};
const HASH_CHUNK: usize = 16 << 10;

/// A retained self-mapping pins its actual backing, including overlay lower
/// inodes. It does not prove that a target registration used that inode.
pub(crate) struct SourceAnchor {
    address: NonNull<libc::c_void>,
    length: usize,
    _file: File,
    _capacity: super::super::schema::StateReservation,
}
impl SourceAnchor {
    pub(crate) fn capture(
        file: &File,
        expected: &ObjectHash,
        budget: &ObservationBudget,
    ) -> Result<Self, ObservationGap> {
        budget.checkpoint()?;
        let metadata = file
            .metadata()
            .map_err(|_| ObservationGap::BackingUnavailable)?;
        let length = usize::try_from(metadata.len()).map_err(|_| ObservationGap::ReadLimit)?;
        if !metadata.is_file() || length == 0 || metadata.len() > super::MAX_OBJECT {
            return Err(ObservationGap::ReadLimit);
        }
        // Base-page size is an observer ABI property; no kernel layout guess.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|p| p.is_power_of_two())
            .ok_or(ObservationGap::StateLimit)?;
        let pages = length
            .checked_add(page - 1)
            .ok_or(ObservationGap::StateLimit)?
            / page;
        let capacity = pages
            .checked_mul(page)
            .and_then(|n| {
                pages
                    .checked_mul(64)
                    .and_then(|overhead| n.checked_add(overhead))
            })
            .and_then(|n| n.checked_add(4096))
            .ok_or(ObservationGap::StateLimit)?;
        let capacity = budget.reserve_state(capacity)?;
        let scratch = budget.reserve_state(HASH_CHUNK)?;
        crate::lifecycle_producer::note_acquisition()
            .map_err(|_| ObservationGap::BackingUnavailable)?;
        let owned = file
            .try_clone()
            .map_err(|_| ObservationGap::BackingUnavailable)?;
        // SAFETY: mmap creates an observer-owned read-only, nonexecutable mapping
        // of this retained descriptor. No Rust reference is formed to its bytes.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                owned.as_raw_fd(),
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(ObservationGap::BackingUnavailable);
        }
        let Some(address) = NonNull::new(raw) else {
            // A null mapping is not used even on a host permitting address zero.
            unsafe {
                libc::munmap(raw, length);
            }
            return Err(ObservationGap::BackingUnavailable);
        };
        let anchor = Self {
            address,
            length,
            _file: owned,
            _capacity: capacity,
        };
        if &anchor.digest(budget, &scratch)? != expected {
            return Err(ObservationGap::ObjectChanged);
        }
        Ok(anchor)
    }
    /// Mapping base address for BPF-side joins. The mapping outlives this
    /// borrow: the anchor owner retains the mapping and its backing file.
    pub(crate) fn address(&self) -> u64 {
        self.address.as_ptr() as u64
    }
    fn digest(
        &self,
        budget: &ObservationBudget,
        _scratch: &super::super::schema::StateReservation,
    ) -> Result<ObjectHash, ObservationGap> {
        budget.read(self.length as u64)?;
        let mut bytes = [0u8; HASH_CHUNK];
        let mut hash = sha2::Sha256::new();
        let mut offset = 0;
        while offset < self.length {
            budget.checkpoint()?;
            let length = HASH_CHUNK.min(self.length - offset);
            let local = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: length,
            };
            let remote = libc::iovec {
                iov_base: (self.address.as_ptr() as usize)
                    .checked_add(offset)
                    .ok_or(ObservationGap::ObjectChanged)?
                    as *mut libc::c_void,
                iov_len: length,
            };
            // SAFETY: destination is a live writable slice. Source is ONLY this
            // observer's retained mapping. Kernel fault handling returns an error
            // for truncation/unmapping; direct Rust loads could instead SIGBUS.
            let copied =
                unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
            if copied != length as isize {
                return Err(ObservationGap::ObjectChanged);
            }
            hash.update(&bytes[..length]);
            offset += length;
        }
        hash.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .try_into()
            .map_err(|_| ObservationGap::ObjectChanged)
    }
}
impl Drop for SourceAnchor {
    fn drop(&mut self) {
        // SAFETY: this owner alone controls this exact mapping. Required link/
        // consumer owners must be retired before they release their anchor Rc.
        unsafe {
            libc::munmap(self.address.as_ptr(), self.length);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        os::unix::fs::FileExt,
        time::{SystemTime, UNIX_EPOCH},
    };
    struct Fixture {
        path: std::path::PathBuf,
        file: std::fs::File,
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "osslscope-anchor-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.write_all(&vec![7; 8192]).unwrap();
            Self { path, file }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
    #[test]
    fn mapped_anchor_hashes_its_own_backing_and_faults_return_errors() {
        let fixture = Fixture::new();
        let hash: ObjectHash = sha2::Sha256::digest(vec![7; 8192])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .try_into()
            .unwrap();
        let budget = ObservationBudget::default();
        let anchor = SourceAnchor::capture(&fixture.file, &hash, &budget).unwrap();
        let scratch = budget.reserve_state(HASH_CHUNK).unwrap();
        fixture.file.write_at(&[8], 0).unwrap();
        assert_ne!(anchor.digest(&budget, &scratch).unwrap(), hash);
        fixture.file.set_len(0).unwrap();
        assert_eq!(
            anchor.digest(&budget, &scratch),
            Err(ObservationGap::ObjectChanged)
        );
    }
    #[test]
    fn anchor_refuses_wrong_artifact_and_capacity_before_mapping() {
        let fixture = Fixture::new();
        let hash = "0".repeat(64).try_into().unwrap();
        let budget = ObservationBudget::default();
        assert!(matches!(
            SourceAnchor::capture(&fixture.file, &hash, &budget),
            Err(ObservationGap::ObjectChanged)
        ));
        let budget = ObservationBudget::new(super::super::super::ObservationLimits {
            max_state_bytes: 1,
            ..Default::default()
        });
        assert!(matches!(
            SourceAnchor::capture(&fixture.file, &hash, &budget),
            Err(ObservationGap::StateLimit)
        ));
        budget.state(1).unwrap();
    }
}
