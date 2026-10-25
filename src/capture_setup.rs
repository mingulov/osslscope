//! SPDX-License-Identifier: GPL-3.0-or-later
//! Native pre-release link custody. The application coordinator adds its real
//! prepared-window and Count observer to this state at the integration boundary.
use crate::capture::{BoundaryFailure, BoundaryFailureClass, BoundaryStage};
use crate::discovery::session::{LinkEntry, LinkKind, LinkSet};
use std::os::fd::OwnedFd;
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

pub(crate) const MAX_SETUP_LINKS: usize = 1024;
const MAX_TEMPORARY_FDS: usize = 4;

#[derive(Clone)]
pub(crate) enum SetupInterrupt {
    Static(&'static AtomicBool),
    Owned(Arc<AtomicBool>),
}
impl SetupInterrupt {
    fn raised(&self) -> bool {
        match self {
            Self::Static(flag) => flag.load(Ordering::Acquire),
            Self::Owned(flag) => flag.load(Ordering::Acquire),
        }
    }
}
#[derive(Clone)]
pub(crate) struct SetupControl {
    deadline: Instant,
    interrupted: SetupInterrupt,
    abandoned: Arc<AtomicBool>,
}
#[derive(Debug, Clone)]
pub(crate) enum SetupFailure {
    Cancelled { stage: BoundaryStage },
    Resource { stage: BoundaryStage },
    Boundary(BoundaryFailure),
}
impl std::fmt::Display for SetupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled { stage } => write!(f, "setup cancelled at {stage:?}"),
            Self::Resource { stage } => write!(f, "setup resource capacity exhausted at {stage:?}"),
            Self::Boundary(failure) => f.write_str(&failure.detail),
        }
    }
}
impl std::error::Error for SetupFailure {}
impl SetupFailure {
    pub(crate) fn io(stage: BoundaryStage, error: &std::io::Error, detail: &str) -> Self {
        Self::Boundary(BoundaryFailure::new(
            stage,
            BoundaryFailureClass::Io,
            error.raw_os_error(),
            detail,
        ))
    }

    pub(crate) fn from_error(stage: BoundaryStage, error: anyhow::Error) -> Self {
        Self::from_error_ref(stage, &error)
    }
    pub(crate) fn from_error_ref(stage: BoundaryStage, error: &anyhow::Error) -> Self {
        if let Some(failure) = error.downcast_ref::<Self>() {
            return failure.clone();
        }
        Self::Boundary(BoundaryFailure::from_error(stage, error))
    }
}
impl SetupControl {
    pub(crate) fn new(deadline: Instant, interrupted: SetupInterrupt) -> Self {
        Self {
            deadline,
            interrupted,
            abandoned: Arc::new(AtomicBool::new(false)),
        }
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn abandon(&self) {
        self.abandoned.store(true, Ordering::Release);
    }
    pub(crate) fn check(&self, stage: BoundaryStage) -> Result<(), SetupFailure> {
        if self.interrupted.raised() || self.abandoned.load(Ordering::Acquire) {
            return Err(SetupFailure::Cancelled { stage });
        }
        if Instant::now() >= self.deadline {
            return Err(SetupFailure::Boundary(BoundaryFailure::new(
                stage,
                BoundaryFailureClass::Timeout,
                None,
                "setup deadline expired",
            )));
        }
        Ok(())
    }
}
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// This is the one native custody mutex; no separate Ready/acceptance protocol.
#[derive(Clone)]
pub(crate) struct SetupLinks(Arc<Mutex<NativeState>>);
struct NativeState {
    abandoned: bool,
    failure: Option<SetupFailure>,
    in_flight: usize,
    temporary: usize,
    discovery: Vec<LinkEntry>,
    retired_discovery: Vec<LinkEntry>,
    members: Vec<MemberLink>,
    retired_members: Vec<MemberLink>,
    pins: Vec<OwnedFd>,
}
pub(crate) struct MemberLink {
    pub(crate) slot: Option<u32>,
    pub(crate) link: OwnedFd,
}
pub(crate) struct SetupLinkCustody {
    discovery: Vec<LinkEntry>,
    retired_discovery: Vec<LinkEntry>,
    pins: Vec<OwnedFd>,
    members: Vec<MemberLink>,
    retired_members: Vec<MemberLink>,
}
impl SetupLinks {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(NativeState {
            abandoned: false,
            failure: None,
            in_flight: 0,
            temporary: 0,
            discovery: Vec::with_capacity(MAX_SETUP_LINKS),
            retired_discovery: Vec::with_capacity(MAX_SETUP_LINKS),
            members: Vec::with_capacity(MAX_SETUP_LINKS),
            retired_members: Vec::with_capacity(MAX_SETUP_LINKS),
            pins: Vec::with_capacity(MAX_SETUP_LINKS),
        })))
    }
    pub(crate) fn seal(&self, failure: SetupFailure) {
        let mut state = locked(&self.0);
        state.abandoned = true;
        if state.failure.is_none() {
            state.failure = Some(failure);
        }
    }
    fn sealed_failure(state: &NativeState, stage: BoundaryStage) -> SetupFailure {
        state
            .failure
            .clone()
            .unwrap_or(SetupFailure::Cancelled { stage })
    }
    fn check(&self, control: &SetupControl, stage: BoundaryStage) -> Result<(), SetupFailure> {
        let state = locked(&self.0);
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        control.check(stage)?;
        if state.abandoned {
            return Err(Self::sealed_failure(&state, stage));
        }
        Ok(())
    }
    pub(crate) fn reserve(
        &self,
        control: &SetupControl,
        stage: BoundaryStage,
        count: usize,
    ) -> Result<SetupLinkReservation, SetupFailure> {
        let mut state = locked(&self.0);
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        control.check(stage)?;
        if state.abandoned {
            return Err(Self::sealed_failure(&state, stage));
        }
        let used = state.discovery.len()
            + state.retired_discovery.len()
            + state.members.len()
            + state.retired_members.len()
            + state.in_flight;
        if count > MAX_SETUP_LINKS - used {
            let failure = SetupFailure::Resource { stage };
            state.abandoned = true;
            state.failure = Some(failure.clone());
            return Err(failure);
        }
        state.in_flight += count;
        Ok(SetupLinkReservation {
            links: self.clone(),
            remaining: count,
            stage,
        })
    }
    pub(crate) fn temporary(
        &self,
        control: &SetupControl,
        stage: BoundaryStage,
        count: usize,
    ) -> Result<TemporaryFds, SetupFailure> {
        let mut state = locked(&self.0);
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        control.check(stage)?;
        if state.abandoned {
            return Err(Self::sealed_failure(&state, stage));
        }
        if count > MAX_TEMPORARY_FDS - state.temporary {
            let failure = SetupFailure::Resource { stage };
            state.abandoned = true;
            state.failure = Some(failure.clone());
            return Err(failure);
        }
        state.temporary += count;
        Ok(TemporaryFds {
            links: self.clone(),
            count,
        })
    }
    fn publish_discovery(
        &self,
        entry: LinkEntry,
        stage: BoundaryStage,
    ) -> Result<(), SetupFailure> {
        let result = {
            let mut state = locked(&self.0);
            state.in_flight -= 1;
            if state.abandoned {
                Err((entry, Self::sealed_failure(&state, stage)))
            } else {
                state.discovery.push(entry);
                Ok(())
            }
        };
        result.map_err(|(late, failure)| {
            drop(late);
            failure
        })
    }
    pub(crate) fn discovery_counts(&self) -> (u64, u64) {
        let state = locked(&self.0);
        state
            .discovery
            .iter()
            .fold((0, 0), |(dispatch, trip), entry| {
                if entry.kind == LinkKind::Tripwire {
                    (dispatch, trip + 1)
                } else {
                    (dispatch + 1, trip)
                }
            })
    }
    pub(crate) fn retire_discovery(&self, mut matches: impl FnMut(LinkKind, &[u64]) -> bool) {
        // Evaluate the port's predicate outside the publication mutex. Only
        // this session's worker mutates these entries; abandonment may drain
        // them concurrently, in which case there is nothing left to retire.
        let metadata: Vec<_> = {
            let state = locked(&self.0);
            state
                .discovery
                .iter()
                .map(|entry| (entry.kind, entry.cookies.clone()))
                .collect()
        };
        let selected: Vec<_> = metadata
            .iter()
            .map(|(kind, cookies)| matches(*kind, cookies))
            .collect();
        let mut state = locked(&self.0);
        for index in (0..selected.len().min(state.discovery.len())).rev() {
            if selected[index] {
                let entry = state.discovery.remove(index);
                state.retired_discovery.push(entry);
            }
        }
    }
    fn publish_member(
        &self,
        slot: Option<u32>,
        link: OwnedFd,
        stage: BoundaryStage,
    ) -> Result<(), SetupFailure> {
        let entry = MemberLink { slot, link };
        let result = {
            let mut state = locked(&self.0);
            state.in_flight -= 1;
            if state.abandoned {
                Err((entry, Self::sealed_failure(&state, stage)))
            } else {
                state.members.push(entry);
                Ok(())
            }
        };
        result.map_err(|(late, failure)| {
            drop(late);
            failure
        })
    }
    pub(crate) fn retire_members(&self) {
        let mut state = locked(&self.0);
        while let Some(link) = state.members.pop() {
            if link.slot.is_some() {
                state.retired_members.push(link);
            } else {
                state.members.push(link);
                break;
            }
        }
    }
    // Called by the later child-first owner only after its consuming reap receipt.
    // This method just seals and moves custody; it never closes a descriptor.
    pub(crate) fn abandon(&self) -> SetupLinkCustody {
        let mut state = locked(&self.0);
        state.abandoned = true;
        SetupLinkCustody {
            discovery: std::mem::take(&mut state.discovery),
            retired_discovery: std::mem::take(&mut state.retired_discovery),
            pins: std::mem::take(&mut state.pins),
            members: std::mem::take(&mut state.members),
            retired_members: std::mem::take(&mut state.retired_members),
        }
    }
}
pub(crate) struct SetupLinkReservation {
    links: SetupLinks,
    remaining: usize,
    stage: BoundaryStage,
}
impl SetupLinkReservation {
    pub(crate) fn publish_discovery(&mut self, entry: LinkEntry) -> Result<(), SetupFailure> {
        assert!(self.remaining > 0);
        self.remaining -= 1;
        self.links.publish_discovery(entry, self.stage)
    }
    pub(crate) fn publish_member(
        &mut self,
        slot: Option<u32>,
        link: OwnedFd,
    ) -> Result<(), SetupFailure> {
        assert!(self.remaining > 0);
        self.remaining -= 1;
        self.links.publish_member(slot, link, self.stage)
    }
}
impl Drop for SetupLinkReservation {
    fn drop(&mut self) {
        locked(&self.links.0).in_flight -= self.remaining;
    }
}
pub(crate) struct TemporaryFds {
    links: SetupLinks,
    count: usize,
}
impl Drop for TemporaryFds {
    fn drop(&mut self) {
        locked(&self.links.0).temporary -= self.count;
    }
}

impl Drop for SetupLinkCustody {
    fn drop(&mut self) {
        // All link closes precede every discovery pin close. The eventual
        // child-first owner chooses when to drop this real custody object.
        for entry in self
            .discovery
            .drain(..)
            .chain(self.retired_discovery.drain(..))
        {
            self.pins.push(entry.pin);
            drop(entry.link);
        }
        for member in self.members.drain(..).chain(self.retired_members.drain(..)) {
            drop(member.link);
        }
        self.pins.clear();
    }
}

/// Local observation custody or the shared pre-release ledger. The actual
/// Runner integration is the only future caller allowed to promote to local.
pub(crate) enum DiscoveryLinkStore {
    Local(LinkSet),
    Preparing {
        links: SetupLinks,
        control: SetupControl,
    },
}
impl Default for DiscoveryLinkStore {
    fn default() -> Self {
        Self::Local(LinkSet::default())
    }
}
impl DiscoveryLinkStore {
    pub(crate) fn preparing(links: &SetupLinks, control: &SetupControl) -> Self {
        Self::Preparing {
            links: links.clone(),
            control: control.clone(),
        }
    }
    pub(crate) fn reserve(&self, count: usize) -> anyhow::Result<Option<SetupLinkReservation>> {
        match self {
            Self::Local(_) => Ok(None),
            Self::Preparing { links, control } => Ok(Some(links.reserve(
                control,
                BoundaryStage::Discovery,
                count,
            )?)),
        }
    }
    pub(crate) fn temporary(&self, count: usize) -> anyhow::Result<Option<TemporaryFds>> {
        match self {
            Self::Local(_) => Ok(None),
            Self::Preparing { links, control } => Ok(Some(links.temporary(
                control,
                BoundaryStage::Discovery,
                count,
            )?)),
        }
    }
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        if let Self::Preparing { links, control } = self {
            links.check(control, BoundaryStage::Discovery)?;
        }
        Ok(())
    }
    pub(crate) fn push(
        &mut self,
        entry: LinkEntry,
        reservation: &mut Option<SetupLinkReservation>,
    ) -> anyhow::Result<()> {
        match self {
            Self::Local(links) => links.links.push(entry),
            Self::Preparing { .. } => reservation
                .as_mut()
                .expect("reserved before native effect")
                .publish_discovery(entry)?,
        }
        Ok(())
    }
    pub(crate) fn mark(&self) -> Option<usize> {
        if let Self::Local(links) = self {
            Some(links.links.len())
        } else {
            None
        }
    }
    pub(crate) fn abort(&self, failure: SetupFailure) {
        if let Self::Preparing { links, .. } = self {
            links.seal(failure);
        }
    }
    pub(crate) fn rollback(&mut self, mark: Option<usize>, failure: SetupFailure) {
        match (self, mark) {
            (Self::Local(links), Some(mark)) => links.links.truncate(mark),
            (Self::Preparing { links, .. }, _) => links.seal(failure),
            _ => {}
        }
    }
    pub(crate) fn clear(&mut self) {
        self.remove_matching(|_, _| true);
    }
    pub(crate) fn counts(&self) -> (u64, u64) {
        match self {
            Self::Local(links) => links.counts(),
            Self::Preparing { links, .. } => links.discovery_counts(),
        }
    }
    pub(crate) fn remove_matching(&mut self, predicate: impl FnMut(LinkKind, &[u64]) -> bool) {
        match self {
            Self::Local(links) => links.remove_matching(predicate),
            Self::Preparing { links, .. } => links.retire_discovery(predicate),
        }
    }
}

pub(crate) struct MemberLinks {
    pub(crate) entry: Option<OwnedFd>,
    pub(crate) members: Vec<OwnedFd>,
}
pub(crate) enum MemberLinkStore {
    Local(MemberLinks),
    Preparing {
        links: SetupLinks,
        control: SetupControl,
    },
}
impl MemberLinkStore {
    pub(crate) fn local() -> Self {
        Self::Local(MemberLinks {
            entry: None,
            members: Vec::with_capacity(512),
        })
    }
    pub(crate) fn preparing(links: &SetupLinks, control: &SetupControl) -> Self {
        Self::Preparing {
            links: links.clone(),
            control: control.clone(),
        }
    }
    pub(crate) fn reserve(&self) -> anyhow::Result<Option<SetupLinkReservation>> {
        match self {
            Self::Local(_) => Ok(None),
            Self::Preparing { links, control } => {
                Ok(Some(links.reserve(control, BoundaryStage::Traversal, 1)?))
            }
        }
    }
    pub(crate) fn temporary(&self, count: usize) -> anyhow::Result<Option<TemporaryFds>> {
        match self {
            Self::Local(_) => Ok(None),
            Self::Preparing { links, control } => Ok(Some(links.temporary(
                control,
                BoundaryStage::Traversal,
                count,
            )?)),
        }
    }
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        if let Self::Preparing { links, control } = self {
            links.check(control, BoundaryStage::Traversal)?;
        }
        Ok(())
    }
    pub(crate) fn push(
        &mut self,
        slot: Option<u32>,
        link: OwnedFd,
        reservation: &mut Option<SetupLinkReservation>,
    ) -> anyhow::Result<()> {
        match self {
            Self::Local(links) => match slot {
                None => {
                    assert!(links.entry.is_none());
                    links.entry = Some(link);
                }
                Some(_) => links.members.push(link),
            },
            Self::Preparing { .. } => reservation
                .as_mut()
                .expect("reserved before native effect")
                .publish_member(slot, link)?,
        }
        Ok(())
    }
    pub(crate) fn abort(&self, failure: SetupFailure) {
        if let Self::Preparing { links, .. } = self {
            links.seal(failure);
        }
    }
    pub(crate) fn clear_members(&mut self) {
        match self {
            Self::Local(links) => links.members.clear(),
            Self::Preparing { links, .. } => links.retire_members(),
        }
    }
    pub(crate) fn take_local(self) -> MemberLinks {
        match self {
            Self::Local(links) => links,
            Self::Preparing { .. } => {
                unreachable!("pre-release custody requires final publication")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn control() -> SetupControl {
        SetupControl::new(
            Instant::now() + Duration::from_secs(20),
            SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
        )
    }
    #[test]
    fn w079_native_capacity_refuses_before_effect() {
        let links = SetupLinks::new();
        let control = control();
        let held = links
            .reserve(&control, BoundaryStage::Traversal, 1024)
            .unwrap();
        assert!(
            matches!(
                links.reserve(&control, BoundaryStage::Traversal, 1),
                Err(SetupFailure::Resource { .. })
            ),
            "a full ledger must refuse before the next native effect"
        );
        drop(held);
    }
    fn pair() -> (OwnedFd, std::os::unix::net::UnixStream) {
        let (fd, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        (fd.into(), peer)
    }
    fn closed(peer: &std::os::unix::net::UnixStream) -> bool {
        use std::io::Read;
        let mut peer = peer;
        match peer.read(&mut [0]) {
            Ok(0) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            result => panic!("unexpected sentinel read {result:?}"),
        }
    }
    #[test]
    fn w079_native_retirement_retains_capacity_and_real_fd_custody() {
        let links = SetupLinks::new();
        let control = control();
        let (fd, peer) = pair();
        let alias = fd.try_clone().unwrap();
        let mut reservation = links
            .reserve(&control, BoundaryStage::Traversal, 1)
            .unwrap();
        reservation.publish_member(Some(3), fd).unwrap();
        drop(reservation);
        links.retire_members();
        let held = links
            .reserve(&control, BoundaryStage::Traversal, 1023)
            .unwrap();
        assert!(matches!(
            links.reserve(&control, BoundaryStage::Traversal, 1),
            Err(SetupFailure::Resource { .. })
        ));
        let custody = links.abandon();
        assert!(!closed(&peer));
        drop(custody);
        assert!(
            !closed(&peer),
            "retained alias is the negative close witness"
        );
        drop(alias);
        assert!(closed(&peer));
        drop(held);
    }
    #[test]
    fn w079_native_late_link_and_temporary_slots() {
        let links = SetupLinks::new();
        let control = control();
        let temporary = links
            .temporary(&control, BoundaryStage::Discovery, 4)
            .unwrap();
        assert!(matches!(
            links.temporary(&control, BoundaryStage::Discovery, 1),
            Err(SetupFailure::Resource { .. })
        ));
        drop(temporary);
        let links = SetupLinks::new();
        let mut reservation = links
            .reserve(&control, BoundaryStage::Traversal, 1)
            .unwrap();
        let custody = links.abandon();
        let (fd, peer) = pair();
        assert!(matches!(
            reservation.publish_member(None, fd),
            Err(SetupFailure::Cancelled { .. })
        ));
        assert!(closed(&peer));
        assert!(links.0.try_lock().is_ok());
        drop(custody);
        drop(reservation);
        assert!(matches!(
            links.reserve(&control, BoundaryStage::Traversal, 1),
            Err(SetupFailure::Cancelled { .. })
        ));
    }
    #[test]
    fn w079_native_control_prioritizes_cancel_and_preserves_errno() {
        let flag = Arc::new(AtomicBool::new(true));
        let control = SetupControl::new(Instant::now(), SetupInterrupt::Owned(flag.clone()));
        assert!(matches!(
            control.check(BoundaryStage::Discovery),
            Err(SetupFailure::Cancelled {
                stage: BoundaryStage::Discovery
            })
        ));
        flag.store(false, Ordering::Release);
        assert!(matches!(
            control.check(BoundaryStage::Traversal),
            Err(SetupFailure::Boundary(BoundaryFailure {
                class: BoundaryFailureClass::Timeout,
                ..
            }))
        ));
        let control = self::control();
        control.abandon();
        assert!(matches!(
            control.check(BoundaryStage::Setup),
            Err(SetupFailure::Cancelled { .. })
        ));
        let failure = SetupFailure::io(
            BoundaryStage::Discovery,
            &std::io::Error::from_raw_os_error(libc::EPERM),
            "attach query_entry@0x1 failed (kind=PermissionDenied)",
        );
        let recovered = SetupFailure::from_error(
            BoundaryStage::Setup,
            anyhow::Error::new(failure).context("outer stage"),
        );
        assert!(matches!(
            recovered,
            SetupFailure::Boundary(BoundaryFailure {
                errno: Some(libc::EPERM),
                stage: BoundaryStage::Discovery,
                ..
            })
        ));
    }
    #[test]
    fn w079_native_discovery_retirement_uses_unlocked_predicate_and_keeps_pins() {
        let links = SetupLinks::new();
        let control = control();
        let mut store = DiscoveryLinkStore::preparing(&links, &control);
        let (link, peer) = pair();
        let (pin, pin_peer) = pair();
        let mut permit = links
            .reserve(&control, BoundaryStage::Discovery, 1)
            .unwrap();
        permit
            .publish_discovery(LinkEntry {
                link,
                pin,
                kind: LinkKind::Stage2,
                cookies: vec![7],
            })
            .unwrap();
        drop(permit);
        store.remove_matching(|kind, cookies| {
            assert!(
                links.0.try_lock().is_ok(),
                "port callbacks cannot run under custody lock"
            );
            kind == LinkKind::Stage2 && cookies == [7]
        });
        assert_eq!(store.counts(), (0, 0));
        assert!(!closed(&peer));
        assert!(!closed(&pin_peer));
        let held = links
            .reserve(&control, BoundaryStage::Traversal, 1023)
            .unwrap();
        assert!(matches!(
            links.reserve(&control, BoundaryStage::Traversal, 1),
            Err(SetupFailure::Resource { .. })
        ));
        let custody = links.abandon();
        assert!(!closed(&peer));
        drop(custody);
        assert!(closed(&peer));
        assert!(closed(&pin_peer));
        drop(held);
    }
}
