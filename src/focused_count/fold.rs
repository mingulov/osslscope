// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded cumulative evidence folding, separate from kernel ownership.
use super::{CountFailure, CountLimits, CountSample, EngineCount, gap, is_engine_cookie};
use crate::evidence::*;
use osslscope_ebpf_common::CountValue;
use std::collections::BTreeMap;

/// Input to the small cumulative fold; production derives it solely from the
/// owned verified candidate. It carries distinct membership and mapping epochs.
pub struct SiteBinding {
    pub site: SiteKey,
    pub session_generation: u64,
    pub mapping_generation: u64,
    pub candidates: Vec<CandidateIdentity>,
    pub installed_ns: u64,
}
#[derive(Clone)]
pub(super) struct Row {
    pub(super) row: SiteExecution,
    pub(super) mapping: u64,
    pub(super) active: bool,
}
/// Bounded pure host folding and attachment admission. The install closure is
/// called once per new physical site; a refusal never publishes a successful row.
#[derive(Clone)]
pub struct CountFold {
    limits: CountLimits,
    pub(super) rows: BTreeMap<u32, Row>,
    foreign: BTreeMap<(u32, u32), u64>,
    engine: BTreeMap<(u32, u32), EngineCount>,
    pub(super) generation: u32,
    pub(super) session: Option<u64>,
    pub(super) next_cookie: u32,
    pub(super) state_bytes: usize,
    gaps: BTreeMap<&'static str, u64>,
}
impl CountFold {
    pub fn new(limits: CountLimits) -> Result<Self, CountFailure> {
        limits.validate()?;
        Ok(Self {
            limits,
            rows: BTreeMap::new(),
            foreign: BTreeMap::new(),
            engine: BTreeMap::new(),
            generation: 1,
            session: None,
            next_cookie: 1,
            state_bytes: 0,
            gaps: BTreeMap::new(),
        })
    }
    pub(super) fn charge(&mut self, n: usize) -> Result<(), CountFailure> {
        let next = self.checked_charge(n)?;
        self.state_bytes = next;
        Ok(())
    }
    pub(super) fn checked_charge(&self, n: usize) -> Result<usize, CountFailure> {
        let next = self
            .state_bytes
            .checked_add(n)
            .ok_or(CountFailure::Resource)?;
        if next > self.limits.max_state_bytes {
            return Err(CountFailure::Resource);
        }
        Ok(next)
    }
    pub(super) fn clone_charged(&self, n: usize) -> Result<Self, CountFailure> {
        let next = self.checked_charge(n)?;
        let mut planned = self.clone();
        planned.state_bytes = next;
        Ok(planned)
    }
    pub(super) fn gap(&mut self, name: &'static str) {
        let v = self.gaps.entry(name).or_default();
        *v = v.saturating_add(1);
    }
    pub fn fence(&mut self) -> Result<(), CountFailure> {
        if self.generation == 0 {
            return Err(CountFailure::Resource);
        }
        for row in self.rows.values_mut() {
            row.active = false;
        }
        self.session = None;
        self.generation = self.generation.checked_add(1).unwrap_or(0);
        if self.generation == 0 {
            return Err(CountFailure::Resource);
        }
        Ok(())
    }
    pub fn attach(
        &mut self,
        binding: SiteBinding,
        install: impl FnOnce(u32, u32) -> Result<(), CountFailure>,
    ) -> Result<(u32, u32), CountFailure> {
        self.attach_inner(binding, None, install)
    }
    /// Attach with a session-pinned cookie so both programs resolve one
    /// SITE_BIND row for the same site. The pinned cookie skips the
    /// counter's own mint ceiling (session-budgeted, disjoint range) but
    /// keeps every fence, charge and dedup check; zero or a cookie already
    /// bound to a different site refuses.
    pub fn attach_pinned(
        &mut self,
        binding: SiteBinding,
        cookie: u32,
        install: impl FnOnce(u32, u32) -> Result<(), CountFailure>,
    ) -> Result<(u32, u32), CountFailure> {
        if cookie == 0 {
            return Err(CountFailure::Identity);
        }
        self.attach_inner(binding, Some(cookie), install)
    }
    fn attach_inner(
        &mut self,
        mut binding: SiteBinding,
        pinned: Option<u32>,
        install: impl FnOnce(u32, u32) -> Result<(), CountFailure>,
    ) -> Result<(u32, u32), CountFailure> {
        if self.generation == 0 {
            return Err(CountFailure::Resource);
        }
        if binding.session_generation == 0 || binding.installed_ns == 0 {
            return Err(CountFailure::Identity);
        }
        if self
            .session
            .is_some_and(|s| s != binding.session_generation)
        {
            self.fence()?;
        }
        // Mapping replacement is a fence even if the enclosing D3 epoch stayed.
        if self.rows.values().any(|r| {
            r.active && r.row.site == binding.site && r.mapping != binding.mapping_generation
        }) {
            self.fence()?;
        }
        let bytes = binding
            .candidates
            .iter()
            .try_fold(
                binding
                    .site
                    .object
                    .0
                    .len()
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(512))
                    .ok_or(CountFailure::Resource)?,
                |n, c| {
                    let strings = c.provider.0.len().checked_add(c.provider_class.len())?;
                    let strings = c
                        .algorithm_classes
                        .iter()
                        .try_fold(strings, |a, s| a.checked_add(s.len()))?;
                    n.checked_add(strings.checked_add(256)?.checked_mul(2)?)
                },
            )
            .ok_or(CountFailure::Resource)?;
        self.charge(bytes)?;
        binding.candidates.sort();
        binding.candidates.dedup();
        if let Some((&cookie, r)) = self
            .rows
            .iter()
            .find(|(_, r)| r.active && r.row.site == binding.site)
        {
            let generation = r.row.generation;
            if r.row.candidates != binding.candidates {
                // Prior calls retain exactly the metadata installed with this
                // cookie. Unknown coverage remains conservative for later hits.
                self.gap("focused_metadata_changed");
            }
            return Ok((cookie, generation));
        }
        let cookie = match pinned {
            Some(cookie) => {
                // The ENGINE probe range is counter-private: a pinned
                // site cookie there would shadow ENGINE evidence (or
                // vice versa) at drain. Refuse rather than alias.
                if is_engine_cookie(cookie) {
                    return Err(CountFailure::Resource);
                }
                // A pinned cookie already bound to a different site is a
                // cross-site collision: refuse rather than alias.
                if let Some(r) = self.rows.get(&cookie) {
                    if r.row.site != binding.site {
                        return Err(CountFailure::Resource);
                    }
                }
                cookie
            }
            None => {
                if self.next_cookie as usize > self.limits.max_cookies {
                    return Err(CountFailure::Resource);
                }
                let cookie = self.next_cookie;
                self.next_cookie = self
                    .next_cookie
                    .checked_add(1)
                    .ok_or(CountFailure::Resource)?;
                cookie
            }
        };
        // Errors are returned to the owner, which records one failure gap.
        install(cookie, self.generation)?;
        self.rows.insert(
            cookie,
            Row {
                mapping: binding.mapping_generation,
                active: true,
                row: SiteExecution {
                    site: binding.site,
                    generation: self.generation,
                    candidates: binding.candidates,
                    candidates_coverage: CandidateCoverage::Unknown,
                    calls: 0,
                    first_ns: 0,
                    last_ns: 0,
                    installed_at: Some(binding.installed_ns),
                },
            },
        );
        self.session = Some(binding.session_generation);
        Ok((cookie, self.generation))
    }
    pub fn observe(
        &mut self,
        cookie: u32,
        generation: u32,
        values: &[CountValue],
    ) -> Result<(), CountFailure> {
        if values.len() > self.limits.max_cpus {
            return Err(CountFailure::Resource);
        }
        if values
            .iter()
            .any(|v| v.count > 0 && (v.first_ns == 0 || v.last_ns < v.first_ns))
        {
            return Err(CountFailure::Read);
        }
        let calls = values
            .iter()
            .try_fold(0u64, |n, v| n.checked_add(v.count))
            .ok_or(CountFailure::Read)?;
        let first = values
            .iter()
            .filter(|v| v.count > 0)
            .map(|v| v.first_ns)
            .min()
            .unwrap_or(0);
        let last = values
            .iter()
            .filter(|v| v.count > 0)
            .map(|v| v.last_ns)
            .max()
            .unwrap_or(0);
        if calls > 0
            && (first == 0
                || first > last
                || (self.limits.window.start_ns != 0
                    && (first < self.limits.window.start_ns
                        || last >= self.limits.window.deadline_ns)))
        {
            return Err(CountFailure::Read);
        }
        // A saturated physical lower bound cannot certify conservation even
        // when the independent admission ledger has saturated to the same value.
        if calls == u64::MAX {
            self.gaps.insert("focused_saturated", 1);
        }
        if let Some(r) = self
            .rows
            .get_mut(&cookie)
            .filter(|r| r.row.generation == generation)
        {
            if calls < r.row.calls {
                return Err(CountFailure::Read);
            }
            r.row.calls = calls;
            r.row.first_ns = first;
            r.row.last_ns = last;
        } else if is_engine_cookie(cookie) {
            // Reserved ENGINE probe plane: same cumulative-drain
            // discipline as foreign keys, but evidence-shaped (the
            // session joins meanings via the planned ProbeSet), never
            // unattributed loss.
            if !self.engine.contains_key(&(cookie, generation)) {
                if self.engine.len() >= self.limits.max_keys {
                    return Err(CountFailure::Resource);
                }
                self.charge(96)?;
            }
            let slot = self
                .engine
                .entry((cookie, generation))
                .or_insert(EngineCount {
                    cookie,
                    generation,
                    calls: 0,
                    first_ns: 0,
                    last_ns: 0,
                });
            if calls < slot.calls {
                return Err(CountFailure::Read);
            }
            slot.calls = calls;
            if slot.first_ns == 0 || (first != 0 && first < slot.first_ns) {
                slot.first_ns = first;
            }
            if last > slot.last_ns {
                slot.last_ns = last;
            }
        } else {
            if !self.foreign.contains_key(&(cookie, generation)) {
                if self.foreign.len() >= self.limits.max_keys {
                    return Err(CountFailure::Resource);
                }
                self.charge(96)?;
            }
            let old = self.foreign.entry((cookie, generation)).or_default();
            if calls < *old {
                return Err(CountFailure::Read);
            }
            *old = calls;
        }
        Ok(())
    }
    /// A closed final enumeration must include every previously observed key.
    /// Counts are never deleted in this producer, including fenced generations.
    /// A missing row cannot be filled from a live cached prefix.
    pub(super) fn validate_final_keys(
        &self,
        keys: &std::collections::BTreeSet<(u32, u32)>,
    ) -> Result<(), CountFailure> {
        if self.rows.iter().any(|(&cookie, row)| {
            row.row.calls > 0 && !keys.contains(&(cookie, row.row.generation))
        }) || self.foreign.keys().any(|key| !keys.contains(key))
            || self.engine.keys().any(|key| !keys.contains(key))
        {
            return Err(CountFailure::Read);
        }
        Ok(())
    }
    pub fn sample(&self) -> CountSample {
        let mut s = CountSample::default();
        for r in self.rows.values() {
            if r.active {
                s.sites.push(r.row.clone());
            } else {
                s.fenced.push(r.row.clone());
            }
        }
        s.unattributed = self.foreign.values().copied().fold(0, u64::saturating_add);
        s.engine = self.engine.values().cloned().collect();
        for (&name, &value) in &self.gaps {
            s.gaps.push(gap(name, value));
        }
        if s.unattributed > 0 {
            s.gaps.push(gap("focused_unattributed", s.unattributed));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_enumeration_cannot_reuse_cached_known_or_foreign_counts() {
        let mut fold = CountFold::new(CountLimits::default()).unwrap();
        let binding = SiteBinding {
            site: SiteKey {
                object: ObjectId("a".repeat(64)),
                device: 1,
                inode: 2,
                offset: 3,
            },
            session_generation: 1,
            mapping_generation: 1,
            candidates: vec![],
            installed_ns: 1,
        };
        let (cookie, generation) = fold.attach(binding, |_, _| Ok(())).unwrap();
        let value = CountValue {
            count: 7,
            first_ns: 2,
            last_ns: 3,
        };
        fold.observe(cookie, generation, &[value]).unwrap();
        assert_eq!(
            fold.validate_final_keys(&Default::default()),
            Err(CountFailure::Read)
        );
        let mut keys = std::collections::BTreeSet::from([(cookie, generation)]);
        assert!(fold.validate_final_keys(&keys).is_ok());
        fold.fence().unwrap();
        assert!(
            fold.validate_final_keys(&keys).is_ok(),
            "fenced physical rows remain once"
        );
        fold.observe(999, 99, &[value]).unwrap();
        assert_eq!(fold.validate_final_keys(&keys), Err(CountFailure::Read));
        keys.insert((999, 99));
        assert!(fold.validate_final_keys(&keys).is_ok());
    }
    #[test]
    fn engine_range_cookies_accumulate_separately_from_unattributed() {
        let mut fold = CountFold::new(CountLimits::default()).unwrap();
        let value = CountValue {
            count: 5,
            first_ns: 2,
            last_ns: 3,
        };
        fold.observe(super::super::ENGINE_COOKIE_BASE, 1, &[value])
            .unwrap();
        fold.observe(999, 99, &[value]).unwrap();
        let s = fold.sample();
        assert_eq!(s.unattributed, 5, "only the non-engine key is foreign");
        assert_eq!(s.engine.len(), 1);
        assert_eq!(s.engine[0].cookie, super::super::ENGINE_COOKIE_BASE);
        assert_eq!(s.engine[0].generation, 1);
        assert_eq!(s.engine[0].calls, 5);
        assert_eq!(s.engine[0].first_ns, 2);
        assert_eq!(s.engine[0].last_ns, 3);
    }
    #[test]
    fn pinned_engine_range_cookie_refuses() {
        let mut fold = CountFold::new(CountLimits::default()).unwrap();
        let binding = SiteBinding {
            site: SiteKey {
                object: ObjectId("a".repeat(64)),
                device: 1,
                inode: 2,
                offset: 3,
            },
            session_generation: 1,
            mapping_generation: 1,
            candidates: vec![],
            installed_ns: 1,
        };
        assert_eq!(
            fold.attach_pinned(binding, super::super::ENGINE_COOKIE_BASE, |_, _| Ok(())),
            Err(CountFailure::Resource)
        );
    }
    #[test]
    fn count_generation_exhaustion_is_permanent() {
        let mut fold = CountFold::new(CountLimits::default()).unwrap();
        fold.generation = u32::MAX;
        assert_eq!(fold.fence(), Err(CountFailure::Resource));
        assert_eq!(fold.fence(), Err(CountFailure::Resource));
        assert_eq!(fold.generation, 0);
    }
}
