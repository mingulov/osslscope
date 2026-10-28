// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded cumulative evidence folding, separate from kernel ownership.
use super::{CountFailure, CountLimits, CountSample, gap};
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
    pub(super) generation: u32,
    pub(super) session: Option<u64>,
    pub(super) next_cookie: u32,
    state_bytes: usize,
    gaps: BTreeMap<&'static str, u64>,
}
impl CountFold {
    pub fn new(limits: CountLimits) -> Result<Self, CountFailure> {
        limits.validate()?;
        Ok(Self {
            limits,
            rows: BTreeMap::new(),
            foreign: BTreeMap::new(),
            generation: 1,
            session: None,
            next_cookie: 1,
            state_bytes: 0,
            gaps: BTreeMap::new(),
        })
    }
    pub(super) fn charge(&mut self, n: usize) -> Result<(), CountFailure> {
        self.state_bytes = self
            .state_bytes
            .checked_add(n)
            .ok_or(CountFailure::Resource)?;
        if self.state_bytes > self.limits.max_state_bytes {
            return Err(CountFailure::Resource);
        }
        Ok(())
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
        mut binding: SiteBinding,
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
        if self.next_cookie as usize > self.limits.max_cookies {
            return Err(CountFailure::Resource);
        }
        let cookie = self.next_cookie;
        self.next_cookie = self
            .next_cookie
            .checked_add(1)
            .ok_or(CountFailure::Resource)?;
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
    fn count_generation_exhaustion_is_permanent() {
        let mut fold = CountFold::new(CountLimits::default()).unwrap();
        fold.generation = u32::MAX;
        assert_eq!(fold.fence(), Err(CountFailure::Resource));
        assert_eq!(fold.fence(), Err(CountFailure::Resource));
        assert_eq!(fold.generation, 0);
    }
}
