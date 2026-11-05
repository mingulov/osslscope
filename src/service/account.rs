//! SPDX-License-Identifier: GPL-3.0-or-later
//! §5.1 service accumulation budgets + MEM allocation accounting.
//!
//! Frozen constants: `SERVICE_ACCUM_BYTES` (64 MiB, one quarter of
//! the 6A engine-state cap), `MAX_TICK_BYTES`/`MAX_RECORD_BYTES`
//! (8 MiB staged), `MAX_OUTSTANDING_TAP` (1), `SPILL_BUF_BYTES`
//! (64 KiB).
//!
//! MEM (T7.4-sized, proof in code + tests): EVERY
//! coordinator-materialized value is charged at materialization.
//! The `Meter` tracks two counters: `rendered` (exact staged
//! record bytes — the `staging_peak_bytes` note, bounded by the
//! §5.1 closed form) and `charged` (`rendered` + per-record struct
//! overhead + parsed-DOM estimates — bounded by `MEM_CAP`, the same
//! numeric value, so overhead trips FIRST). Over-cap ⟹ the frozen
//! §5.1 behavior (cut at the last fully-admitted tick / spill /
//! single-tick admit-whole + note) — never silent, never an
//! exception. RSS stays trend-oracle only (§9).

/// §5.1: per-window in-memory accumulation budget (64 MiB).
pub const SERVICE_ACCUM_BYTES: u64 = 67_108_864;
/// §5.1: maximum STAGED bytes of one tick (8 MiB).
pub const MAX_TICK_BYTES: u64 = 8_388_608;
/// §5.1: maximum STAGED bytes of one record (= `MAX_TICK_BYTES`).
pub const MAX_RECORD_BYTES: u64 = MAX_TICK_BYTES;
/// §6.1/§7.2: at most one live tap writer per tap.
pub const MAX_OUTSTANDING_TAP: u64 = 1;
/// §5.1: bounded spill streaming buffer (64 KiB).
pub const SPILL_BUF_BYTES: usize = 65_536;

/// MEM cap (T7.4): the §5.1 closed form, applied to `charged`
/// (rendered + overhead), so overhead trips before raw bytes.
pub const MEM_CAP: u64 = SERVICE_ACCUM_BYTES + MAX_TICK_BYTES;

/// Per-record struct overhead prepaid at admission (T7.4): covers
/// the staged `Vec` entry + parsed-value handle + delta-map entry
/// for one record (proof: `hostile_struct_count_trips_meter`).
pub const RECORD_OVERHEAD: u64 = 256;

/// Parsed-DOM charge factor (T7.4): `serde_json::Value` DOMs charge
/// 4× source bytes (conservative; proof: `hostile_dom_trips_meter`).
pub const DOM_CHARGE_FACTOR: u64 = 4;

/// Over-cap marker (the MEM trip — a value, never `()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverCap;

/// The window accumulation meter (§5.1 + MEM).
#[derive(Debug)]
pub struct Meter {
    rendered: u64,
    charged: u64,
    rendered_peak: u64,
    charged_peak: u64,
}

impl Meter {
    pub fn new() -> Self {
        Self {
            rendered: 0,
            charged: 0,
            rendered_peak: 0,
            charged_peak: 0,
        }
    }

    /// Charge staged rendered bytes + per-record overhead.
    /// `Err` ⟹ over-cap (the caller runs the frozen budget
    /// decision; NOTHING was admitted by this call).
    pub fn charge_record(&mut self, rendered_bytes: u64) -> Result<(), OverCap> {
        let charge = rendered_bytes.saturating_add(RECORD_OVERHEAD);
        let next_charged = self.charged.saturating_add(charge);
        let next_rendered = self.rendered.saturating_add(rendered_bytes);
        // The rendered closed form binds unconditionally (§5.1).
        if next_rendered > SERVICE_ACCUM_BYTES + MAX_TICK_BYTES {
            return Err(OverCap);
        }
        // MEM binds charged (trips first under overhead pressure).
        if next_charged > MEM_CAP {
            return Err(OverCap);
        }
        self.charged = next_charged;
        self.rendered = next_rendered;
        self.rendered_peak = self.rendered_peak.max(self.rendered);
        self.charged_peak = self.charged_peak.max(self.charged);
        Ok(())
    }

    /// Charge a parsed DOM / delta structure (4× source bytes).
    pub fn charge_parsed(&mut self, source_bytes: u64) -> Result<(), OverCap> {
        let charge = source_bytes.saturating_mul(DOM_CHARGE_FACTOR);
        let next = self.charged.saturating_add(charge);
        if next > MEM_CAP {
            return Err(OverCap);
        }
        self.charged = next;
        self.charged_peak = self.charged_peak.max(self.charged);
        Ok(())
    }

    /// Release staged bytes (window publish / seal frees staging).
    pub fn release_rendered(&mut self, rendered_bytes: u64, records: u64) {
        self.rendered = self.rendered.saturating_sub(rendered_bytes);
        self.charged = self
            .charged
            .saturating_sub(rendered_bytes.saturating_add(records.saturating_mul(RECORD_OVERHEAD)));
    }

    pub fn rendered(&self) -> u64 {
        self.rendered
    }

    pub fn charged(&self) -> u64 {
        self.charged
    }

    /// The `staging_peak_bytes` note (§5.1 staging definition:
    /// admitted staged records plus the tick's staged piece).
    pub fn staging_peak(&self) -> u64 {
        self.rendered_peak
    }
}

impl Default for Meter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_closed_form_is_exact() {
        let mut m = Meter::new();
        // Fill exactly to the closed form with one big record.
        assert!(
            m.charge_record(SERVICE_ACCUM_BYTES + MAX_TICK_BYTES - RECORD_OVERHEAD)
                .is_ok()
        );
        // One more byte trips (MEM charged rule — overhead trips
        // first; rendered ≤ charged keeps the §5.1 form exact).
        assert!(m.charge_record(1).is_err());
        assert!(m.staging_peak() <= SERVICE_ACCUM_BYTES + MAX_TICK_BYTES);
        assert_eq!(
            m.staging_peak(),
            SERVICE_ACCUM_BYTES + MAX_TICK_BYTES - RECORD_OVERHEAD
        );
    }

    /// MEM hostile-allocation proof 1: a flood of tiny records
    /// (small bytes, huge struct count) trips the meter via
    /// overhead LONG before raw bytes fill — frozen behavior (cut),
    /// never silent growth.
    #[test]
    fn hostile_struct_count_trips_meter() {
        let mut m = Meter::new();
        let mut admitted = 0u64;
        // Tiny 8-byte records: overhead dominates 32:1.
        while m.charge_record(8).is_ok() {
            admitted += 1;
        }
        // Tripped by charged (8+256 each), not by rendered.
        assert!(m.rendered() < SERVICE_ACCUM_BYTES + MAX_TICK_BYTES);
        assert!(m.charged() <= MEM_CAP);
        assert!(m.charged() + 264 > MEM_CAP);
        // And the trip is early: admitted « byte-capacity count.
        assert!(admitted < (SERVICE_ACCUM_BYTES + MAX_TICK_BYTES) / 8);
    }

    /// MEM hostile-allocation proof 2: hostile parsed DOMs (dense
    /// tiny values) trip via the 4× charge.
    #[test]
    fn hostile_dom_trips_meter() {
        let mut m = Meter::new();
        // A hostile 20 MiB dense-JSON DOM charges 80 MiB > cap.
        assert!(m.charge_parsed(20 << 20).is_err());
        assert_eq!(m.charged(), 0);
        // Ordinary DOMs fit.
        assert!(m.charge_parsed(1 << 20).is_ok());
    }

    #[test]
    fn release_frees_staging() {
        let mut m = Meter::new();
        m.charge_record(1000).unwrap();
        m.charge_record(2000).unwrap();
        m.release_rendered(3000, 2);
        assert_eq!(m.rendered(), 0);
        assert_eq!(m.charged(), 0);
        // The peak note survives release (high-water).
        assert_eq!(m.staging_peak(), 3000);
    }
}
