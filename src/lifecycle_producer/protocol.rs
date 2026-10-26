// SPDX-License-Identifier: GPL-3.0-or-later
pub(super) const HELLO: u16 = 1;
pub(super) const READY: u16 = 2;
pub(super) const SPAWN: u16 = 3;
pub(super) const CHILD: u16 = 4;
pub(super) const OBSERVED: u16 = 5;
pub(super) const REAPED: u16 = 6;
pub(super) const ABORT: u16 = 7;
pub(super) const FAILED: u16 = 8;
pub(super) const SHUTDOWN: u16 = 9;
pub(super) const DONE: u16 = 10;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Frame {
    pub kind: u16,
    pub session: u64,
    pub request: u64,
    pub deadline: u64,
    pub floor: u64,
    pub arg0: u64,
    pub arg1: u64,
}
impl Frame {
    pub fn encode(self) -> [u8; 64] {
        let mut b = [0; 64];
        b[..8].copy_from_slice(b"OSLCPR01");
        b[8..10].copy_from_slice(&1u16.to_le_bytes());
        b[10..12].copy_from_slice(&self.kind.to_le_bytes());
        for (i, v) in [
            self.session,
            self.request,
            self.deadline,
            self.floor,
            self.arg0,
            self.arg1,
        ]
        .into_iter()
        .enumerate()
        {
            b[16 + i * 8..24 + i * 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 64
            || &b[..8] != b"OSLCPR01"
            || b[8..10] != 1u16.to_le_bytes()
            || b[12..16] != [0; 4]
        {
            return None;
        }
        let kind = u16::from_le_bytes(b[10..12].try_into().ok()?);
        let v = |i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let f = Self {
            kind,
            session: v(16),
            request: v(24),
            deadline: v(32),
            floor: v(40),
            arg0: v(48),
            arg1: v(56),
        };
        (f.session != 0 && (HELLO..=DONE).contains(&kind)).then_some(f)
    }
}
