// SPDX-License-Identifier: GPL-2.0-or-later
//! Private fixed-width attribution ABI. These types never contain public events.
//! A typed role is independent of legacy API IDs and static dispatch shapes.
pub const VERSION: u32 = 1;
pub const SELECTOR_ENCODING: u32 = 2;
pub const MAX_RELATIONSHIPS: u32 = 8192;
pub const MAX_PENDING: u32 = 4096;
pub const MAX_DEPTH: u32 = 8;
pub const MAX_PREPARED_OBJECTS: u32 = 16;
pub const SELECTOR_PREFIX: &[u8; 16] = b"ossl-code-req-v1";

/// Independent role identity. Neither an API number nor a public function ID
/// can be converted to this type without the complete finite role-table check.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TypedRoleId(u32);
impl TypedRoleId {
    pub const fn from_u32(id: u32) -> Option<Self> {
        match id {
            5
            | 18
            | 130
            | 131
            | 136
            | 137
            | 142
            | 143
            | 146..=155
            | 258
            | 259
            | 274
            | 275
            | 290
            | 291
            | 304..=308 => Some(Self(id)),
            _ => None,
        }
    }
    pub const fn id(self) -> u32 {
        self.0
    }
    pub const fn public_export(self) -> Option<&'static str> {
        Some(match self.0 {
            5 => "OSSL_PROVIDER_unload",
            130 => "EVP_MAC_fetch",
            131 => "EVP_KDF_fetch",
            136 => "EVP_MAC_free",
            137 => "EVP_KDF_free",
            142 => "EVP_MAC_get0_provider",
            143 => "EVP_KDF_get0_provider",
            146 => "OSSL_PROVIDER_get0_provider_ctx",
            147 => "EVP_MAC_CTX_new",
            148 => "EVP_KDF_CTX_new",
            149 => "EVP_MAC_CTX_free",
            150 => "EVP_KDF_CTX_free",
            151 => "EVP_MAC_CTX_dup",
            152 => "EVP_KDF_CTX_dup",
            153 => "EVP_KDF_CTX_reset",
            154 => "OSSL_LIB_CTX_free",
            155 => "OPENSSL_cleanup",
            _ => return None,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TypedAdmission {
    pub role_id: u32,
    pub public_api_id: u32,
    pub operation: u32,
    pub function: u32,
    pub abi_epoch: u64,
    pub source_epoch: u64,
}
impl TypedAdmission {
    /// Exact first-slice role table. Reserved roles are not admitted.
    pub const fn new(
        role_id: u32,
        public_api_id: u32,
        operation: u32,
        function: u32,
        abi_epoch: u64,
        source_epoch: u64,
    ) -> Option<Self> {
        let (api, op, fun) = match role_id {
            5 => (5, 0, 0),
            18 => (0, 0, 0),
            130 => (12, 3, 0),
            131 => (13, 4, 0),
            136 | 142 | 147 | 149 | 151 => (0, 3, 0),
            137 | 143 | 148 | 150 | 152 | 153 => (0, 4, 0),
            146 | 154 | 155 => (0, 0, 0),
            258 => (0, 3, 1),
            259 => (0, 4, 1),
            274 => (0, 3, 3),
            275 => (0, 4, 3),
            290 => (0, 3, 2),
            291 => (0, 4, 2),
            304 => (0, 3, 4),
            305 => (0, 3, 5),
            306 => (0, 3, 6),
            307 => (0, 4, 5),
            308 => (0, 4, 4),
            _ => return None,
        };
        if public_api_id != api
            || operation != op
            || function != fun
            || abi_epoch == 0
            || source_epoch == 0
        {
            return None;
        }
        Some(Self {
            role_id,
            public_api_id,
            operation,
            function,
            abi_epoch,
            source_epoch,
        })
    }
    pub const fn valid(&self) -> bool {
        Self::new(
            self.role_id,
            self.public_api_id,
            self.operation,
            self.function,
            self.abi_epoch,
            self.source_epoch,
        )
        .is_some()
    }
    pub const fn paired(&self) -> bool {
        matches!(
            self.role_id,
            130 | 131 | 142 | 143 | 146 | 147 | 148 | 151 | 152 | 258 | 259 | 290 | 291
        )
    }
    pub const fn operational(&self) -> bool {
        matches!(self.role_id, 304..=307)
    }
}
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExactNameKey {
    pub object_domain: u64,
    pub operation: u32,
    pub name_length: u32,
    pub name: [u8; 128],
}
impl ExactNameKey {
    /// Helper result includes NUL. Return128 may be truncation: never accept it.
    pub fn from_read(
        object_domain: u64,
        operation: u32,
        bytes: &[u8; 128],
        result: i64,
    ) -> Option<Self> {
        if !(2..=127).contains(&result) || !matches!(operation, 3 | 4) {
            return None;
        }
        let length = (result - 1) as usize;
        if bytes[length] != 0 {
            return None;
        }
        let mut name = [0; 128];
        let mut i = 0;
        while i < 126 {
            if i < length {
                if bytes[i] == 0 {
                    return None;
                }
                name[i] = bytes[i];
            }
            i += 1;
        }
        Some(Self {
            object_domain,
            operation,
            name_length: length as u32,
            name,
        })
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RelKey {
    pub process_incarnation: u64,
    pub image_epoch: u64,
    pub relation_epoch: u64,
    pub primary_handle: u64,
    pub secondary_handle: u64,
    pub kind: u32,
    pub operation: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RelValue {
    pub witness_id: u64,
    pub parent_id: u64,
    pub evidence_epoch: u64,
    pub born_ns: u64,
    pub retired_ns: u64,
    pub state: u32,
    pub cardinality: u32,
    pub data: [u64; 10],
    pub tail: [u8; 128],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BindPendingKey {
    pub process_incarnation: u64,
    pub image_epoch: u64,
    pub thread_incarnation: u64,
    pub depth: u32,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BindPendingValue {
    pub occurrence_id: u64,
    pub api_cookie: u64,
    pub entry_handle: u64,
    pub provider_witness: u64,
    pub relation_epoch: u64,
    pub loss_epoch: u64,
    pub mapping_epoch: u64,
    pub entry_ns: u64,
    pub api_role: u32,
    pub reserved: u32,
    pub name_length: u32,
    pub name_state: u32,
    pub name: [u8; 128],
    pub parent_occurrence_id: u64,
    pub method_observation_id: u64,
    pub current_p: u64,
    pub current_c: u64,
    pub staged_x: u64,
    pub source_object_id: u64,
    pub source_epoch: u64,
    pub selector_or_set_id: u64,
    pub dictionary_epoch: u64,
    pub guard_epoch: u64,
    pub constructor_cookie: u64,
    pub getter_count: u16,
    pub constructor_count: u16,
    pub transaction_flags: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SelectorDictionaryKey {
    pub session_id: u64,
    pub selector_id: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct SelectorDictionaryValue {
    pub object_id: u64,
    pub operation: u32,
    pub encoding: u32,
    pub digest: [u8; 32],
    pub dictionary_epoch: u64,
    pub reserved: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SelectorRef {
    pub session_id: u64,
    pub selector_id: u64,
    pub dictionary_epoch: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DigestKey {
    pub code_object_id: u64,
    pub operation: u32,
    pub reserved: u32,
    pub digest: [u8; 32],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ThreadIdentityKey {
    pub process_incarnation: u64,
    pub tid: u32,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ThreadIdentityValue {
    pub thread_incarnation: u64,
    pub image_epoch: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PartitionKey {
    pub version: u32,
    pub size: u32,
    pub session_id: u64,
    pub cut_id: u64,
    pub site_id: u64,
    pub segment_id: u64,
    pub provider_definition_object_id: u64,
    pub provider_continuity_id: u64,
    pub selector_id: u64,
    pub dictionary_epoch: u64,
    pub relation_epoch: u64,
    pub source_epoch: u64,
    pub count_generation: u32,
    pub operation: u32,
    pub function: u32,
    pub selector_encoding: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PartitionValue {
    pub calls: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

/// Fixed SHA-256 request encoding; invoked on dictionary insertion only. The
/// caller supplies a complete ExactNameKey and the retained callback artifact.
/// At most three compression blocks and sixteen schedule words are needed.
pub fn selector_digest(object: &[u8; 32], name: &ExactNameKey) -> Option<[u8; 32]> {
    if name.object_domain == 0 || name.name_length == 0 || name.name_length > 126 {
        return None;
    }
    let mut check = 0;
    while check < 128 {
        if (check < name.name_length as usize && name.name[check] == 0)
            || (check >= name.name_length as usize && name.name[check] != 0)
        {
            return None;
        }
        check += 1;
    }
    let mut message = [0u8; 192];
    message[..16].copy_from_slice(SELECTOR_PREFIX);
    message[16..48].copy_from_slice(object);
    message[48..52].copy_from_slice(&name.operation.to_le_bytes());
    message[52..56].copy_from_slice(&name.name_length.to_le_bytes());
    let length = name.name_length as usize;
    let mut i = 0;
    while i < 126 {
        if i < length {
            message[56 + i] = name.name[i];
        }
        i += 1;
    }
    let used = 56 + length;
    message[used] = 0x80;
    let blocks = if used < 120 { 2 } else { 3 };
    let bits = (used as u64) * 8;
    message[(blocks * 64 - 8)..(blocks * 64)].copy_from_slice(&bits.to_be_bytes());
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut block = 0;
    while block < 3 {
        if block < blocks {
            sha256_block(&mut state, &message, block * 64);
        }
        block += 1;
    }
    let mut digest = [0; 32];
    i = 0;
    while i < 8 {
        digest[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        i += 1;
    }
    Some(digest)
}
#[inline(never)]
fn sha256_block(state: &mut [u32; 8], message: &[u8; 192], offset: usize) {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut w = [0u32; 16];
    let mut i = 0;
    while i < 16 {
        let j = offset + i * 4;
        w[i] = u32::from_be_bytes([message[j], message[j + 1], message[j + 2], message[j + 3]]);
        i += 1;
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    i = 0;
    while i < 64 {
        if i >= 16 {
            let x = w[(i - 15) & 15];
            let y = w[(i - 2) & 15];
            let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
            let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
            w[i & 15] = w[i & 15]
                .wrapping_add(s0)
                .wrapping_add(w[(i - 7) & 15])
                .wrapping_add(s1);
        }
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(choose)
            .wrapping_add(K[i])
            .wrapping_add(w[i & 15]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }
    let values = [a, b, c, d, e, f, g, h];
    i = 0;
    while i < 8 {
        state[i] = state[i].wrapping_add(values[i]);
        i += 1;
    }
}
