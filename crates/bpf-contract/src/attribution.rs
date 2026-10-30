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

/// REL relationship kinds. Kinds 1-5 retain their draft meanings; 6-14 are
/// the first MAC/KDF producer rows; 15-17 are source rows (see `source.rs`).
pub const REL_PROVIDER: u32 = 1;
pub const REL_QUERY: u32 = 2;
pub const REL_BINDING: u32 = 3;
pub const REL_CONTEXT_INDEX: u32 = 4;
pub const REL_CODE_ROLE: u32 = 5;
pub const REL_REQUEST_NAME: u32 = 6;
pub const REL_OBJECT_SELECTOR: u32 = 7;
pub const REL_METHOD: u32 = 8;
pub const REL_OWNER: u32 = 9;
pub const REL_OWNER_SELECTOR: u32 = 10;
pub const REL_METHOD_AMBIGUITY: u32 = 11;
pub const REL_CONTEXT_QUARANTINE: u32 = 12;
pub const REL_X_INDEX: u32 = 13;
pub const REL_U_INDEX: u32 = 14;

/// REL row states. Checked exactly, never inferred bitwise.
pub const REL_WITNESS: u32 = 1;
pub const REL_CERTIFIED: u32 = 2;
pub const REL_RETIRED: u32 = 3;
pub const REL_CONFLICT: u32 = 4;

/// Quarantine secondary-handle domains (`CONTEXT_QUARANTINE.secondary_handle`).
pub const QUARANTINE_OWNER_U: u64 = 1;
pub const QUARANTINE_CONTEXT_X: u64 = 2;

/// Quarantine/ambiguity reasons (`data[0]`).
pub const CONFLICT_METHOD_NAME: u64 = 1;
pub const CONFLICT_SHARED_X: u64 = 2;
pub const CONFLICT_SHARED_U: u64 = 3;
pub const CONFLICT_DUP_EQUALITY: u64 = 4;

/// Producer control modes (`ProducerControl.producer_mode`). The producer is
/// inert unless mode is exactly `ADMITTED`; any other value, including a
/// poison transition, disables every typed read and partition write.
pub const PRODUCER_CLOSED: u64 = 0;
pub const PRODUCER_ADMITTED: u64 = 1;
pub const PRODUCER_POISONED: u64 = 2;

/// Pending-frame name states (`BindPendingValue.name_state`).
pub const NAME_ABSENT: u32 = 0;
pub const NAME_COMPLETE: u32 = 1;
pub const NAME_UNREADABLE: u32 = 2;
pub const NAME_EMPTY: u32 = 3;
pub const NAME_BOUNDARY: u32 = 4;

/// Pending-frame transaction flags (`BindPendingValue.transaction_flags`).
pub const TXN_AMBIGUITY: u32 = 1;
pub const TXN_GUARD_CHANGED: u32 = 2;
pub const TXN_SOURCE_CHANGED: u32 = 4;
pub const TXN_PUBLICATION_FAILED: u32 = 8;
pub const TXN_COLLISION: u32 = 16;

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
            | 161
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
            161 => "OSSL_PROVIDER_query_operation",
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
    /// Exact first-slice (api, operation, function) triple per role.
    /// Single table shared by the constructor and host-side admission
    /// programming; reserved roles have no triple and never admit.
    /// Role 161 is the U1 query-observation role: legacy query API 8,
    /// operation/function 0 (the observed op rides the pending frame,
    /// never the admission triple).
    #[inline(always)]
    pub const fn admission_parts(role_id: u32) -> Option<(u32, u32, u32)> {
        match role_id {
            5 => Some((5, 0, 0)),
            18 => Some((0, 0, 0)),
            161 => Some((8, 0, 0)),
            130 => Some((12, 3, 0)),
            131 => Some((13, 4, 0)),
            136 | 142 | 147 | 149 | 151 => Some((0, 3, 0)),
            137 | 143 | 148 | 150 | 152 | 153 => Some((0, 4, 0)),
            146 | 154 | 155 => Some((0, 0, 0)),
            258 => Some((0, 3, 1)),
            259 => Some((0, 4, 1)),
            274 => Some((0, 3, 3)),
            275 => Some((0, 4, 3)),
            290 => Some((0, 3, 2)),
            291 => Some((0, 4, 2)),
            304 => Some((0, 3, 4)),
            305 => Some((0, 3, 5)),
            306 => Some((0, 3, 6)),
            307 => Some((0, 4, 5)),
            308 => Some((0, 4, 4)),
            _ => None,
        }
    }
    /// Exact first-slice role table. Reserved roles are not admitted.
    #[inline(always)]
    pub const fn new(
        role_id: u32,
        public_api_id: u32,
        operation: u32,
        function: u32,
        abi_epoch: u64,
        source_epoch: u64,
    ) -> Option<Self> {
        let (api, op, fun) = match Self::admission_parts(role_id) {
            Some(parts) => parts,
            None => return None,
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
    #[inline(always)]
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
    #[inline(always)]
    pub const fn paired(&self) -> bool {
        matches!(
            self.role_id,
            130 | 131 | 142 | 143 | 146 | 147 | 148 | 151 | 152 | 161 | 258 | 259 | 290 | 291
        )
    }
    #[inline(always)]
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
/// Check raw helper-read name bytes are already in canonical zero-padded
/// form: `length` nonzero bytes up front, zeroes after. This is STRICTER
/// than [`ExactNameKey::from_read`], which zero-pads and therefore accepts
/// garbage tails: BPF uses the raw buffer verbatim as exact-key and request
/// row material (see `intern_request`), so only canonical buffers may pass.
/// The staged frames start zeroed and the string helper preserves the zero
/// tail, which makes this sound on the kernel path.
#[inline(always)]
pub fn exact_name_canonical(bytes: &[u8; 128], length: u32) -> bool {
    if length == 0 || length > 126 {
        return false;
    }
    let mut check = 0;
    while check < 128 {
        if (check < length as usize && bytes[check] == 0)
            || (check >= length as usize && bytes[check] != 0)
        {
            return false;
        }
        check += 1;
    }
    true
}
impl ExactNameKey {
    /// Helper result includes NUL. Return128 may be truncation: never accept it.
    /// Always inlined: BPF callers materialize the 144-byte key once on the
    /// merged caller frame instead of nesting it under a call frame.
    #[inline(always)]
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

/// CODE_ROLE (kind 5) key shape: full target-domain scope plus the
/// VMA-joined callback (inode, file offset) and the live packed
/// (operation, function) pair. One row per (file, offset, op, fun):
/// same-(op, fun) callbacks across provider algos publish distinct
/// rows instead of colliding. The relation epoch is 0 so ordinary
/// relation/loss advance cannot clear code facts; code replacement
/// changes the inode or image instead.
///
/// `RelKey` has no free slot, so the shape repurposes kind-5 field
/// meaning inside the unchanged 48-byte key (the OWNER precedent:
/// explicit per-kind decoding, no map-layout change). `secondary`
/// carries the exact observed file offset; the `operation` slot
/// carries [`code_role_pair`], never the bare operation. The value
/// ([`code_role_data`]) keeps the plain operation/function/offset, and
/// both kernel readers (publish-adopt, consuming join) re-verify them
/// from the value, so a hypothetical packed-pair collision fails
/// closed as a refusal, never a false certification.
///
/// The key is inode-SCOPED, never cookie-bound: the consuming kernel
/// join binds it to the firing cookie's live registration/source epoch
/// (two-phase binding, because the firing cookie exists only in the
/// copied callback's own probe context and the query-time publisher
/// observes bare dispatch-table addresses). No VA/cookie dependence is
/// structural in this constructor: it takes neither (see the
/// signature). A caller cannot smuggle either in. The kernel
/// `code_role_key` wrapper delegates here; the full interpretation
/// comment lives with it.
#[inline(always)]
pub const fn code_role_key(
    process_incarnation: u64,
    image_epoch: u64,
    inode: u64,
    file_offset: u64,
    function: u32,
    operation: u32,
) -> RelKey {
    RelKey {
        process_incarnation,
        image_epoch,
        relation_epoch: 0,
        primary_handle: inode,
        secondary_handle: file_offset,
        kind: REL_CODE_ROLE,
        operation: code_role_pair(function, operation),
    }
}

/// Pack the live (operation, function) pair into the CODE_ROLE key's
/// `operation` slot (kind 5 only). Injective over the `code_shape`
/// domain (operations 3|4, functions 1..=6): callers must gate through
/// `code_shape` before constructing the key, and both kernel call
/// sites (publish, consuming join) do. Out-of-domain inputs fold
/// silently at this layer; the value cross-checks fail them closed.
#[inline(always)]
pub const fn code_role_pair(function: u32, operation: u32) -> u32 {
    ((function & 0xFFFF) << 16) | (operation & 0xFFFF)
}

/// CODE_ROLE (kind 5) value identity: the live operation, function,
/// reviewed ABI shape, exact observed file offset of the advertised
/// callback, publishing query witness and publication sequence. The
/// offset at `data[3]` is the substitution killer: a query advertising
/// callback A never authorizes a separately staged callback B at
/// another offset in the same file. The key carries the same offset
/// plus the packed pair, so the value positions double as the
/// publish-adopt/join cross-checks. `data[5]` and `data[7..=9]` stay
/// zero. The kernel publisher writes this exact array; the pin below
/// locks every position.
#[inline(always)]
pub const fn code_role_data(
    operation: u64,
    function: u64,
    shape: u64,
    file_offset: u64,
    occurrence: u64,
    sequence: u64,
) -> [u64; 10] {
    [
        operation,
        function,
        shape,
        file_offset,
        occurrence,
        0,
        sequence,
        0,
        0,
        0,
    ]
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
/// Typed-admission/site-bind key: the full process/image-bound site/cookie
/// identity, never a naked address. Admission is programmed per incarnation;
/// exec retires the old image rows by key mismatch. 24 bytes, align 8.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct TypedSiteKey {
    pub cookie: u64,
    pub process_incarnation: u64,
    pub image_epoch: u64,
}
/// Host-programmed per-site binding for the typed producer. The site's
/// `site_id` is the observer dictionary ID the partition writer emits; the
/// `source_epoch` selects that site's `SOURCE_READY` row; `code_object_id`
/// is the retained object containing the firing callback; `object_sha256`
/// is that retained artifact's raw 32-byte fingerprint feeding the request
/// digest (B in encoding 2). IDs are nonzero. 56 bytes, align 8.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct SiteBindValue {
    pub site_id: u64,
    pub source_epoch: u64,
    pub code_object_id: u64,
    pub object_sha256: [u8; 32],
}
impl SiteBindValue {
    #[inline(always)]
    pub const fn valid(&self) -> bool {
        self.site_id != 0 && self.source_epoch != 0 && self.code_object_id != 0
    }
}
/// Producer control cell (single-entry array). The host programs the
/// session/cut/admission coordinates and the initial epochs before opening
/// admission; only the qualified source-acquisition path may transition
/// `producer_mode` from `CLOSED` to `ADMITTED`. Kernel poison paths advance
/// `relation_epoch`/`loss_epoch` and may set `POISONED`; the host never
/// mutates this cell after admission opens. 64 bytes, align 8.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ProducerControl {
    pub producer_mode: u64,
    pub session_id: u64,
    pub admission_epoch: u64,
    pub cut_id: u64,
    pub next_producer_id: u64,
    pub relation_epoch: u64,
    pub loss_epoch: u64,
    pub reserved: u64,
}
impl ProducerControl {
    pub const fn admitted(&self) -> bool {
        self.producer_mode == PRODUCER_ADMITTED
            && self.session_id != 0
            && self.admission_epoch != 0
            && self.cut_id != 0
            && self.next_producer_id != 0
            && self.relation_epoch != 0
            && self.loss_epoch != 0
            && self.reserved == 0
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DigestKey {
    pub code_object_id: u64,
    pub operation: u32,
    pub reserved: u32,
    pub digest: [u8; 32],
}
/// Segment index key: one immutable attribution tuple (site, owner interval,
/// count generation, operation/function) maps to exactly one nonzero segment
/// ID. The kernel allocates the segment once per tuple; every later hit with
/// the same tuple reuses it, so per-CPU shards reduce exactly once. 32 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct SegmentIndexKey {
    pub site_id: u64,
    pub owner_id: u64,
    pub count_generation: u32,
    pub operation: u32,
    pub function: u32,
    pub reserved: u32,
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
    let mut message = [0u8; 192];
    selector_digest_into(object, name, &mut message)
}
/// Scratch-buffer variant of [`selector_digest`] for BPF callers whose 512B
/// stack cannot hold the 192-byte padded message beside the 144-byte key.
/// The caller supplies any 192-byte buffer that no nested producer path can
/// observe: BPF passes its per-CPU staging cell while holding the shared
/// publisher lock, which serializes every staging user on every CPU. The
/// buffer is fully rewritten on success and left unspecified on failure.
#[inline(always)]
pub fn selector_digest_into(
    object: &[u8; 32],
    name: &ExactNameKey,
    message: &mut [u8; 192],
) -> Option<[u8; 32]> {
    if name.object_domain == 0 {
        return None;
    }
    selector_digest_parts(
        name.operation,
        name.name_length,
        &name.name,
        object,
        message,
    )
}
/// Parts-based variant hashing an exact request without materializing the
/// 144-byte key: the BPF commit path marshals directly from the immutable
/// request row and the retained artifact hash. Validation is identical to
/// the key-based entry point; only the key container differs. Always
/// inlined so the BPF caller keeps one flat frame above the block hash.
#[inline(always)]
pub fn selector_digest_parts(
    operation: u32,
    name_length: u32,
    name: &[u8; 128],
    object: &[u8; 32],
    message: &mut [u8; 192],
) -> Option<[u8; 32]> {
    if !matches!(operation, 3 | 4) || name_length == 0 || name_length > 126 {
        return None;
    }
    let mut check = 0;
    while check < 128 {
        if (check < name_length as usize && name[check] == 0)
            || (check >= name_length as usize && name[check] != 0)
        {
            return None;
        }
        check += 1;
    }
    // Immediate stores, not `copy_from_slice(SELECTOR_PREFIX)`: taking the
    // prefix's address pools it in `.rodata.cst16`, and the loader accepts
    // no data-section relocation. The pair spells "ossl-code-req-v1".
    message[..8].copy_from_slice(&u64::from_le_bytes(*b"ossl-cod").to_le_bytes());
    message[8..16].copy_from_slice(&u64::from_le_bytes(*b"e-req-v1").to_le_bytes());
    message[16..48].copy_from_slice(object);
    message[48..52].copy_from_slice(&operation.to_le_bytes());
    message[52..56].copy_from_slice(&name_length.to_le_bytes());
    let length = name_length as usize;
    let mut i = 0;
    while i < 126 {
        if i < length {
            message[56 + i] = name[i];
        } else {
            message[56 + i] = 0;
        }
        i += 1;
    }
    i = 56 + length;
    while i < 192 {
        message[i] = 0;
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
            // Panic-free chunking: the loader accepts no call into the
            // cold panic section, so a dynamic `message[offset]` index is
            // forbidden here; `get` fails closed instead of panicking.
            let start = block * 64;
            let slice = message.get(start..start + 64)?;
            let block_bytes: &[u8; 64] = slice.try_into().ok()?;
            sha256_block(&mut state, block_bytes);
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
#[cfg_attr(target_arch = "bpf", unsafe(no_mangle))]
pub fn sha256_block(state: &mut [u32; 8], block: &[u8; 64]) -> u64 {
    // Stack array, not `const`: a const table is pooled in `.rodata` and
    // addressed by relocation, which the loader rejects; the 64 immediates
    // materialize on the stack and the verifier checks the depth on load.
    let k: [u32; 64] = [
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
        let j = i * 4;
        w[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
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
            .wrapping_add(k[i])
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
    // Scalar tail, not `()`: the K-materialization loop leaves a stack
    // address in R0, and a BPF subprogram may not exit with R0 holding a
    // stack pointer. Callers ignore the value.
    u64::from(state[0])
}
