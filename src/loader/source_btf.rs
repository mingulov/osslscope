// SPDX-License-Identifier: GPL-3.0-or-later
//! Finite kernel layout admission for the callback-free code-source join.

use anyhow::{Result, ensure};

// These bounds cover the running kernel BTF, not arbitrary user BTF packages.
// The owner reserves input plus the maximal offset index before reading it.
pub(super) const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_TYPES: usize = 0x000f_ffff;
pub(super) const SCRATCH_RESERVATION: usize = MAX_BYTES + MAX_TYPES * 4 + 4096;

/// Only validated semantic offsets/IDs escape the borrowed BTF view. Neither
/// kernel pointers nor unrelated types are retained or exposed as output.
pub(super) struct SourceLayout {
    functions: [u32; 3],
    fields: [u32; 6],
    vma_bytes: u32,
    registration_function: u32,
    allocation: [u32; 2],
}
impl SourceLayout {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let view = View::parse(bytes)?;
        let iterator = view.named(4, b"bpf_iter_task_vma")?;
        let task = view.named(4, b"task_struct")?;
        let vma = view.named(4, b"vm_area_struct")?;
        let file = view.named(4, b"file")?;
        let inode = view.named(4, b"inode")?;
        let it = view.ty(iterator)?;
        ensure!(it.size == 8 && it.count == 1, "source iterator shape");
        let (opaque, offset) = view.member(iterator, b"__opaque")?;
        ensure!(offset == 0, "source iterator alignment");
        let array = view.ty(view.resolve(opaque)?)?;
        ensure!(
            array.kind == 3 && word(array.data, 8)? == 1,
            "source iterator storage"
        );
        view.integer(word(array.data, 0)?, 8, false, false)?;
        let mut fields = [0; 6];
        for (i, name) in [b"vm_start".as_slice(), b"vm_end", b"vm_pgoff", b"vm_flags"]
            .iter()
            .enumerate()
        {
            let (ty, offset) = view.member(vma, name)?;
            view.integer(ty, 8, false, true)?;
            fields[i] = offset;
        }
        let (ty, offset) = view.member(vma, b"vm_file")?;
        view.pointer(ty, file)?;
        fields[4] = offset;
        let (ty, offset) = view.member(file, b"f_inode")?;
        view.pointer(ty, inode)?;
        fields[5] = offset;
        for i in 0..5 {
            ensure!(
                !fields[..i].contains(&fields[i]),
                "overlapping source fields"
            );
        }
        let mut functions = [0; 3];
        for (i, name) in [
            b"bpf_iter_task_vma_new".as_slice(),
            b"bpf_iter_task_vma_next",
            b"bpf_iter_task_vma_destroy",
        ]
        .iter()
        .enumerate()
        {
            let id = view.named(12, name)?;
            let function = view.ty(id)?;
            ensure!(
                function.count <= 1 && !function.flag,
                "source kfunc definition"
            );
            let proto = view.ty(function.size)?;
            ensure!(
                proto.kind == 13 && !proto.flag && proto.count == if i == 0 { 3 } else { 1 },
                "source kfunc arguments"
            );
            view.pointer(word(proto.data, 4)?, iterator)?;
            match i {
                0 => {
                    view.pointer(word(proto.data, 12)?, task)?;
                    view.integer(word(proto.data, 20)?, 8, false, false)?;
                    view.integer(proto.size, 4, true, false)?;
                }
                1 => view.pointer(proto.size, vma)?,
                _ => ensure!(proto.size == 0, "source destroy return"),
            }
            functions[i] = id;
        }
        // The observer-only registration hooks have one finite trampoline ABI.
        // Checking the consumer pointer type does not authorize reading arg3.
        let consumer = view.named(4, b"uprobe_consumer")?;
        let uprobe = view.named(4, b"uprobe")?;
        let registration_function = view.named(12, b"uprobe_register")?;
        let function = view.ty(registration_function)?;
        ensure!(
            function.count <= 1 && !function.flag,
            "registration definition"
        );
        let proto = view.ty(function.size)?;
        ensure!(
            proto.kind == 13 && !proto.flag && proto.count == 4,
            "registration arguments"
        );
        view.pointer(word(proto.data, 4)?, inode)?;
        view.integer(word(proto.data, 12)?, 8, true, false)?;
        view.integer(word(proto.data, 20)?, 8, true, false)?;
        view.pointer(word(proto.data, 28)?, consumer)?;
        view.pointer(proto.size, uprobe)?;
        // Capacity metadata only: never resolve or read this internal type's
        // members. The iterator's 8B opaque handle is not its allocation size.
        let allocation_type = view.ty(view.named(4, b"bpf_iter_task_vma_kern_data")?)?;
        ensure!(
            allocation_type.size >= 8 && allocation_type.size % 8 == 0,
            "iterator allocation extent"
        );
        let with_node = allocation_type
            .size
            .checked_add(8)
            .ok_or_else(|| anyhow::anyhow!("iterator allocation overflow"))?;
        // Reviewed bpf_mem_alloc non-percpu LLIST_NODE_SZ and finite classes.
        // This validates a class only, not concurrent/cache/deferred capacity.
        let class = [16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096]
            .into_iter()
            .find(|class| *class >= with_node)
            .ok_or_else(|| anyhow::anyhow!("iterator allocation class unavailable"))?;
        Ok(Self {
            functions,
            fields,
            vma_bytes: view.ty(vma)?.size,
            registration_function,
            allocation: [allocation_type.size, class],
        })
    }
    pub(super) fn kfunc_ids(&self) -> [u32; 3] {
        self.functions
    }
    pub(super) fn field_offsets(&self) -> [u32; 6] {
        self.fields
    }
    pub(super) fn vma_size(&self) -> u32 {
        self.vma_bytes
    }
    pub(super) fn registration_id(&self) -> u32 {
        self.registration_function
    }
    pub(super) fn allocation(&self) -> [u32; 2] {
        self.allocation
    }
}
fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    let bytes = bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or_else(|| anyhow::anyhow!("BTF offset"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("truncated source BTF"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}
struct Ty<'a> {
    name: u32,
    kind: u32,
    count: u32,
    size: u32,
    flag: bool,
    data: &'a [u8],
}
struct View<'a> {
    types: &'a [u8],
    strings: &'a [u8],
    offsets: Vec<u32>,
}
impl<'a> View<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 24 && bytes.len() <= MAX_BYTES,
            "source BTF bounds"
        );
        ensure!(
            bytes[..4] == [0x9f, 0xeb, 1, 0] && word(bytes, 4)? == 24,
            "source BTF header"
        );
        let section = |offset, length| -> Result<&'a [u8]> {
            let start = 24usize
                .checked_add(word(bytes, offset)? as usize)
                .ok_or_else(|| anyhow::anyhow!("BTF offset"))?;
            let end = start
                .checked_add(word(bytes, length)? as usize)
                .ok_or_else(|| anyhow::anyhow!("BTF length"))?;
            bytes
                .get(start..end)
                .ok_or_else(|| anyhow::anyhow!("source BTF section"))
        };
        let types = section(8, 12)?;
        let strings = section(16, 20)?;
        let type_start = word(bytes, 8)? as usize;
        let string_start = word(bytes, 16)? as usize;
        ensure!(
            type_start + types.len() <= string_start || string_start + strings.len() <= type_start,
            "overlapping BTF sections"
        );
        ensure!(
            strings.first() == Some(&0) && strings.last() == Some(&0),
            "source BTF strings"
        );
        let mut offsets = Vec::with_capacity(MAX_TYPES);
        let mut cursor = 0;
        while cursor < types.len() {
            ensure!(offsets.len() < MAX_TYPES, "source BTF type bound");
            let info = word(types, cursor + 4)?;
            let kind = (info >> 24) & 31;
            let count = (info & 0xffff) as usize;
            ensure!(info & 0x60ff0000 == 0, "source BTF reserved bits");
            let payload = match kind {
                1 | 14 | 17 => 4,
                2 | 7..=12 | 16 | 18 => 0,
                3 => 12,
                4 | 5 | 15 | 19 => count * 12,
                6 | 13 => count * 8,
                _ => anyhow::bail!("unknown source BTF kind"),
            };
            ensure!(
                !matches!(kind, 1..=3 | 7..=11 | 14 | 16..=18) || count == 0,
                "source BTF scalar count"
            );
            ensure!(kind != 12 || count <= 2, "source BTF linkage");
            let end = cursor + 12 + payload;
            ensure!(end <= types.len(), "truncated source BTF type");
            offsets.push(cursor as u32);
            cursor = end;
        }
        Ok(Self {
            types,
            strings,
            offsets,
        })
    }
    fn ty(&self, id: u32) -> Result<Ty<'a>> {
        let offset = *self
            .offsets
            .get(
                id.checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("source BTF void"))? as usize,
            )
            .ok_or_else(|| anyhow::anyhow!("source BTF type ID"))? as usize;
        let end = self
            .offsets
            .get(id as usize)
            .map_or(self.types.len(), |n| *n as usize);
        let info = word(self.types, offset + 4)?;
        Ok(Ty {
            name: word(self.types, offset)?,
            kind: info >> 24 & 31,
            count: info & 0xffff,
            size: word(self.types, offset + 8)?,
            flag: info >> 31 != 0,
            data: &self.types[offset + 12..end],
        })
    }
    fn name_is(&self, offset: u32, name: &[u8]) -> bool {
        let offset = offset as usize;
        self.strings.get(offset..offset + name.len()) == Some(name)
            && self.strings.get(offset + name.len()) == Some(&0)
    }
    fn named(&self, kind: u32, name: &[u8]) -> Result<u32> {
        let mut found = None;
        for id in 1..=self.offsets.len() as u32 {
            let ty = self.ty(id)?;
            if ty.kind == kind && self.name_is(ty.name, name) {
                ensure!(found.is_none(), "ambiguous source BTF type");
                found = Some(id);
            }
        }
        found.ok_or_else(|| anyhow::anyhow!("missing source BTF type"))
    }
    fn resolve(&self, mut id: u32) -> Result<u32> {
        for _ in 0..32 {
            let ty = self.ty(id)?;
            if !matches!(ty.kind, 8..=11 | 18) {
                return Ok(id);
            }
            id = ty.size;
        }
        anyhow::bail!("cyclic or excessive source BTF qualifiers")
    }
    fn integer(&self, id: u32, bytes: u32, signed: bool, native_long: bool) -> Result<()> {
        let ty = self.ty(self.resolve(id)?)?;
        ensure!(
            ty.kind == 1
                && !ty.flag
                && ty.size == bytes
                && word(ty.data, 0)? == ((u32::from(signed) << 24) | (bytes * 8)),
            "source integer ABI"
        );
        ensure!(
            !native_long
                || self.name_is(ty.name, b"long unsigned int")
                || self.name_is(ty.name, b"unsigned long"),
            "source native long ABI"
        );
        Ok(())
    }
    fn pointer(&self, id: u32, expected: u32) -> Result<()> {
        let ty = self.ty(self.resolve(id)?)?;
        ensure!(
            ty.kind == 2 && !ty.flag && self.resolve(ty.size)? == expected,
            "source pointer ABI"
        );
        Ok(())
    }
    fn member(&self, id: u32, name: &[u8]) -> Result<(u32, u32)> {
        let mut found = None;
        let mut visited = 0;
        self.member_in(id, name, 0, 0, &mut visited, &mut found)?;
        found.ok_or_else(|| anyhow::anyhow!("missing source BTF member"))
    }
    // C anonymous aggregates promote exactly these semantic members. Follow no
    // named member or pointer, and bound both depth and total aggregate visits.
    fn member_in(
        &self,
        id: u32,
        name: &[u8],
        base: u32,
        depth: u32,
        visited: &mut u32,
        found: &mut Option<(u32, u32)>,
    ) -> Result<()> {
        *visited += 1;
        ensure!(
            depth <= 8 && *visited <= 32,
            "source anonymous aggregate bound"
        );
        let ty = self.ty(self.resolve(id)?)?;
        ensure!(
            matches!(ty.kind, 4 | 5) && ty.size >= 8 && ty.size % 8 == 0,
            "source containing type"
        );
        for member in ty.data.chunks_exact(12) {
            let member_name = word(member, 0)?;
            let wanted = self.name_is(member_name, name);
            let anonymous = member_name == 0;
            if !wanted && !anonymous {
                continue;
            }
            let bits = word(member, 8)?;
            ensure!(!ty.flag || bits >> 24 == 0, "source BTF bitfield");
            ensure!(
                bits % 64 == 0 && bits / 8 <= ty.size - 8,
                "source BTF member extent"
            );
            let offset = base
                .checked_add(bits / 8)
                .ok_or_else(|| anyhow::anyhow!("source BTF offset overflow"))?;
            let member_id = word(member, 4)?;
            if wanted {
                ensure!(found.is_none(), "ambiguous source BTF member");
                *found = Some((member_id, offset));
            } else {
                let child = self.ty(self.resolve(member_id)?)?;
                ensure!(
                    child.size <= ty.size - bits / 8,
                    "source anonymous aggregate extent"
                );
                self.member_in(member_id, name, offset, depth + 1, visited, found)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        types: Vec<u8>,
        strings: Vec<u8>,
        count: u32,
        offsets: Vec<usize>,
    }
    impl Fixture {
        fn new() -> Self {
            Self {
                types: Vec::new(),
                strings: vec![0],
                count: 0,
                offsets: Vec::new(),
            }
        }
        fn name(&mut self, name: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            off
        }
        fn ty(&mut self, name: &str, kind: u32, count: u32, size: u32, data: &[u32]) -> u32 {
            let name = self.name(name);
            self.offsets.push(self.types.len());
            for n in [name, kind << 24 | count, size]
                .into_iter()
                .chain(data.iter().copied())
            {
                self.types.extend_from_slice(&n.to_le_bytes());
            }
            self.count += 1;
            self.count
        }
        fn member(&mut self, name: &str, ty: u32, bits: u32) -> [u32; 3] {
            [self.name(name), ty, bits]
        }
        fn mutate(&mut self, id: usize, offset: usize, value: u32) {
            let offset = self.offsets[id - 1] + offset;
            self.types[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn finish(self) -> Vec<u8> {
            let mut bytes = vec![0x9f, 0xeb, 1, 0];
            for n in [
                24,
                0,
                self.types.len() as u32,
                self.types.len() as u32,
                self.strings.len() as u32,
            ] {
                bytes.extend_from_slice(&n.to_le_bytes());
            }
            bytes.extend(self.types);
            bytes.extend(self.strings);
            bytes
        }
    }
    fn fixture() -> Fixture {
        let mut f = Fixture::new();
        let ulong = f.ty("long unsigned int", 1, 0, 8, &[64]); // 1
        let int = f.ty("int", 1, 0, 4, &[1 << 24 | 32]); // 2
        let array = f.ty("", 3, 0, 0, &[ulong, int, 1]); // 3
        let opaque = f.member("__opaque", array, 0);
        let iter = f.ty("bpf_iter_task_vma", 4, 1, 8, &opaque); // 4
        let iter_ptr = f.ty("", 2, 0, iter, &[]); // 5
        let task = f.ty("task_struct", 4, 0, 64, &[]); // 6
        let task_ptr = f.ty("", 2, 0, task, &[]); // 7
        let inode = f.ty("inode", 4, 0, 64, &[]); // 8
        let inode_ptr = f.ty("", 2, 0, inode, &[]); // 9
        let inode_member = f.member("f_inode", inode_ptr, 64);
        let file = f.ty("file", 4, 1, 32, &inode_member); // 10
        let file_ptr = f.ty("", 2, 0, file, &[]); // 11
        let members = [
            f.member("vm_start", ulong, 0),
            f.member("vm_end", ulong, 64),
            f.member("vm_pgoff", ulong, 128),
            f.member("vm_flags", ulong, 192),
            f.member("vm_file", file_ptr, 256),
        ]
        .concat();
        let vma = f.ty("vm_area_struct", 4, 5, 64, &members); // 12
        let vma_ptr = f.ty("", 2, 0, vma, &[]); // 13
        let new_proto = f.ty("", 13, 3, int, &[0, iter_ptr, 0, task_ptr, 0, ulong]); // 14
        f.ty("bpf_iter_task_vma_new", 12, 1, new_proto, &[]); // 15
        let next_proto = f.ty("", 13, 1, vma_ptr, &[0, iter_ptr]); // 16
        f.ty("bpf_iter_task_vma_next", 12, 1, next_proto, &[]); // 17
        let destroy_proto = f.ty("", 13, 1, 0, &[0, iter_ptr]); // 18
        f.ty("bpf_iter_task_vma_destroy", 12, 1, destroy_proto, &[]); // 19
        let loff = f.ty("long long int", 1, 0, 8, &[1 << 24 | 64]); // 20
        let consumer = f.ty("uprobe_consumer", 4, 0, 64, &[]); // 21
        let consumer_ptr = f.ty("", 2, 0, consumer, &[]); // 22
        let uprobe = f.ty("uprobe", 4, 0, 64, &[]); // 23
        let uprobe_ptr = f.ty("", 2, 0, uprobe, &[]); // 24
        let registration = f.ty(
            "",
            13,
            4,
            uprobe_ptr,
            &[0, inode_ptr, 0, loff, 0, loff, 0, consumer_ptr],
        ); // 25
        f.ty("uprobe_register", 12, 1, registration, &[]); // 26
        f.ty("bpf_iter_task_vma_kern_data", 4, 0, 320, &[]); // 27
        f
    }
    #[test]
    fn finite_source_layout_validates_exact_fields_and_prototypes() {
        let got = SourceLayout::parse(&fixture().finish()).unwrap();
        assert_eq!(got.kfunc_ids(), [15, 17, 19]);
        assert_eq!(got.field_offsets(), [0, 8, 16, 24, 32, 8]);
        assert_eq!(got.vma_size(), 64);
        assert_eq!(got.registration_id(), 26);
        assert_eq!(got.allocation(), [320, 512]);
        // vmlinux BTF producers may mark registered kfunc definitions STATIC.
        let mut static_definition = fixture();
        static_definition.mutate(15, 4, 12 << 24);
        assert!(SourceLayout::parse(&static_definition.finish()).is_ok());
        let mut external_declaration = fixture();
        external_declaration.mutate(15, 4, 12 << 24 | 2);
        assert!(SourceLayout::parse(&external_declaration.finish()).is_err());
    }
    #[test]
    fn finite_source_layout_rejects_type_and_layout_ambiguity() {
        let mut duplicate = fixture();
        duplicate.ty("vm_area_struct", 4, 0, 64, &[]);
        assert!(SourceLayout::parse(&duplicate.finish()).is_err());
        for (offset, value) in [(12usize, 1 << 24 | 64), (28, 8), (36, 0)] {
            let mut bytes = fixture().finish();
            bytes[24 + offset..28 + offset].copy_from_slice(&u32::to_le_bytes(value));
            assert!(SourceLayout::parse(&bytes).is_err(), "mutation at {offset}");
        }
        let mut bytes = fixture().finish();
        bytes[2] = 2;
        assert!(SourceLayout::parse(&bytes).is_err());
        for length in [0, 23, 25, bytes.len() - 1] {
            assert!(SourceLayout::parse(&bytes[..length]).is_err());
        }
    }
    #[test]
    fn finite_source_layout_rejects_bitfields_alias_cycles_and_wrong_pointees() {
        for (id, offset, value) in [
            (12, 4, 1 << 31 | 4 << 24 | 5), // paired with bitfield mutation below
            (12, 20, 32),                   // vm_start is not aligned to a native long
            (12, 8, 32),                    // vm_file extends beyond containing structure
            (11, 8, 8),                     // vm_file points to inode rather than file
            (9, 8, 10),                     // f_inode points to file rather than inode
            (14, 8, 1),                     // new returns unsigned long rather than signed int
            (16, 8, 11),                    // next returns file rather than VMA
            (18, 8, 2),                     // destroy is not void
            (3, 20, 2),                     // iterator opaque storage is not a single u64
        ] {
            let mut f = fixture();
            f.mutate(id, offset, value);
            if id == 12 && offset == 4 {
                f.mutate(12, 20, 8 << 24);
            }
            assert!(
                SourceLayout::parse(&f.finish()).is_err(),
                "mutation {id}/{offset}"
            );
        }
        let mut f = fixture();
        let next_id = f.count + 1;
        let alias = f.ty("bad_alias", 8, 0, next_id, &[]);
        assert_eq!(alias, next_id);
        f.mutate(12, 16, alias);
        assert!(SourceLayout::parse(&f.finish()).is_err());
    }
    #[test]
    fn finite_source_layout_resolves_only_bounded_anonymous_promotions() {
        let mut f = fixture();
        let start = f.offsets[11];
        let original = f.types[start + 12..start + 72]
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect::<Vec<_>>();
        let aggregate = f.ty("", 4, 5, 64, &original);
        let union = f.ty("", 5, 1, 64, &[0, aggregate, 0]);
        f.mutate(12, 4, 4 << 24 | 1);
        for (offset, value) in [(12, 0), (16, union), (20, 0)] {
            f.mutate(12, offset, value);
        }
        f.types.drain(start + 24..start + 72);
        let layout = SourceLayout::parse(&f.finish()).unwrap();
        assert_eq!(layout.field_offsets(), [0, 8, 16, 24, 32, 8]);
    }
    #[test]
    fn source_registration_abi_rejects_integer_return_and_wrong_parameters() {
        for (offset, value) in [(8, 2), (16, 11), (24, 2), (32, 1), (40, 9)] {
            let mut f = fixture();
            f.mutate(25, offset, value);
            assert!(
                SourceLayout::parse(&f.finish()).is_err(),
                "registration prototype mutation at {offset}"
            );
        }
    }
    #[test]
    fn iterator_allocation_metadata_refuses_unaccountable_sizes() {
        for size in [0, 1, 4089, 4096, u32::MAX] {
            let mut f = fixture();
            f.mutate(27, 8, size);
            assert!(
                SourceLayout::parse(&f.finish()).is_err(),
                "allocation size {size}"
            );
        }
        let mut f = fixture();
        f.mutate(27, 8, 4088);
        assert_eq!(
            SourceLayout::parse(&f.finish()).unwrap().allocation(),
            [4088, 4096]
        );
    }
    #[test]
    fn source_kernel_budget_precedes_file_acquisition() {
        let budget = crate::provider_observation::ObservationBudget::new(
            crate::provider_observation::ObservationLimits {
                max_state_bytes: 0,
                ..Default::default()
            },
        );
        assert!(matches!(
            super::super::SourceKernel::read(&budget),
            Err(crate::provider_observation::ObservationGap::StateLimit)
        ));
    }
    #[test]
    #[ignore = "read-only running-kernel BTF capability check"]
    fn running_kernel_source_layout() {
        let budget = crate::provider_observation::ObservationBudget::default();
        let layout = super::super::SourceKernel::read(&budget).unwrap();
        assert!(layout._configuration[..3].iter().all(|id| *id > 0));
        assert!(layout._configuration[10] > 0);
        assert!(layout._configuration[11] >= 8);
        assert!(layout._configuration[12] >= layout._configuration[11] + 8);
        assert!(
            layout._configuration[3..8]
                .iter()
                .all(|offset| *offset + 8 <= layout._configuration[9])
        );
    }
}
