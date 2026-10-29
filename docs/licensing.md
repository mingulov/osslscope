<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Component licensing and BPF boundary

The host application, host-only `osslscope-ebpf-common`, documentation, and
build scripts carry GPL-3.0-or-later terms; the root [LICENSE](../LICENSE)
contains that license. The five shipped BPF program sources in `crates/ebpf` carry
GPL-2.0-only terms; [GPL-2.0-only.txt](../LICENSES/GPL-2.0-only.txt)
contains that text. The independent `crates/bpf-contract` component carries
GPL-2.0-or-later package and file expressions. It is used under its GPL-2.0
option in the GPL-2.0-only BPF programs. The GPL-2.0-only text is applicable
to that selected option; the component retains its explicit `-or-later`
expression.

The detached BPF workspace depends directly on `osslscope-bpf-contract`,
not on host common. The host keeps its host-common dependency. Both sides
use the same specified wire records and constants through separate source
components. The host owns parsing, registry population, and validation;
the BPF component supplies the bounded record, scalar, and classification
surface used by the BPF programs.

The loader accepts a `.license` ELF section when present and checks its
GPL-compatible value. When absent, it uses the same `GPL` program-load
argument. The two program-load attempts both pass `GPL`; this kernel API
argument does not change a file's source license. A particular object's
optional section presence and bytes must be inspected on that build.

These package and file expressions describe this product tree's component
terms. A source and dependency review, an actual-object inspection, and
separate runtime qualification are needed before claims about a particular
release artifact. Metadata and the kernel load argument alone do not
establish source provenance or conveyance rights.

## Source-only preview inventory

The preview's source archive is produced from the tracked product repository.
It includes the project components above, both lockfiles, source fixtures,
catalogue metadata, schemas, scripts and documentation. It excludes private
workspace material, generated outputs, compiled host/BPF binaries and vendored
third-party source. OpenSSL, the kernel, registry dependencies and the pinned
Rust/linker prerequisites are separate build/runtime inputs under their own
terms; they are not bundled into this source archive.

The [source component notices](../NOTICE.md) and
[license index](../LICENSES/README.md) describe that conveyed inventory. The
lockfiles pin external versions, registry locations and checksums, not an
aggregate license determination. Later distribution of compiled binaries,
vendored dependencies or copied tool sources needs a notice/source review for
those actual contents. The current matched development package builder inventories both locked
resolved dependency graphs, copies registry notices and requires an actual
[accompanying-source payload](../packaging/SOURCE-README.md) alongside its binary
packages. This contains exact product/Cargo sources, two pinned official Rust
library source components, the bounded host standard-library crate superset and
original runtime notices. The source manifest binds every payload hash to the
current product revision/tree and six shipped artifact hashes. Upstream URLs
are provenance in addition to the actual source payloads.

The [restoration index](../packaging/notices/restored.json) preserves missing Aya
registry notices from each published crate's exact upstream VCS revision,
including both upstream texts and the selected MIT option. Runtime
compiler_builtins terms remain conjunctive, including the complete LLVM
exception and per-file notices; they are not flattened to a blanket MIT option.
The source recipe explains the ordinary compiler/linker/system-runtime boundary
and exact pinned prerequisites. Artifact construction is separate from final
conveyance-rights review, reproducibility, installed runtime qualification and
public release authorization.
