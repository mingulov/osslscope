<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Component licensing and BPF boundary

The host application, host-only `osslscope-ebpf-common`, documentation, and
build scripts carry GPL-3.0-or-later terms; the root [LICENSE](../LICENSE)
contains that license. The three BPF program sources in `crates/ebpf` carry
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
