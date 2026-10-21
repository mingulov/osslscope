<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Live-run seal checklist (R21/R21b I4)

Every live qualification run MUST retain (sealed evidence dir):

1. Host archive sha256 + guest pre/post-transfer `sha256` executions
   (full command output, not just the digest).
2. Guest extract reconciliation output (file count + symlink lines).
3. The build manifest CONTENT (not just its path).
4. Single-build transcript with exit status + artifact hashes.
5. Post-diagnostic `sha256sum -c` FULL output + the diagnostic patch
   + the hardlink-breaking procedure (or: no post-seal diagnosis —
   state it).
6. Final artifact receipt (hashes re-verified at shutdown).

Historical note (unrecoverable, guests down — NEVER re-fabricated):
R21 kept expected values but no `sha256sum -c` execution (BOUNDED);
R21b kept host verification but no guest hash/manifest executions
(BOUNDED). Both stand as provenance gaps, not corruption evidence.
