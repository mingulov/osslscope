<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Overhead and support matrix

The tables below preserve historical fixture-era results, separate
from current integrated v2 qualification. They are source/kernel/
workload-specific medians from repeated fixture-provider runs on
VM or bare-metal kernels, not standing support or performance
certification for the current tree. Historical `v0.1.0` release
credit remains on its recorded terms; current live, overhead,
COMPLETE-window and exact-package acceptance remains open.
An enrollment-only profile is listed separately from performance.

## Budgets

Two absolute budgets, both must hold:

- At most 4.0 us median added latency per intercepted call.
- At most 2.0x wall-clock at realistic rates (paced to 100k ops/s).

Absolute means absolute: the per-call baseline is reported
alongside, never folded into the budget. In the historical setup,
the uprobe trap cost of about 0.5 us already exceeded typical
sub-microsecond callback baselines; relative ratios alone did not
describe the added latency usefully.

## Worst-cell numbers

Historical performance results, not a new measurement:

| Platform | Kernel | OpenSSL | Overhead added/call | Wall small / paced | Verdict |
|---|---|---|---|---|---|
| Debian 13 | 6.12 | 3.0 | 0.6 us | 0.81 us / 0.99x | PASS |
| Ubuntu host | 7.0 | 4.0 | about 2.1 us | 2.82 us / 1.05x | PASS |
| Ubuntu 24.04 | 6.9 HWE | 3.5 | about 13-15 us | 14.77 us / 4.33x | REPORT-ONLY (see below) |
| AlmaLinux 10.2 | 6.12 | 3.5 | 0.6-1.8 us | 1.18 us / 1.02x | PASS |
| Fedora 44 | 6.19 | 3.5 | 0.8-1.3 us | 1.12 us / 1.19x | PASS |
| Arch rolling | 7.2 | 3.6 | 0.8-1.4 us | 1.44 us / 0.90x | PASS |
| openSUSE Tumbleweed | 7.2 | 3.5 | 0.8-0.9 us | 3.37 us / 0.54x | PASS |
| Alpine 3.24 (musl) | 6.18-lts | 4.0 | 0.8-3.1 us | 1.08 us / 1.02x | PASS |

Historical enrollment-only profile (excluded from the performance
denominator): Debian 13, kernel `6.12.107+deb13-cloud-amd64`, OpenSSL
3.5.9 source build under `/opt`, enrolled as table entry 11. That
profile recorded passing profile legs but no overhead measurement;
its stripped system libcrypto remained unenrolled/anchor-unresolved.
Neither table presence nor those profile legs qualify current
integrated performance (`tests/build_id_table.rs`).

In the historical eight-platform fixture set, overhead passed on
7 of 8 platforms; the worst passing absolute
cell is the Alpine 504-entry attach shape at 3.14 us, inside the
4.0 us budget. Wall-clock passed on 7 of 8 in both cells. (The
Tumbleweed paced ratio below 1.0 is pacer slack noise, a pass
under the 2.0x budget, not a speedup claim.)

The single outlier -- Ubuntu 24.04 on kernel 6.9 observing
CET-built (`endbr64`) targets under nested virtualization -- is
report-only in that measured setup: its recorded cause was that
the guest kernel could not emulate `endbr`, so it single-stepped
every uprobe hit at two nested
exits per hit (about 5 us each). The BPF probe body itself is
isolated at about 0.3-0.5 us per hit in those runs. Historical
correctness gates, including keyed exactness, passed there; that
does not prove current correctness or establish a new kernel-floor
exclusion. Re-measure the exact current target/kernel/observer.

Practical guidance: pin overhead-sensitive gates to 6.12+
runners as a starting point, then measure both budgets. `doctor`
has no overhead qualification probe; a functional admission pass
does not establish latency, rate or wall-clock acceptance.

## Support matrix

Historical observation matrix (fixture-era correctness/attach,
canary/capture/fence and builtin-parity results, with wall-clock
as above). It includes a real 6.9 lane, so 6.12 is not the oldest
historically exercised kernel. No row grants current matrix-wide
qualification:

| Platform | Kernel | OpenSSL | Notes |
|---|---|---|---|
| Debian 13 | 6.12 | 3.0 | reference 6.12 lane |
| Ubuntu host | 7.0 | 4.0 | FIPS-provider cell runs here |
| Ubuntu 24.04 | 6.9 HWE | 3.5 | correctness green; overhead report-only |
| AlmaLinux 10.2 | 6.12 | 3.5 | SELinux Enforcing cell green |
| Fedora 44 | 6.19 | 3.5 | rpm-family lane |
| Arch rolling | 7.2 | 3.6 | first 3.6 signal |
| openSUSE Tumbleweed | 7.2 | 3.5 | rolling newest-kernel lane |
| Alpine 3.24 (musl) | 6.18-lts | 4.0 | musl lane; musl fence shape asserted |

Recorded historical fixture checks across that matrix:

- Attach SLO: file-caps least-priv attach (`CAP_BPF` +
  `CAP_PERFMON`) green in 40 of 40 cells (5 per platform).
- Exactness: keyed counts match known-N drivers with zero delta
  (12/12 cells per platform), including the single-hot-key
  100k/s cell.
- Harvest scale: per-operation dispatch walks paginate to 512
  algorithms with userspace/loader lockstep (third-party
  re-proof clean at the raised bound).
- Third-party providers: oqsprovider harvest attributed 100%
  both unstripped and stripped (4876/4876 rows file-backed),
  COMPLETE, stripped-vs-unstripped row multisets identical --
  against a bar of 95% stripped.
  The historical third-party setup used oqsprovider 0.11.0 and
  liboqs 0.15.0; harvest parity is not a current count-window proof.
- No-secret guarantee: the canary suite (29 sentinels through
  digest/sign/cipher/MAC/KEM/KDF/RAND/password/salt paths,
  hostile names, overlong arrays, live-map scan) reports zero
  secret bytes in any artifact on every platform.
- SELinux Enforcing/targeted and the 6.18-LTS watch kernel passed
  their historical cells. Secure Boot qualification was host-blocked
  and remains unclaimed; no current enabled-state success follows
  from these tables. AlmaLinux is not an actual RHEL 10 receipt.

Current qualification must use the exact integrated artifacts and
actual required platforms, including actual RHEL 10 and enabled
Secure Boot/lockdown/enforcing SELinux states with the required
controls preserved. A disabled-state control or approved alternative
environment does not qualify an enabled state. Ordinary failed and
PARTIAL windows remain in completeness denominators; exclude only
predeclared expected-PARTIAL negatives. See
[the promotion checklist](promotion-checklist.md).

Current unsupported shapes include pre-6.9 kernels and non-x86-64
targets. Unknown stripped builds need explicit admission, not
guessed offsets. Always-on service operation is forthcoming and
current COMPLETE-window gating is unqualified; see
[who should NOT adopt](what-it-proves.md).
