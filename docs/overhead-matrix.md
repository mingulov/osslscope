# Overhead and support matrix

Overhead claims match the worst passing cell, never the best case.
All numbers below are medians over repeated runs against fixture
providers on real (VM or bare-metal) kernels.

## Budgets

Two absolute budgets, both must hold:

- At most 4.0 us median added latency per intercepted call.
- At most 2.0x wall-clock at realistic rates (paced to 100k ops/s).

<!-- source: absolute budgets (G4 restatement): PRD.md section 8,
     wallclock-record.md sections 1-2 -->
Absolute means absolute: the per-call baseline is reported
alongside, never folded into the budget. (The uprobe trap floor of
about 0.5 us exceeds typical sub-microsecond baselines, so a
relative budget would be unachievable by construction.)

## Worst-cell numbers

<!-- source: per-platform rows: p5-gate-record.md (recomputed from
     committed logs); platform detail: wallclock-record.md,
     perf-rhel10 note, alpine/arch/fedora44/tw lane notes -->

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

Overhead is GREEN on 7 of 8 platforms; the worst passing absolute
cell is the Alpine 504-entry attach shape at 3.14 us, inside the
4.0 us budget. Wall-clock is GREEN on 7 of 8 in both cells. (The
Tumbleweed paced ratio below 1.0 is pacer slack noise, a pass
under the 2.0x budget, not a speedup claim.)

The single outlier -- Ubuntu 24.04 on kernel 6.9 observing
CET-built (`endbr64`) targets under nested virtualization -- is
report-only and fully root-caused: that guest kernel cannot
emulate `endbr`, so it single-steps every uprobe hit at two nested
exits per hit (about 5 us each). The BPF probe body itself is
isolated at about 0.3-0.5 us per hit on every platform, so no
product change can move the outlier: the trap path belongs to the
guest kernel. Correctness gates (including exactness) stay green
there; only overhead is documented-slow, not broken.
<!-- source: root-cause chain (single-step + nested exits, BPF body
     isolated): wallclock-record.md section 3 -->

Practical guidance: pin overhead-sensitive gates to 6.12+
runners. `doctor` carries no overhead probe in v1 (trap cost is
not cheaply probed); this matrix plus the CI recipes carry the
guidance instead.

## Support matrix

Qualified for v1 observation (all correctness gates green,
attach 26/26 or via canary/capture/fence cells, builtin parity
100%, wallclock as above):

| Platform | Kernel | OpenSSL | Notes |
|---|---|---|---|
| Debian 13 | 6.12-LTS | 3.0 | reference 6.12 lane |
| Ubuntu host | 7.x | 4.0 | FIPS-provider cell runs here |
| Ubuntu 24.04 | 6.9 HWE | 3.5 | correctness green; overhead report-only |
| AlmaLinux 10.2 | 6.12 (RHEL 10) | 3.5 | SELinux Enforcing cell green |
| Fedora 44 | 6.19 | 3.5 | rpm-family lane |
| Arch rolling | 7.2 | 3.6 | first 3.6 signal |
| openSUSE Tumbleweed | 7.2 | 3.5 | rolling newest-kernel lane |
| Alpine 3.24 (musl) | 6.18-lts | 4.0 | musl lane; musl fence shape asserted |

<!-- source: gate verdicts per platform (all PASS except 6.9
     overhead/wallclock report-only): p5-gate-record.md -->

Standing claims across the matrix:

- Attach SLO: file-caps least-priv attach (`CAP_BPF` +
  `CAP_PERFMON`) green in 40 of 40 cells (5 per platform).
  <!-- source: 40/40 filecaps GREEN: p5-gate-record.md -->
- Exactness: keyed counts match known-N drivers with zero delta
  (12/12 cells per platform), including the single-hot-key
  100k/s cell.
  <!-- source: exact 12/12 delta=0: p5-gate-record.md -->
- Harvest scale: per-operation dispatch walks paginate to 512
  algorithms with userspace/loader lockstep (third-party
  re-proof clean at the raised bound).
  <!-- source: MAX_ALGS 512 raise + oqsprovider re-proof:
       p5-gate-record.md, oqs-spike note -->
- Third-party providers: oqsprovider harvest attributed 100%
  both unstripped and stripped (4876/4876 rows file-backed),
  COMPLETE, stripped-vs-unstripped row multisets identical --
  against a bar of 95% stripped.
  <!-- source: oqsprovider 0.11.0 + liboqs 0.15.0 re-proof:
       oqs-spike note, p5-gate-record.md -->
- No-secret guarantee: the canary suite (29 sentinels through
  digest/sign/cipher/MAC/KEM/KDF/RAND/password/salt paths,
  hostile names, overlong arrays, live-map scan) reports zero
  secret bytes in any artifact on every platform.
  <!-- source: canary 8/8 green, scanned=120 fails=0 (147 incl
       FIPS on the FIPS host): p5-gate-record.md -->
- SELinux Enforcing/targeted: green. 6.18-LTS watch kernel:
  green. SecureBoot: RED -- host-blocked, deferred post-v1, no
  v1 claim (see [what it proves](what-it-proves.md)).
  <!-- source: SELinux/6.18/SecureBoot cells:
       p5-exit1-cells note, p5-gate-record.md -->

Not qualified (see [who should NOT adopt](what-it-proves.md)):
pre-6.9 kernels and distros (EL9, Ubuntu 22.04, Ubuntu 24.04 GA,
Debian 12), non-x86-64 targets, stripped static binaries,
always-on production attach, and CI gating on COMPLETE status.
