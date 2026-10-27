<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Provider observation

`scan` and `inspect` can observe OpenSSL public provider APIs in addition to
passive file-backed inventory:

```sh
osslscope scan --pid 1234 --observe-providers --watch --duration 10 --json
osslscope inspect --pid 1234 --observe-providers
osslscope doctor --discovery --json
```

Observation lasts 30 seconds by default and always has a finite duration.
`scan --watch` accepts `--duration` in `(0,3600]` seconds and `--interval` in
`[0.05,3600]` seconds (default 1 second). PID, cgroup and module selectors have
the same intersection meaning as passive `scan`. `inspect` requires one PID.
Without `--observe-providers`, existing passive discovery commands retain their
behavior and need no BPF capability.

Tracing records public API attempts/results, provider initialization results,
query results and bounded advertisement samples. Advertisements describe
interfaces that were returned; they do not establish execution, policy
compliance or complete provider coverage. Activation before attachment stays
unknown, including a default provider that was already active. Opaque context
associations can be unknown or candidates. A provider display name need not be
recognized to observe its interfaces; unknown names become `other` before
transport. Enumeration is sampled, and a repeated sample is not a census.

The observer does not trigger target APIs or send target signals. It uses no
private OpenSSL layout, memory-reader fallback, manual offsets, build catalogue,
provider injection or implementation-entry probes. Mapped objects must pass
native backing and retained-descriptor identity checks before attachment.
Inventory remains useful when trace access, relocation or attachment is denied.

JSON output is a stream of `osslscope.discovery.provider.v1` records, one JSON
object per line. Both commands emit an initial `snapshot`, optional subsequent
`snapshot`/`observation` records and a final `end`. Each snapshot embeds the
unchanged safe `osslscope.discovery.v1` inventory. Facts, finite gaps and
capabilities are separate fields. Capture intervals include observer elapsed
start/end times and measured drain lag; facts carry their monotonic timestamps.
The end record includes elapsed time, status and duration/interruption reason.
No CBOM assets or policy verdicts are produced. Human output carries safe
identities, finite facts, capabilities and gaps in readable lines.

The event loop drains cooperatively at a 100 ms cadence while it has control.
Bounded synchronous snapshots and ELF reads can delay draining. Queue loss,
overrun, lag, first-query uncertainty and unobserved intervals remain explicit;
this is not a hard latency guarantee or lossless event history. SIGINT/SIGTERM
to the observer stop observation and produce an interrupted end record when
the output sink remains writable. Output failure stops acquisition and exits 1.

Default trace limits are 64 processes, 256 retained objects, 1,024 links,
4,096 pending calls, nesting depth 8, 4,096 learned physical sites,
16,384 facts per window, a 1 MiB ring, 64 MiB retained trace state and
256 MiB cumulative ELF reads. Passive inventory retains its separate limits.
Facts stream directly from bounded batches; no full event history is retained.
Exhaustion emits finite gaps and preserves available inventory.

The companion has the fixed basename `osslscope-provider-observation`.
`scripts/build-dev.sh --offline --jobs 2` builds it and copies the exact emitted
Cargo artifact beside the actual host executable, including custom Cargo target
directories and target triples. `--host-only` does not build a companion.
An installed executable at `PREFIX/bin/osslscope` also looks in
`PREFIX/lib/osslscope/osslscope-provider-observation`. Resolution never searches
the current directory or environment variables. The executable is pinned and
reopened identity checked; companion and ancestor directories are opened without
following symlinks, and the regular companion is read with a size bound and
stability checks on the same descriptor. Privileged use requires root ownership
and no group/other write bits on the executable, companion and every ancestor.
User-owned worktrees and writable temporary directories consequently do not
supply privileged companions. Installed-package qualification is separate from
a development build.

`doctor --discovery` reports finite inventory, companion and kernel capability
states without consulting a target profile or build admission catalogue.
Feature checks do not qualify a target's attachment, provider behavior or
complete coverage. Target access and attachment remain scope dependent.

Exit codes are 0 for completed inventory and supported observation, 3 for useful
inventory with access/resource/trace gaps or interruption, 4 for no usable
requested inventory/observation, 2 for invalid arguments and 1 for internal or
output failure. Expected unknown historical activation alone does not turn a
completed window into an error. Discovery doctor exits 3 when a required tracing
capability or companion is unavailable.
