<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Lifecycle producer initialization

Report and Check require an explicitly initialized lifecycle runtime. Initialize
it in the initial single-threaded phase, after parsing and complete object-set
admission, before signal installation, target acquisition, setup workers, native
loading, or Count preparation. The CLI follows this order and reuses the admitted
object bytes. Help, version, invalid arguments, and failed object admission do not
start a producer. Doctor and Inspect do not need a producer; their acquisitions
permanently close the opportunity to initialize one later in that process.

`unsafe LifecycleRuntime::bootstrap_early(deadline, workload_fd)` is the only
constructor. The caller must guarantee no earlier protected acquisition or
mapping, competing child waiter, descriptor or namespace mutation, SIGCHLD
auto-reaping, or preloaded protected state. The creating thread must outlive the
runtime. Runtime checks require exactly one thread, default SIGCHLD disposition,
matching parent/child PID and time namespaces, zero monotonic time offset, bounded
mappings, and only actually open standard descriptors plus the optional borrowed
workload descriptor. These checks do not certify arbitrary embedding history.

Validate a raw workload descriptor before borrowing it. Keep its original slot
open and unchanged through target creation; the runtime neither duplicates nor
consumes it. Closed standard slots are supported and remain closed in the
observer. A workload descriptor equal to stdout is closed once in the launcher.
The target closes the observer's two producer descriptors before redirecting
stdio or stopping. Ordinary target creation uses the same guarded path.

An embedding owner can call `runtime.install()` and retain its guard across
multiple Report/Check calls. Legacy `cli`, `report`, `check`, and capture entry
points borrow that installation; they do not create or shut down a runtime.
Capture also provides `run_with_producer`, `run_for_command_with_producer`,
`run_with_dirs_and_producer`, and `run_traversal_with_producer`, with the existing
arguments followed by `&ProducerHandle`. An already installed matching handle is
borrowed without unregistering its owner. Installation never creates a producer.
The initialization requirement is a compatibility change even where the old
function signatures remain unchanged. `LiveLifecycle::Kernel` now contains a
boxed kernel adapter.

The launcher is created by raw clone before protected acquisition and has its own
file table and address space. It resets inherited handlers while signals are
blocked, arms parent-death protection before inherited closes, clears
capabilities, checks closures, disables dumping, and enters a syscall filter. It cannot open,
receive descriptors, load BPF, execute programs, or import later observer state.
One supervisor owns its endpoint, pidfd, and exact parent wait. Each serial CPU
lane gets a fresh helper. Only the launcher may reap that helper; a positive exact
wait status is required. There is one launcher, helper, supervisor, and active
burst, with at most four subscriptions. Steady producer references are two in the
observer and one in the launcher; bootstrap uses at most seven temporary table
references, and target creation temporarily copies two. Count and native
allowances are unchanged; observer producer descriptors remain in the measured
non-Count inventory.

Kernel lifecycle subscriptions authenticate the returned netlink peer before
accepting an ACK, stashing bytes, or ingesting events. Payload port IDs are not
origin evidence. Watermarks require the actual helper PID, received CPU, birth
floor, and launcher parent on FORK records, followed by the launcher's positive
reap. Initial and terminal production use the same private-table producer.
Terminal production does not need permission to fork the observer. Sparse online
CPU topology is preserved across the window; offline, lost, migrated, stale, or
unwitnessed lanes remain explicit gaps. Timestamp binding does not change the
public `LifecycleTimingTrust::Unknown` classification.

Dropping an installed guard only unregisters it. Dropping a handle or adapter
releases its reservation; dropping a burst publishes abandonment. Runtime Drop
publishes shutdown but does not wait. An embedding owner must explicitly call
`shutdown(deadline)` or `request_shutdown(deadline).wait()` before exit. The first
shutdown deadline is sticky; it never extends setup, helper, Count, or terminal
budgets. A held lease retains its descriptors. `Complete` requires all helper
receipts, DONE, a positive launcher exit-zero wait, and successful endpoint and
pidfd closure. `Pending` and `Unknown` retain uncertain custody and prohibit
replacement. A deadline or ECHILD is not a reap receipt. Parent-death signals are
an exit fallback, not proof of collection.

The CLI consumes shutdown on normal, error, and caught-unwind returns. Incomplete
producer disposal appends one bounded diagnostic and changes success, partial,
and inconclusive exits to tool failure. Usage, environment, policy-violation,
and existing tool-failure precedence is preserved, together with the observation,
policy document, delivery, target, and Count outcomes.

The `lifecycle_producer_host` test target starts before test threads and exercises
real own-child custody with explicitly scripted event peers. Connector test
wrappers require `OSSL_LIFECYCLE_TEST_DRIVER` to name the exact current executable
reported by Cargo's `compiler-artifact` record for that target. Missing or invalid
initialization fails required connector tests. `OSSLSCOPE_CONNECTOR_TEST=force-absent`
is an explicit HOST fixture and supplies no connector qualification. Required
connector execution must not use that fixture. HOST and source checks do not
qualify actual connector, package, provider, capability, policy, or platform
behavior; those require their respective environment tests.
