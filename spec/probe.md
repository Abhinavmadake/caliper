# Probe specification format

> **Frozen** at the week 2 gate, 2026-09-11 (issue #1). A change from here needs
> team agreement.
>
> §8 makes this freeze a decision of all four members; the team delegated it to
> A, who took it. Recorded because the authority matters to anyone reading a
> later change: these are A's decisions under a delegation, not four members'
> consensus, and reopening one costs correspondingly less.
>
> The three questions this file left open are resolved below, each decided
> against the proposal rather than by preference.

A probe attempts one kernel operation at argument granularity and records what
the kernel returned. Every probe is authored complete with its attribution
metadata — the proposal is explicit that this is not deferred to a later phase.

## Fields to define

- **Identity** — stable id, entry family, human description
- **Operation** — the syscall and the exact arguments under test
- **Errno oracle** — the argument set chosen so that, if the call reaches the
  kernel at all, a specific error is structurally guaranteed (`EBADF` on a
  deliberately invalid descriptor, `EINVAL` on a malformed request,
  `EAFNOSUPPORT` for a family outside the kernel's range). Receiving `EPERM`
  where the oracle guaranteed something else proves interception before the
  point at which the kernel would have produced that error. What that isolates
  is per syscall and is recorded with the oracle: descriptor resolution precedes
  every LSM hook, so an `EBADF` oracle isolates seccomp; the `socket(2)` hook
  runs before the family lookup, so an `EAFNOSUPPORT` oracle on an in-range
  family does not separate seccomp from AppArmor or SELinux. `ENOSYS` from a
  syscall the cell's kernel implements is a filter, not `unimplemented`.
- **Capability requirement** — the operation's documented capability, for
  correlation against the effective and bounding sets
- **Side effects** — what the probe creates, and how it is reclaimed.
  Descriptor-shaped effects are reclaimed by child exit; anything that outlives
  a process must declare its rollback. A probe that can make the kernel
  autoload a module (unregistered socket family, netlink protocol, AF_ALG
  algorithm type) declares that too: it is neither reclaimable nor rolled back,
  and the engine reports it from a before/after snapshot of loaded modules
- **Risk class** — whether the probe requires fork isolation, and its timeout
- **Kernel dependency** — the kernel version, configuration option or module
  the entry point needs, so the diff engine can exclude kernel-version-explained
  divergence probe by probe instead of inferring it from the version string
- **Architecture applicability** — probes whose entry point exists only on
  some architectures must say so, or the diff engine will report architecture
  as policy. Where presence is a kernel property rather than an architecture
  property — the 32-bit compatibility ABI is built into some arm64 kernels and
  not others — it is detected at run time and recorded, not declared

## Decisions

### Probes are Rust definitions compiled into the engine

Not a declarative data file read at run time.

Three things in the proposal decide this together. The engine "must not issue
syscalls of its own that pollute the measurement" (§5, §6.2) — opening and
reading a corpus file is exactly such a syscall, and it happens before the
module snapshot that the environment cell depends on. The probe image is a
static musl binary with no runtime dependencies, so a data file alongside it is
a second artefact that can drift from the binary that interprets it. And §5
fixes where the two halves of the system meet: "the two halves meet at the
fingerprint format and nowhere else" — a declarative corpus would be a second
interface across that boundary, with its own parser, its own version skew and
its own failure mode inside a container.

The cost is that B authors probes in Rust rather than in data. That cost is
accepted: the errno oracle is a per-syscall argument about where the kernel
produces which error, which is reasoning about code, and §8 already pairs every
oracle B designs with review against the family A implements.

To keep a data view without a second input path, the engine emits the corpus as
JSON on demand (`--dump-corpus`). It is an output, never an input. The corpus
index, the freeze-gate completeness check (#18) and the control plane all read
that, so nothing downstream needs to parse Rust.

### A probe that exceeds its timeout is recorded `timed-out`; hung and slow are not distinguished

The proposal does not ask for the distinction. It asks that a hang be recorded
"rather than stalling the run" (§6.2), and `timed-out` is a verdict in the
fingerprint's own enumeration, not an error.

The distinction is not made because it cannot be made soundly from outside the
child: a probe blocked forever and a probe that would have returned just after
the deadline are the same observation. Pretending otherwise would put a guess
in the measurement, which is the failure this instrument exists to avoid.

The mechanism is the fork isolation that is already there for SIGSYS (§6.2):
the parent waits on the child with the deadline from the probe's risk class,
sends `SIGKILL` on expiry, reaps it, and records `timed-out`. The deadline is a
declared field, so it travels in the fingerprint — a `timed-out` verdict is
readable against the timeout that produced it, and a timeout that was simply
too tight is visible as such rather than hidden in the engine.

### The committed/deferred split lives in the corpus index, not here

This file defines what a probe *is*. Membership of a set is a property of the
corpus, not of any probe's specification, and no field here changes when a
probe moves between sets.

That is what makes the deferred set "additive work rather than redesign"
(§9.2, objective 2): promoting a probe from deferred to committed is an index
entry plus an implementation, never a respecification. Were the split a field
in this file, every promotion would edit a frozen format.

A deferred probe is therefore a complete, valid probe definition that the index
marks as unimplemented (#20), and the index is the artefact frozen at the end
of week 8 (#19).

### Rollback is the child's, not a hook

The side-effects field says a probe "must declare its rollback". That is a
declaration — the class of object the probe may leave behind — not a rollback
function the engine calls. The child removes what it created before it
returns; the engine measures whether it did.

The proposal puts the rollback in the isolation, not in a callback: "fork
isolation is the rollback for most of the corpus" (§6.2), and the side-effect
declaration requirement is a §12 mitigation the engine enforces "rather than
leaving to convention". A hook would be a second code path, and it cannot be
made to run soundly from the parent. The parent runs under a different view of
the filters than the child — its calls were made before any probe's, and a
filter that permits `shmget` and denies `shmctl(IPC_RMID)` is a finding, not a
fault — so a parent-side rollback would succeed in exactly the ways the probe
could not, and hide the asymmetry the corpus exists to measure. It also cannot
be ordered correctly: a rollback that ran before the residual snapshot would
erase the residual, and one that ran after is hygiene the finding has already
done.

Residual state is therefore measured after the child is reaped and before
anything is removed. A probe that cannot remove what it created — killed
first, or create permitted and remove blocked — leaves an object that is
counted, attributed to the probe, and checked against its declaration. The
structural fallback is an end-of-run janitor: after the run's final snapshot it
removes what is recognisably the instrument's (POSIX objects under a reserved
name prefix, System V objects in a reserved key range), each removal in its own
forked child under the same filters the probe had, and every attempt is
recorded on the fingerprint whether it succeeded or not. It runs once, it is
not on any probe's path, and its output is a finding about the corpus, never a
silent fix. Per-probe namespaces were considered and are not available: a
fresh namespace needs `CAP_SYS_ADMIN` or a user namespace, RuntimeDefault
denies both, and a user namespace would change what the kernel permits — the
workload's room is the only room the engine gets (§5).

What this rules out is a probe that leaves a `caliper-` object behind by
design and relies on the janitor. The child owns its objects; the janitor is
for the case where the kernel would not let it.
