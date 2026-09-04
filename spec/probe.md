# Probe specification format

> Stub. To be agreed in week 2 and frozen.

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

## Open questions

- Declarative data file, or Rust definitions compiled in?
- How is a probe that hangs distinguished from one that is slow?
- Does the committed/deferred split live in this file or in the corpus index?
