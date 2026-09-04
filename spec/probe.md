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
  `EAFNOSUPPORT` for an unimplemented family). Receiving `EPERM` where the
  oracle guaranteed something else proves interception before execution.
- **Capability requirement** — the operation's documented capability, for
  correlation against the effective and bounding sets
- **Side effects** — what the probe creates, and how it is reclaimed.
  Descriptor-shaped effects are reclaimed by child exit; anything that outlives
  a process must declare its rollback
- **Risk class** — whether the probe requires fork isolation, and its timeout
- **Architecture applicability** — probes that do not exist on all targets
  (the 32-bit ABI path has no arm64 equivalent) must say so, or the diff
  engine will report architecture as policy

## Open questions

- Declarative data file, or Rust definitions compiled in?
- How is a probe that hangs distinguished from one that is slow?
- Does the committed/deferred split live in this file or in the corpus index?
