# Confinement fingerprint

> Stub. To be agreed in week 2, frozen end of week 9.

A fingerprint is one measurement run. It is the unit the diff engine,
evaluator and remediator all consume.

## Identity

The fingerprint's identity is the **environment cell**, not the workload. These
are first-class fields, because a divergence between an arm64 and an amd64
measurement is not a policy finding and must not be reported as one:

- processor architecture *(probe)*
- kernel version *(probe; a sandbox's synthetic version is recorded as its
  claim)*, distribution *(control plane)*, and relevant loaded modules *(probe;
  captured before any probe runs, so it describes the node and not the
  instrument's own footprint)*
- container runtime and runtime version *(control plane, from the Node object
  or the operator — not observable from inside an unprivileged container)*
- active LSM (AppArmor / SELinux / none) *(probe, from its own label)*
- RuntimeClass (runc / gVisor / Kata) *(control plane, from the pod spec)*

Every control-plane field records its source. The probe emits a raw
measurement; the control plane completes it into a fingerprint and computes the
attribution — the engine stores no interpretation.

## Per-probe result

Each probe records the verdict, not an interpretation of it:

- `permitted` / `denied` / `unimplemented` / `killed` (terminated by SIGSYS) /
  `timed-out` (exceeded its risk-class timeout, proposal §6.2) /
  `not-applicable` (entry point absent on this architecture or kernel, per the
  probe's applicability and kernel-dependency fields)
- the raw errno
- attribution: which mechanism produced the denial, with a confidence level
- whether attribution was undecidable from inside the container

## Divergence classes

The diff engine assigns every divergence between two fingerprints exactly one
class (proposal §5):

- `architecture-explained` — from the probe's declared or detected applicability
- `kernel-version-explained` — kernel build, configuration or loaded modules
- `runtime-class-explained` — the cells differ in RuntimeClass and the sandboxed
  side reports `unimplemented`; never counted as policy
- `policy-explained` — everything else, including LSM and runtime-version
  differences, which are differences in the policy the kernel actually enforces

## Open questions

- Versioning: how does a consumer handle a fingerprint from an older corpus?
- Integrity protection: the proposal does not require fingerprints to be
  signed. Decide whether a signature or content hash is worth carrying, or drop
  the question.
- Serialisation format and stability guarantees across corpus revisions.
