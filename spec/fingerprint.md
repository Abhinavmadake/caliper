# Confinement fingerprint

> Stub. To be agreed in week 2, frozen end of week 9.

A fingerprint is one measurement run. It is the unit the diff engine,
evaluator and remediator all consume.

## Identity

The fingerprint's identity is the **environment cell**, not the workload. These
are first-class fields, because a divergence between an arm64 and an amd64
measurement is not a policy finding and must not be reported as one:

- processor architecture
- kernel version, distribution, and relevant loaded modules
- container runtime and runtime version
- active LSM (AppArmor / SELinux / none)
- RuntimeClass (runc / gVisor / Kata)

## Per-probe result

Each probe records the verdict, not an interpretation of it:

- `permitted` / `denied` / `unimplemented` / `killed` (terminated by SIGSYS)
- the raw errno
- attribution: which mechanism produced the denial, with a confidence level
- whether attribution was undecidable from inside the container

## Open questions

- Versioning: how does a consumer handle a fingerprint from an older corpus?
- Are fingerprints signed? The proposal calls them signed; decide the mechanism.
- Serialisation format and stability guarantees across corpus revisions.
