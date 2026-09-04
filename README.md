# CALIPER

Empirical measurement of container confinement.

A container's security posture is declared in a manifest and enforced by the
kernel. These are not the same thing. What a container can actually reach
depends on the runtime and its version, the node's kernel and loaded modules,
the processor architecture, and the active security module — none of which the
manifest records. Two clusters running an identical manifest can expose
materially different attack surface, and nothing in a deployment pipeline
reports the difference.

CALIPER runs as an ordinary container, probes kernel entry points at argument
granularity, records what the kernel actually permits, and reports how that
differs across environments and what minimal policy change closes the gap.

**Status:** pre-implementation. The proposal is in `docs/`.

## Why this exists

CVE-2026-31431 ("Copy Fail", CISA KEV, May 2026) is reached through the AF_ALG
address family. The `RuntimeDefault` seccomp profile denies it on neither
containerd nor Moby, and Pod Security Standards at the Restricted level does
not address it. Workloads that passed every conventional hardening check were
exploitable, and establishing that fact required hand-built test images.

Existing tooling does not close this gap. Configuration scanners report what
was declared. Runtime monitors report what a workload did, a subset of what it
could have done. Profile generators report what an application needs, not what
its environment permits. None measures enforced confinement.

## Layout

| Path | Contents | Owner |
|------|----------|-------|
| `spec/` | Fixed interfaces: probe specification and fingerprint format | agreed by all, frozen week 2 |
| `engine/` | Probe engine — Rust. Fork isolation, verdict classification, safety | A |
| `corpus/` | Probe definitions, argument-granular, with attribution metadata | A + B |
| `posture/` | Reference posture — tier assertions with citations | B |
| `control/` | Fingerprint, diff, classifier, evaluator, reporting — Go | C |
| `docs/` | Proposal and design notes | — |

Delivery, the environment harness, remediation and integration are owned by D
and land across `control/` and repository tooling.

## The interface

`spec/` is the contract the four workstreams develop against. The probe
engine and corpus produce a fingerprint; the diff engine, evaluator and
remediator consume one. Everything else can proceed in parallel once these are
frozen — which is why they are frozen in week 2 and treated as fixed
thereafter.

## Scope

CALIPER measures and reports. It does not enforce, and it is not a substitute
for the mechanisms whose effect it measures.

Probes establish that a kernel entry point is **reachable** and stop there. The
corpus contains no exploit code and no operation whose success confers
privilege. Where an enumeration interface can answer the question without
executing anything, it is preferred — `IORING_REGISTER_PROBE` over submitting
queue entries, for example.

Intended for infrastructure you own or have written authorisation to test.
