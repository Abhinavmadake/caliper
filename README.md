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
address family. When the published testing ran, the `RuntimeDefault` seccomp
profile denied it on neither containerd nor Moby, and Pod Security Standards at
the Restricted level did not address it. Workloads that passed every
conventional hardening check were exploitable, and establishing that fact
required hand-built test images. Moby has since added a deny in 29.4.2 — and
whether a given node enforces it is a property of the runtime version, not of
anything the manifest records, which is the point.

Existing tooling does not close this gap. Configuration scanners report what
was declared. Runtime monitors report what a workload did, a subset of what it
could have done. Profile generators report what an application needs, not what
its environment permits. None measures enforced confinement.

## Layout

| Path | Contents | Owner |
|------|----------|-------|
| `spec/` | Fixed interfaces: probe specification and fingerprint format | agreed by all in week 2, frozen week 9 |
| `engine/` | Probe engine — Rust. Fork isolation, verdict classification, safety, attribution engine | A |
| `corpus/` | Probe definitions, argument-granular, with attribution metadata | A + B |
| `posture/` | Reference posture — tier assertions with citations | B |
| `control/` | Fingerprint, diff, classifier, evaluator, remediator, reporting — Go | C, remediation from D |
| `deploy/` | Kubernetes Job and DaemonSet manifests, environment-matrix bring-up, CI | D |
| `scripts/` | Repository tooling (backlog seeding) | — |
| `docs/` | Proposal and design notes | — |

D also acts as integrator, responsible for the components composing correctly.

| Member | GitHub | Workstream |
|--------|--------|------------|
| A | `Abhinavmadake` | Probe engine, safety, attribution engine, half the corpus |
| B | `sahilwaje23` | Corpus, oracle discipline, reference posture |
| C | `Yogesh-Palve` | Fingerprint, diff, evaluation, reporting |
| D | `Ritesh-Saindane` | Delivery, environment harness, remediation, integration |

Work is tracked as GitHub issues, one milestone per freeze gate; the workstream
letter is in every issue title.

## The interface

`spec/` is the contract the four workstreams develop against. The probe
engine and corpus produce a fingerprint; the diff engine, evaluator and
remediator consume one. Everything else can proceed in parallel once a first
version is agreed — which happens in week 2. The fingerprint format is frozen
at the end of week 9; after that a change is a new format version.

## Scope

CALIPER measures and reports. It does not enforce, and it is not a substitute
for the mechanisms whose effect it measures.

Probes establish that a kernel entry point is **reachable** and stop there. The
corpus contains no exploit code and no operation whose success confers
privilege. Where an enumeration interface can answer the question without
executing the probed operation, it is preferred — `IORING_REGISTER_PROBE` over
submitting queue entries, for example.

One side effect cannot be rolled back and is declared instead: probing an
unregistered socket family, netlink protocol or AF_ALG algorithm type asks the
kernel to autoload the module for it. The engine records the loaded module set
before and after a run and reports the difference.

Intended for infrastructure you own or have written authorisation to test.

## Licence

Apache License 2.0 — see [`LICENSE`](LICENSE).

Copyright 2026 The CALIPER Authors.

All four members agreed to this licence before their first commit.

Apache-2.0 rather than MIT for two reasons that matter to this project. It
carries an express patent grant, which is what an operator's legal review looks
for before running an instrument like this against their own nodes; and it is
the licence of the ecosystem CALIPER measures and integrates with — Kubernetes,
containerd, runc, gVisor, Kata and the Security Profiles Operator whose custom
resources the remediator emits are all Apache-2.0.
