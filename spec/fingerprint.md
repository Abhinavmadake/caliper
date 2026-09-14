# Confinement fingerprint

> **Fixed for week 2 purposes** at the gate on 2026-09-11 (issue #2). The final
> freeze is the end of week 9 (issue #28), after which a change is a new format
> version (§5). Until then this is the version the four workstreams develop
> against, and a change is cheap by design.
>
> §8 makes this a decision of all four members; the team delegated it to A, who
> took it. Recorded because the authority matters to anyone reading a later
> change.
>
> The three questions this file left open are resolved below, against the
> proposal.

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

Three fields identify the fingerprint itself rather than the cell:

- `format_version` — integer. Incremented only by a breaking change to this
  format, per §5. Frozen from the end of week 9
- `corpus_revision` — which corpus produced the run. Distinct from
  `format_version`: the format can be stable across many corpus revisions
- `digest` — a SHA-256 over the canonical serialisation, for identity and
  deduplication. It is **not** authenticity; see the decision below

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

## Decisions

### A consumer diffs the intersection; corpus skew is reported, never classified

Two fingerprints from different corpus revisions are compared over the probe
ids present in **both**. A probe present in only one is reported in a separate
`corpus-skew` section and is never assigned a divergence class.

This follows the rule the whole format is built on. §5 fixes the environment
cell as first-class "because a divergence between an arm64 and an amd64
measurement is not a policy finding and must not be reported as one"; a probe
that exists in one corpus and not the other is the same error one level up —
instrument drift reported as a property of the node. `not-applicable` must not
be reused for it either: that verdict means the entry point is absent on this
cell, which is a fact about the kernel, whereas an absent probe is a fact about
the instrument.

Corpus skew stays outside the four divergence classes deliberately. §5 and
objective 4 fix those four as the classifier's output, and a fifth class would
reopen a frozen enumeration to describe something that is not a divergence.

A `format_version` a consumer does not know is refused outright rather than
read on a best-effort basis. The same discipline applies: guessing at a format
would put an inference where the system promises a measurement.

### No signature. A content hash, and it is not authenticity

The proposal does not require fingerprints to be signed, and nothing in it
carries a threat model in which a forged fingerprint is the attack. What §12
requires signing for is the **probe image**, so operators can allowlist a known
instrument (#40) — a different artefact answering a different question. Signing
fingerprints would import key distribution and rotation into a project whose
stated scope is to measure and report (§14).

The `digest` field is retained because it is nearly free and reproducibility is
a stated concern — §12 mitigates the posture's subjectivity by "versioning it so
that findings are reproducible against a stated posture revision", and a run
needs the same handle. It answers "are these two runs the same run", not "did
this come from someone I trust". Documented as such so the distinction is not
quietly lost.

### JSON, additive-only within a format version

serde on the Rust side, `encoding/json` on the Go side — §10 names serde for
fingerprint serialisation, and §5 puts a Go control plane on the other end.
JSON is where those meet, it is what the reporting layer emits anyway (#35),
and it is readable in a CI log without tooling.

Stability, within one `format_version`:

- fields may be **added**, and must be optional
- no field is removed, renamed or retyped
- no enum variant is removed — verdicts and divergence classes only grow
- unknown fields are ignored by consumers, never an error, so a newer engine's
  output stays readable by an older control plane

Anything else increments `format_version`. The canonical form for the digest is
JSON with object keys sorted and insignificant whitespace removed.

The stability rule is what lets §5's parallelism actually hold — "the reporting
layers to be developed against recorded fingerprints long before the corpus is
complete" only works if a fixture recorded in week 3 still parses in week 12.

## Serialisation conventions

Normative, so that two people writing a fingerprint by hand produce the same
bytes. These are the conventions; the field *names and nesting* are C's to
settle in #25.

- **Object keys are `snake_case`** — `format_version`, `corpus_revision`,
  `runtime_version`.
- **Enumerated values are `kebab-case`** — the verdicts serialise as
  `"permitted"`, `"denied"`, `"unimplemented"`, `"killed"`, `"timed-out"`,
  `"not-applicable"`, and the divergence classes as
  `"architecture-explained"`, `"kernel-version-explained"`,
  `"runtime-class-explained"`, `"policy-explained"`. The engine already emits
  the verdicts this way (`#[serde(rename_all = "kebab-case")]` in
  `engine/crates/engine/src/verdict.rs`); the two halves must agree.
- Keys are snake_case even where the value is kebab-case. The split is not
  cosmetic: keys are field identifiers, values are members of a fixed
  enumeration named in this document and in the proposal.
- **`errno` is the raw integer**, never a name. `0` where the verdict has no
  errno because the child did not return (`killed`, `timed-out`) or because
  the call succeeded (`permitted`). A `permitted` from a probe whose errno
  oracle guarantees an error carries that errno, raw: the call reached the
  point where the kernel produces it, which is what the oracle was built to
  show, and the answer is recorded as given (`spec/probe.md`, errno oracle).
  A name is a presentation concern.
- **Every control-plane field records its source**, per §5 — the field is an
  object carrying the value and where it came from, not a bare value, because
  "containerd 2.2 from the Node object" and "containerd 2.2 because the
  operator said so" are different evidence.
- **Booleans are stated, not implied by absence.** A missing key means a
  producer that did not know; `false` means it knew and the answer was no.
- Canonical form, for the `digest`: object keys sorted, no insignificant
  whitespace.

`examples/fingerprint.json` is a worked example against these conventions. It
is **illustrative, not normative** — the shape of the object is #25's to
decide, and the example is there so that #3's fixtures and C's first parser
start from the same picture rather than two different guesses.
