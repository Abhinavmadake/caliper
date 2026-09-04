#!/usr/bin/env bash
#
# Seed the CALIPER backlog: labels, milestones and issues derived from the
# project proposal (docs/proposal.txt).
#
# Every issue's workstream letter follows the work allocation in proposal §8:
#
#   A  probe engine and safety, half the corpus
#   B  corpus, attribution and reference posture
#   C  fingerprint, diff and evaluation
#   D  delivery and evaluation harness, remediation, integration
#
# Issues are created UNASSIGNED. The letter in the title says who owns the work;
# members claim their own with:
#
#   gh issue edit <n> --add-assignee <handle>
#
# Usage:  ./scripts/seed-backlog.sh [--force]
#
# Refuses to run if the repository already has issues, so a re-run cannot
# create fifty duplicates. --force overrides.

set -euo pipefail

REPO="Abhinavmadake/caliper"

# Week 1 begins Monday 2026-09-07. Milestone due dates are the Friday ending
# each gate week of the seventeen-week schedule in proposal §9.1.
M2="W2 — Interfaces frozen"
M3="W3 — Engine + reference corpus"
M8="W8 — Corpus frozen"
M9="W9 — Fingerprint frozen"
M12="W12 — Attribution, evaluator, remediation"
M15="W15 — Evaluation complete"
M16="W16 — Integration buffer"
M17="W17 — Release"

# ---------------------------------------------------------------- guards ----

FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

command -v gh >/dev/null || { echo "gh not found" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh not authenticated" >&2; exit 1; }

existing=$(gh issue list --repo "$REPO" --state all --limit 1 --json number --jq 'length')
if [[ "$existing" != "0" && $FORCE -eq 0 ]]; then
  echo "refusing: $REPO already has issues. Re-run with --force if that is intended." >&2
  exit 1
fi

# --------------------------------------------------------------- helpers ----

mklabel() {
  gh label create "$1" --repo "$REPO" --color "$2" --description "$3" --force >/dev/null
  echo "  label  $1"
}

mkmilestone() {
  local title=$1 due=$2 desc=$3
  if gh api "repos/$REPO/milestones?state=all" --jq '.[].title' | grep -qxF "$title"; then
    echo "  exists $title"
    return
  fi
  gh api "repos/$REPO/milestones" \
    -f title="$title" -f due_on="${due}T23:59:59Z" -f description="$desc" >/dev/null
  echo "  due $due  $title"
}

# mkissue <title> <comma-separated-labels> <milestone>   body on stdin
# Labels may be empty, in which case the flag is omitted entirely.
mkissue() {
  local title=$1 labels=$2 milestone=$3 body
  body=$(cat)
  local args=(--repo "$REPO" --title "$title" --body "$body" --milestone "$milestone")
  [[ -n "$labels" ]] && args+=(--label "$labels")
  gh issue create "${args[@]}" >/dev/null
  echo "  + $title"
}

# ---------------------------------------------------------------- labels ----

echo "Labels"
mklabel "ws:engine"     "1d76db" "Member A — probe engine and safety"
mklabel "ws:corpus"     "0e8a16" "Members A+B — probe corpus and attribution"
mklabel "ws:posture"    "5319e7" "Member B — reference posture"
mklabel "ws:control"    "b60205" "Member C — fingerprint, diff, evaluation"
mklabel "ws:delivery"   "e99695" "Member D — delivery, harness, remediation"
mklabel "spec"          "fbca04" "Fixed interface frozen in week 2"
mklabel "freeze-gate"   "d93f0b" "Deadline after which this artefact is fixed"
mklabel "critical-path" "000000" "A slip here cascades into every later phase"
mklabel "deferred-set"  "cfd3d7" "Entered only if the committed set is complete"
mklabel "evaluation"    "006b75" "Success criterion from proposal §11.2"

# ------------------------------------------------------------ milestones ----

echo "Milestones"
mkmilestone "$M2"  "2026-09-18" "Probe and fingerprint formats agreed and fixed. Every other workstream develops against these rather than against the engine."
mkmilestone "$M3"  "2026-09-25" "Probe engine with fork isolation, SIGSYS survival, timeout handling and verdict classification, plus a ten-probe reference corpus end to end. The critical path."
mkmilestone "$M8"  "2026-10-30" "Committed corpus complete and frozen, every probe carrying its errno oracle. Reference posture drafted with citations."
mkmilestone "$M9"  "2026-11-06" "Fingerprint format frozen. The system is independently defensible from this point: it measures, classifies and diffs confinement across environments."
mkmilestone "$M12" "2026-11-27" "Attribution confidence model, evaluator against manifest and posture, and minimal remediation with closure verification."
mkmilestone "$M15" "2026-12-18" "Environment matrix measured across six cells. Every success criterion in §11.2 reported."
mkmilestone "$M16" "2026-12-25" "Held deliberately empty. A compressed schedule with no slack fails on its first surprise, and the surprises here are kernel-level. No issues belong in this milestone."
mkmilestone "$M17" "2027-01-01" "Final report, demonstration, release."

# ---------------------------------------------------- W2 — interfaces -------

echo "Issues"

mkissue "[ALL] Freeze spec/probe.md — probe specification format" \
        "spec,freeze-gate,critical-path" "$M2" <<'EOF'
**Workstream:** agreed by all four (proposal §5)
**Phase:** Week 2 — the interface freeze

`spec/probe.md` is currently a stub whose headings record the decisions to be made
rather than the answers. Agree the field set and fix it, because the corpus,
attributor and every downstream consumer are authored against this rather than
against the engine.

**Done when**
- [ ] Identity fields defined — stable id, entry family, human description
- [ ] Operation fields defined — the syscall and the exact arguments under test
- [ ] Errno oracle field defined, with the rule that the argument set must make a
      specific error structurally guaranteed if the call reaches the kernel at all
- [ ] Capability requirement field defined, for correlation against effective and
      bounding sets
- [ ] Side-effect and rollback fields defined; descriptor-shaped effects reclaimed
      by child exit, anything outliving a process declares its rollback
- [ ] Risk class and timeout fields defined
- [ ] Architecture applicability field defined, so the diff engine cannot report
      architecture as policy
- [ ] Open question resolved: declarative data file, or Rust definitions compiled in
- [ ] Open question resolved: how a hung probe is distinguished from a slow one
- [ ] Open question resolved: whether the committed/deferred split lives here or in
      the corpus index
- [ ] Marked frozen; changes after this need team agreement

**Proposal reference:** §5, §6.2, §9.1
EOF

mkissue "[ALL] Freeze spec/fingerprint.md — confinement fingerprint format" \
        "spec,freeze-gate,critical-path" "$M2" <<'EOF'
**Workstream:** agreed by all four (proposal §5)
**Phase:** Week 2 — the interface freeze

The fingerprint is the fixed interface of the whole system. The engine and corpus
produce it; the diff engine, evaluator and remediator consume it. Agreeing it now is
what allows the four workstreams to proceed without blocking one another.

**Done when**
- [ ] Environment cell recorded as first-class identity fields: processor
      architecture, kernel version and distribution, relevant loaded modules,
      container runtime and version, active LSM, RuntimeClass
- [ ] Per-probe verdict enumeration fixed: `permitted` / `denied` / `unimplemented`
      / `killed`, plus the raw errno
- [ ] Attribution recorded with a confidence level, and an explicit flag for
      attribution that was undecidable from inside the container
- [ ] Open question resolved: how a consumer handles a fingerprint from an older
      corpus revision
- [ ] Open question resolved: the signing mechanism — the proposal calls
      fingerprints signed, so decide what that means
- [ ] Serialisation format chosen and its stability guarantees stated
- [ ] Marked frozen for week 2 purposes; final freeze is week 9 (see the W9 issue)

**Proposal reference:** §5, §9.1
EOF

mkissue "[C] Recorded fingerprint fixtures for downstream development" \
        "spec,ws:control" "$M2" <<'EOF'
**Workstream:** C — fingerprint, diff and evaluation
**Phase:** Week 2, in parallel with the engine

The proposal requires the reporting layers to be developed against recorded
fingerprints long before the corpus is complete. Without fixtures, C and D are
blocked on A for six weeks.

**Done when**
- [ ] At least two hand-written fingerprints conforming to the frozen format,
      differing only in architecture
- [ ] At least two differing only in a policy field, so the divergence classifier
      has something to separate
- [ ] Fixtures live in the repository and are used by the diff engine's tests
- [ ] A fixture exists representing the AF_ALG case, so the evaluator can be
      developed against the motivating example before the probe exists

**Proposal reference:** §5, §9.1
EOF

# --------------------------------------------------------- W3 — engine ------

mkissue "[A] Rust workspace, static musl build, dependency-free probe image" \
        "ws:engine,critical-path" "$M3" <<'EOF'
**Workstream:** A — probe engine and safety
**Phase:** Weeks 1–3

The probe image must be statically linked and dependency-free by construction: any
library it carries is itself a source of syscalls that pollute the measurement.

**Done when**
- [ ] Cargo workspace laid out under `engine/`
- [ ] Static musl target builds and runs with no dynamic loader
- [ ] `nix` and `libc` are the only syscall-facing dependencies
- [ ] The binary issues no background syscalls of its own during a probe — verified
      by strace on a no-op run
- [ ] Container image builds from scratch, carrying the binary and nothing else

**Proposal reference:** §5, §10
EOF

mkissue "[A] Fork isolation harness — one child per risky probe" \
        "ws:engine,critical-path" "$M3" <<'EOF'
**Workstream:** A — probe engine and safety
**Phase:** Weeks 1–3

Fork isolation is the rollback mechanism for most of the corpus. Every side effect
that is descriptor-shaped — io_uring rings, BPF program and map descriptors,
sockets, userfaultfd, perf events — is reclaimed by the kernel when the child exits.

**Done when**
- [ ] Each probe declaring a risk class executes in a forked child
- [ ] The child's exit status is itself the measurement, carried back to the parent
- [ ] The parent issues no syscalls between fork and the probe that could pollute
      the result
- [ ] Descriptor-shaped side effects are demonstrably reclaimed at child exit
- [ ] A probe that crashes its child does not lose the run

**Proposal reference:** §6.2
EOF

mkissue "[A] SIGSYS survival — record SECCOMP_RET_KILL_PROCESS without losing the run" \
        "ws:engine,critical-path" "$M3" <<'EOF'
**Workstream:** A — probe engine and safety
**Phase:** Weeks 1–3

An instrument that dies on its first genuine finding is worthless. A probe tripping a
filter whose action is `SECCOMP_RET_KILL_PROCESS` terminates the process that issued
it; the run must continue and record the kill as the verdict.

This is not the common case — `RuntimeDefault`'s default action is `SCMP_ACT_ERRNO`
rather than a kill — but it is exactly the case for the hand-authored hardened
profiles this instrument is most useful against.

**Done when**
- [ ] A child terminated by SIGSYS is recorded with the `killed` verdict
- [ ] The parent survives and continues to the next probe
- [ ] Verified against a test fixture installing a real `KILL_PROCESS` filter, built
      with `seccompiler`
- [ ] Distinguished from a child that exited normally having received an errno

**Proposal reference:** §6.2, §12
EOF

mkissue "[A] Timeout handling — distinguish a hung probe from a slow one" \
        "ws:engine" "$M3" <<'EOF'
**Workstream:** A — probe engine and safety
**Phase:** Weeks 1–3

Probes with unbounded duration execute under a timeout, and a probe that hangs is
recorded as such rather than stalling the run. `spec/probe.md` lists the distinction
between hung and slow as an open question — resolve it here in line with whatever
that issue decides.

**Done when**
- [ ] Per-probe timeout read from the probe's risk class
- [ ] A probe exceeding it is killed and recorded distinctly, not as `denied`
- [ ] The full corpus cannot stall indefinitely on any single probe
- [ ] The hung/slow distinction matches what `spec/probe.md` specifies

**Proposal reference:** §6.2
EOF

mkissue "[A] Verdict classification — permitted / denied / unimplemented / killed, plus raw errno" \
        "ws:engine,critical-path" "$M3" <<'EOF'
**Workstream:** A — probe engine and safety
**Phase:** Weeks 1–3

Each probe records the verdict, not an interpretation of it. Interpretation is the
attributor's job, and conflating the two makes attribution unfalsifiable.

**Done when**
- [ ] The four verdicts are distinguished correctly and the raw errno preserved
      alongside every one
- [ ] `unimplemented` is separated from `denied` — an address family the kernel does
      not implement is not a policy finding
- [ ] The engine performs no attribution and stores no interpretation
- [ ] Output conforms to the frozen fingerprint format

**Proposal reference:** §5, §6.1
EOF

mkissue "[A] Side-effect declaration and accounting, enforced by the engine" \
        "ws:engine" "$M3" <<'EOF'
**Workstream:** A — probe engine and safety
**Phase:** Weeks 1–3

The proposal is explicit that the side-effect declaration requirement is enforced by
the engine rather than left to convention — it is one of the §12 mitigations for a
probe destabilising a host.

**Done when**
- [ ] A probe without a side-effect declaration is rejected, not run
- [ ] Effects that outlive a process are measured directly rather than by whole-host
      comparison, which normal system churn would swamp
- [ ] The five tracked classes are accounted: mount table, session and user keyrings,
      cgroup entries, System V and POSIX IPC objects, network namespaces
- [ ] A residual-state report is emitted after a full run

**Proposal reference:** §6.2, §11.2, §12
EOF

mkissue "[A] Ten-probe reference corpus running end to end" \
        "ws:engine,ws:corpus,critical-path" "$M3" <<'EOF'
**Workstream:** A — probe engine and safety
**Phase:** End of week 3 — the phase gate

Ten probes, each authored complete with errno oracle, capability requirement and
side-effect declaration, running from image start to emitted fingerprint. This is
the deliverable the whole schedule hangs on: every probe family depends on it, and a
defect here is discovered late and cascades.

**Done when**
- [ ] Ten probes spanning at least three entry families
- [ ] Each carries its errno oracle, capability requirement and side-effect
      declaration — none deferred
- [ ] At least one probe exercises the SIGSYS path
- [ ] A complete fingerprint is emitted and validates against the frozen format
- [ ] Runs inside an unprivileged container with no added capabilities

**Proposal reference:** §9.1, §12
EOF

# --------------------------------------------------------- W8 — corpus ------

mkissue "[A] Probe family: socket address families and netlink protocol numbers" \
        "ws:corpus" "$M8" <<'EOF'
**Workstream:** A — half the corpus (proposal §8)
**Phase:** Weeks 4–8, first in the committed order

First because it carries the motivating case. CVE-2026-31431 is reached through
AF_ALG, a socket address family and not a distinctive syscall — filtering at
syscall-name granularity cannot express the difference between a container that may
call `socket(2)` and one that may reach the kernel crypto API.

**Done when**
- [ ] Address families probed individually, AF_ALG among them
- [ ] Netlink protocol numbers probed individually, raw netlink included
- [ ] Every probe carries an errno oracle — `EAFNOSUPPORT` for an unimplemented
      family is the natural one here
- [ ] `unimplemented` is correctly separated from `denied`
- [ ] Side effects are socket descriptors only, reclaimed at child exit

**Proposal reference:** §2, §4 (objective 2), §9.1
EOF

mkissue "[A] Probe family: io_uring opcode reach via IORING_REGISTER_PROBE" \
        "ws:corpus" "$M8" <<'EOF'
**Workstream:** A — half the corpus
**Phase:** Weeks 4–8

io_uring defeats syscall filtering entirely by performing operations without issuing
the corresponding syscalls, and entered the default deny set only in 2023 (Moby) and
2024 (containerd) — so a node image predating those changes enforces a weaker policy
than an identically configured one that does not.

Measured with `IORING_REGISTER_PROBE`, which reports supported opcodes **without
submitting a single queue entry**. This is the proposal's stated preference for
enumeration over execution and is not optional.

**Done when**
- [ ] Opcode reach measured via registration, with no SQE ever submitted
- [ ] Ring descriptors reclaimed at child exit
- [ ] The probe distinguishes io_uring being denied outright from individual opcodes
      being unavailable
- [ ] Errno oracle authored

**Proposal reference:** §2, §6.2, §13
EOF

mkissue "[A] Probe family: mount filesystem types" \
        "ws:corpus" "$M8" <<'EOF'
**Workstream:** A — half the corpus
**Phase:** Weeks 4–8

**Done when**
- [ ] Filesystem types probed individually
- [ ] Errno oracle authored per probe
- [ ] Capability requirement recorded (CAP_SYS_ADMIN) for correlation
- [ ] Mount table is one of the tracked residual-state classes — the probe declares
      its rollback and leaves nothing behind
- [ ] No probe performs a mount whose success confers privilege

**Proposal reference:** §4 (objective 2), §6.2, §13
EOF

mkissue "[B] Probe family: clone and unshare flags" \
        "ws:corpus" "$M8" <<'EOF'
**Workstream:** B — the remaining corpus families
**Phase:** Weeks 4–8

**Done when**
- [ ] Namespace flags probed individually, CLONE_NEWUSER included
- [ ] Errno oracle authored per flag
- [ ] Network namespaces are a tracked residual-state class — rollback declared
- [ ] Capability requirements recorded for correlation against the bounding set

**Proposal reference:** §4 (objective 2), §6.1
EOF

mkissue "[B] Probe family: masked and read-only path coverage" \
        "ws:corpus" "$M8" <<'EOF'
**Workstream:** B — the remaining corpus families
**Phase:** Weeks 4–8

Mount masking is one of the mechanisms that can produce a denial indistinguishable
from seccomp or a dropped capability, so this family feeds the attributor directly.

**Done when**
- [ ] The OCI runtime specification's default masked and read-only paths are probed
- [ ] Unmasked procfs is detectable, since the reference posture asserts against it
- [ ] Probes read only — nothing writes to a path that is unexpectedly writable
- [ ] Errno oracle authored per probe

**Proposal reference:** §6.1, §7, §10
EOF

mkissue "[B] Probe family: device node access" \
        "ws:corpus" "$M8" <<'EOF'
**Workstream:** B — the remaining corpus families
**Phase:** Weeks 4–8

**Done when**
- [ ] Device nodes probed for reachability, by open only
- [ ] No probe reads from or writes to a device whose access confers privilege
- [ ] Errno oracle authored per probe
- [ ] Descriptors reclaimed at child exit

**Proposal reference:** §4 (objective 2), §13
EOF

mkissue "[B] Probe family: capability effect" \
        "ws:corpus" "$M8" <<'EOF'
**Workstream:** B — the remaining corpus families
**Phase:** Weeks 4–8

Last in the committed order, and the family that most directly supports capability
attribution: it establishes what a capability actually buys in this environment
rather than what the manifest says was granted.

**Done when**
- [ ] For each capability of interest, a probe whose success depends on it
- [ ] Effective and bounding sets read from `/proc/self/status`, which needs no
      privilege
- [ ] Discrepancies between granted and effective capability are detectable
- [ ] Errno oracle authored per probe

**Proposal reference:** §6.1
EOF

mkissue "[B] Errno oracle authored for every probe in the committed set" \
        "ws:corpus,freeze-gate" "$M8" <<'EOF'
**Workstream:** B — errno oracle authoring across the whole corpus (§8)
**Phase:** Weeks 4–8, gating the corpus freeze

The oracle is the primary attribution technique and the reason attribution needs no
privilege. Each probe's arguments are chosen so that, if the syscall reaches the
kernel at all, a specific and distinctive error is structurally guaranteed —
`EBADF` on a deliberately invalid descriptor, `EINVAL` on a malformed request,
`EAFNOSUPPORT` for an unimplemented family. Receiving `EPERM` where `EBADF` was
guaranteed **proves** the call was intercepted before execution, and therefore that
a filter and not a capability produced the denial.

The proposal states the corpus is not considered complete until every probe carries
one. This issue is the check on that.

**Done when**
- [ ] Every committed-set probe has an oracle with its guaranteed errno recorded
- [ ] Each oracle's guarantee is justified in a comment against the relevant man page
- [ ] No probe in the committed set is exempt
- [ ] A CI check fails the build if a probe lacks an oracle

**Proposal reference:** §6.1
EOF

mkissue "[A+B] Corpus index and committed/deferred split; freeze end of week 8" \
        "ws:corpus,freeze-gate" "$M8" <<'EOF'
**Workstream:** A and B jointly
**Phase:** End of week 8 — the corpus freeze

The corpus is frozen at a declared size. This is the §12 mitigation for the project's
principal risk: becoming breadth without depth and producing a larger `amicontained`
rather than an instrument.

**Done when**
- [ ] An index enumerating every probe, its family, and its committed/deferred status
- [ ] The committed set is complete: socket families and netlink, io_uring opcodes,
      mount filesystem types, clone and unshare flags, masked and read-only paths,
      device nodes, capability effect
- [ ] The corpus size is declared and recorded
- [ ] Frozen. The deferred set is entered only if the committed set is complete and
      the schedule is intact
- [ ] If the engine slipped, the deferred set is abandoned before any reduction is
      made to attribution, evaluation or the environment matrix

**Proposal reference:** §9.1, §9.2, §12
EOF

mkissue "[B] Specify the deferred set in the committed format, unimplemented" \
        "ws:corpus,deferred-set" "$M8" <<'EOF'
**Workstream:** B
**Phase:** Weeks 4–8

Specified in the same format as the committed set so that implementing it later is
additive work rather than redesign. Specification only — no implementation under this
issue.

**Families to specify**
ioctl request codes · bpf commands and program types · keyctl operations ·
prctl options · perf_event_open · userfaultfd · open_by_handle_at · module loading ·
seccomp user notification

**Done when**
- [ ] Each family specified in the frozen probe format
- [ ] Errno oracle strategy noted per family, even though unimplemented
- [ ] Recorded explicitly as deferred, so its absence is visible rather than
      discovered later

**Proposal reference:** §4 (objective 2), §9.2
EOF

mkissue "[B] Reference posture: tier definitions" \
        "ws:posture" "$M8" <<'EOF'
**Workstream:** B — reference posture
**Phase:** Weeks 4–8, in parallel with the corpus

The motivating case is not a claim violation. PSS Restricted asserts nothing about
AF_ALG and `RuntimeDefault`'s entire contract is that it contains whatever the
runtime ships — so measured against the manifest alone, the AF_ALG case produces no
finding. What failed was an expectation, and detecting it needs a model of what a
hardened workload ought not to reach, authored independently of what any
specification happens to promise.

**Done when**
- [ ] Named security tiers defined, including an untrusted multi-tenant tier
- [ ] Each tier states what class of workload it describes
- [ ] The relationship to the PSS tiers it is named after is stated, including that
      it is deliberately stronger — that gap is the point of it

**Proposal reference:** §7
EOF

mkissue "[B] Reference posture: per-tier assertions, each with rationale and citation" \
        "ws:posture" "$M8" <<'EOF'
**Workstream:** B — reference posture
**Phase:** Weeks 4–8

For each tier, which kernel entry families a workload at that tier should not reach:
for the untrusted multi-tenant tier, the kernel crypto API, module loading,
`perf_event_open`, raw netlink, io_uring, the 32-bit ABI, unmasked procfs, and the
rest.

Every assertion carries a rationale and a citation — a CVE, a documented escape
technique, or a vendor advisory — so the posture is auditable rather than assertion
by authority. This is the §12 mitigation for the posture being our own judgement, and
it is the most reusable artefact the project produces.

**Done when**
- [ ] Assertions follow the same entry families as the probes, so they map one to one
- [ ] Every assertion has a rationale
- [ ] Every assertion has a citation
- [ ] AF_ALG is asserted against for the untrusted tier, citing CVE-2026-31431
- [ ] No assertion rests on our authority alone

**Proposal reference:** §7, §12
EOF

mkissue "[B] Reference posture versioning so findings are reproducible against a revision" \
        "ws:posture" "$M8" <<'EOF'
**Workstream:** B — reference posture
**Phase:** Weeks 4–8

The posture is a judgement, and the §12 mitigation is that findings are reproducible
against a stated revision of it.

**Done when**
- [ ] The posture carries a version
- [ ] Every finding records the posture revision it was evaluated against
- [ ] A changelog records what changed between revisions and why
- [ ] Released with the instrument

**Proposal reference:** §7, §12
EOF

# -------------------------------------------------- W9 — fingerprint --------

mkissue "[C] Environment cell detection — arch, kernel, runtime+version, LSM, RuntimeClass" \
        "ws:control" "$M9" <<'EOF'
**Workstream:** C — fingerprint, diff and evaluation
**Phase:** Weeks 4–9

The fingerprint's identity is the environment cell, not the workload. Detection has
to work from inside an unprivileged container.

**Done when**
- [ ] Processor architecture detected
- [ ] Kernel version, distribution and relevant loaded modules detected — module
      presence matters, since AF_ALG exploitability depends on whether `algif_aead`
      is loaded, which the workload author neither controls nor can observe
- [ ] Container runtime and runtime version detected
- [ ] Active LSM detected: AppArmor, SELinux or none
- [ ] RuntimeClass detected: runc, gVisor or Kata
- [ ] Fields that cannot be determined are recorded as unknown rather than guessed

**Proposal reference:** §2, §5
EOF

mkissue "[C] Fingerprint serialisation and version negotiation across corpus revisions" \
        "ws:control" "$M9" <<'EOF'
**Workstream:** C — fingerprint, diff and evaluation
**Phase:** Weeks 4–9

**Done when**
- [ ] Serialisation implemented in the format agreed in week 2
- [ ] A consumer handles a fingerprint produced by an older corpus revision without
      silently misreporting it
- [ ] Probes present in one fingerprint and absent from another are handled explicitly
      by the diff, not treated as a divergence
- [ ] Signing implemented per the week-2 decision
- [ ] Round-trips the recorded fixtures

**Proposal reference:** §5
EOF

mkissue "[C] Diff engine — divergence at probe granularity" \
        "ws:control" "$M9" <<'EOF'
**Workstream:** C — fingerprint, diff and evaluation
**Phase:** Weeks 4–9

**Done when**
- [ ] Two fingerprints diff at probe granularity, not family granularity
- [ ] Verdict changes are reported with both sides' raw errno
- [ ] Probes absent from one side are distinguished from probes that diverged
- [ ] Developed against the recorded fixtures, before the corpus is complete

**Proposal reference:** §4 (objective 4), §5
EOF

mkissue "[C] Divergence classifier — architecture / kernel-version / policy-explained" \
        "ws:control,critical-path" "$M9" <<'EOF'
**Workstream:** C — fingerprint, diff and evaluation
**Phase:** Weeks 4–9

**This classification is the contribution, not a correction.** Without it the headline
divergence metric is dominated by architecture rather than by policy, and a
divergence between an arm64 and an amd64 measurement gets reported as a policy
finding when it is nothing of the kind.

**Done when**
- [ ] Every divergence is classified as architecture-explained,
      kernel-version-explained or policy-explained
- [ ] Architecture applicability declared on the probe is what drives the
      architecture class — the classifier does not infer it
- [ ] The 32-bit ABI path, which has no arm64 equivalent, is correctly classified
- [ ] Divergence counts are reported separately per class, never as a single number
- [ ] Classification is testable against the recorded fixtures

**Proposal reference:** §4 (objective 4), §5, §11.2, §12
EOF

mkissue "[C] Freeze the fingerprint format" \
        "ws:control,freeze-gate" "$M9" <<'EOF'
**Workstream:** C — fingerprint, diff and evaluation
**Phase:** End of week 9 — the format freeze

The proposal states the system is independently defensible from the end of week 9:
at this point it measures, classifies and diffs confinement across environments
without yet evaluating against a posture or remediating. **That is the point below
which the project should not be allowed to fall.**

**Done when**
- [ ] Format frozen and its stability guarantees documented
- [ ] Engine output and control-plane input agree on it, verified end to end
- [ ] The system demonstrably measures, classifies and diffs across at least two real
      environments
- [ ] Comparison against `amicontained` and `seccomp-diff` on shared targets has been
      run at least once (full comparison is a week 15 issue)

**Proposal reference:** §5, §9.1
EOF

mkissue "[D] Kubernetes Job and DaemonSet packaging" \
        "ws:delivery" "$M9" <<'EOF'
**Workstream:** D — delivery and evaluation harness
**Phase:** Weeks 4–9, needed before the environment matrix

**Done when**
- [ ] Job manifest for a single-node measurement
- [ ] DaemonSet manifest for measuring every node in a cluster
- [ ] Runs unprivileged, with no added capabilities, under `RuntimeDefault`
- [ ] Fingerprints are retrievable from a completed run
- [ ] Manifests carry no privilege the instrument does not need — it must be
      deployable in the environments where it is most needed

**Proposal reference:** §4 (objective 7), §8
EOF

# ------------------------------- W12 — attribution, evaluator, remediation ---

mkissue "[B] Errno oracle attribution engine — prove interception before execution" \
        "ws:corpus" "$M12" <<'EOF'
**Workstream:** B — attribution
**Phase:** Weeks 9–11

Consumes the oracles authored during corpus construction. A probe receives `EPERM`
and the kernel does not say why: the denial may have come from the seccomp filter, a
dropped capability, AppArmor or SELinux, an unmapped identity in a user namespace, or
a read-only or masked mount. From inside the container these are indistinguishable,
and a report that cannot tell them apart cannot produce a remediation, because the
fix differs in each case.

**Done when**
- [ ] Receiving `EPERM` where the oracle guaranteed something else is reported as
      proof of interception before execution, and therefore of a filter
- [ ] Receiving the oracle's guaranteed errno is reported as the call having reached
      the kernel
- [ ] Attribution yields a positive proof rather than an inference, and needs no
      privilege
- [ ] Works from inside an unprivileged container

**Proposal reference:** §6.1
EOF

mkissue "[B] Capability correlation from effective and bounding sets in /proc/self/status" \
        "ws:corpus" "$M12" <<'EOF'
**Workstream:** B — attribution
**Phase:** Weeks 9–11

Capability attribution is by correlation: the operation's documented capability
requirement is recorded with the probe and checked against the sets read from the
process's own status, which is readable without privilege.

**Done when**
- [ ] Effective and bounding sets parsed from `/proc/self/status`
- [ ] Where a capability is absent and the errno oracle indicates the call reached
      the kernel, the capability is reported as the cause
- [ ] Capability-caused denials are distinguished from filter-caused ones
- [ ] Requires no privilege

**Proposal reference:** §6.1
EOF

mkissue "[B] Confidence model and measurement of the undecidable fraction" \
        "ws:corpus" "$M12" <<'EOF'
**Workstream:** B — attribution
**Phase:** Weeks 9–11

Some denials remain undecidable from inside the container. The design accepts this
rather than concealing it: the residual undecidable fraction is reported as a
measured quantity rather than assumed to be zero.

Note that filter introspection is **not** in scope. `PTRACE_SECCOMP_GET_FILTER`
requires CAP_SYS_ADMIN and a ptrace-attachable target, which an unprivileged
container does not have. The privileged helper is specified in the proposal but is
explicitly not a committed deliverable (§9.2).

**Done when**
- [ ] Every attribution carries a confidence level
- [ ] The undecidable fraction is computed and reported as a first-class output
- [ ] The instrument remains useful with attribution disabled, since reachability is
      the primary measurement and attribution refines it
- [ ] No attribution is asserted at a confidence the evidence does not support

**Proposal reference:** §6.1, §9.2, §12
EOF

mkissue "[C] Manifest parsing — seccomp profile, capability set, Pod Security Standard" \
        "ws:control" "$M12" <<'EOF'
**Workstream:** C — evaluator
**Phase:** Weeks 10–12

**Done when**
- [ ] Pod and container specs parsed for the declared seccomp profile, capability
      set and Pod Security Standard
- [ ] `RuntimeDefault` is recorded as runtime-defined rather than resolved to a
      fixed contract — its contents are a property of the runtime binary on the
      node, not of the manifest
- [ ] Uses the mature Kubernetes ecosystem libraries rather than hand-rolled parsing
- [ ] What the manifest does not say is distinguishable from what it says permissively

**Proposal reference:** §2, §5, §10
EOF

mkissue "[C] Finding categorisation — expectation / claim violation, undeclared exposure" \
        "ws:control" "$M12" <<'EOF'
**Workstream:** C — evaluator
**Phase:** Weeks 10–12

Three categories, and the distinction between the first two is what makes the
instrument detect the case it exists for. A checker comparing measurement against
the manifest and nothing else would have missed AF_ALG entirely.

| Category | Meaning |
|---|---|
| Expectation violation | Reachable, and the reference posture holds it should not be. The AF_ALG case. |
| Claim violation | The manifest asserts a protection the measurement does not confirm. |
| Undeclared exposure | Reachable, and addressed by neither model. An input to corpus and posture development. |

**Done when**
- [ ] All three categories implemented and reported separately, never merged
- [ ] Expectation violations record the posture revision they were evaluated against
- [ ] The AF_ALG case is categorised as an expectation violation, not a claim
      violation, when run against a `RuntimeDefault` + PSS Restricted manifest
- [ ] Undeclared exposures are surfaced as feedback into corpus and posture work

**Proposal reference:** §7
EOF

mkissue "[C] Reporting in JSON and human-readable form; SARIF deferred" \
        "ws:control" "$M12" <<'EOF'
**Workstream:** C — reporting
**Phase:** Weeks 10–12

SARIF is explicitly deferred behind these two (§9.2). Do not build it under this
issue.

**Done when**
- [ ] Machine-readable JSON output covering findings, divergences and attribution
      confidence
- [ ] Human-readable output that states the divergence classes separately
- [ ] The undecidable attribution fraction appears in both
- [ ] Output states that the instrument is intended for infrastructure the operator
      owns or has written authorisation to test

**Proposal reference:** §9.2, §13
EOF

mkissue "[D] Remediation generator — minimal Localhost seccomp profile and SPO custom resource" \
        "ws:delivery" "$M12" <<'EOF'
**Workstream:** D — remediation
**Phase:** Weeks 10–12

Emits the minimal argument-level policy closing the divergences found. Minimal *with
respect to the reference posture* — without the posture, a minimal patch has nothing
to be minimal against.

The SPO custom resource is the **primary** output form, not an alternative: a
Localhost profile requires the file to exist at the kubelet's seccomp root on every
node, which is not achievable on EKS or GKE without custom node images or a
privileged installer. The SPO CR solves distribution.

**Done when**
- [ ] Security Profiles Operator custom resource emitted as the primary form
- [ ] Localhost seccomp profile emitted as the secondary form
- [ ] Policy is argument-level, not syscall-name-level — syscall-name granularity is
      the granularity at which the AF_ALG case is invisible
- [ ] Minimal with respect to a stated posture revision
- [ ] Divergences the instrument can identify but cannot close are reported as such

**Proposal reference:** §4 (objective 7), §7, §12
EOF

mkissue "[D] Closure verification by re-probing" \
        "ws:delivery" "$M12" <<'EOF'
**Workstream:** D — remediation
**Phase:** Weeks 10–12

**Done when**
- [ ] Generated policy is applied and the corpus re-run
- [ ] Closure is verified by measurement, not asserted from the policy text
- [ ] Divergences that remain open after remediation are reported
- [ ] Verification is performed on self-managed nodes, per the §12 mitigation

**Proposal reference:** §4 (objective 7), §11.2, §12
EOF

mkissue "[D] CI integration with the reduced corpus" \
        "ws:delivery" "$M12" <<'EOF'
**Workstream:** D — delivery
**Phase:** Weeks 10–12

**Done when**
- [ ] The instrument runs in CI and reports findings against a pull request
- [ ] A reduced corpus exists for CI use
- [ ] The reduced corpus completes in **under 5 seconds** (§11.2)
- [ ] Uses the mature Go ecosystem libraries for reporting

**Proposal reference:** §10, §11.2
EOF

mkissue "[D] Environment matrix automation — the six required cells" \
        "ws:delivery,evaluation" "$M12" <<'EOF'
**Workstream:** D — evaluation harness
**Phase:** Weeks 4–12, feeding week 13–15 evaluation

Six required cells, each chosen to move exactly one axis relative to another in the
set, so that a divergence is attributable. All six run on developer hardware, so the
evaluation depends on neither cloud budget nor account availability.

Cells are counted honestly: kind, minikube and k3s on the same host are **one** cell,
not three, because all three are containerd on the same kernel. The same collapse
applies to Docker Desktop and Colima on macOS, which share a Lima-class VM.

**Required cells**
- [ ] arm64, Lima-class kernel, containerd, no LSM
- [ ] amd64, Ubuntu 24.04, containerd and runc, AppArmor
- [ ] amd64, Fedora or Rocky, containerd, SELinux
- [ ] amd64, Ubuntu 24.04, containerd predating the io_uring deny change
- [ ] amd64, gVisor RuntimeClass
- [ ] amd64, Kata Containers RuntimeClass

**Optional additions, only if the schedule permits**
- [ ] amd64 Podman and crun on the AppArmor host
- [ ] EKS on Amazon Linux 2023
- [ ] GKE on Container-Optimized OS

**Also done when**
- [ ] Bring-up is automated and repeatable
- [ ] Development happens inside disposable VMs with snapshot rollback (§12)

**Proposal reference:** §11.1, §12
EOF

mkissue "[D] Documented probe image signature and alert-safe reduced corpus" \
        "ws:delivery" "$M12" <<'EOF'
**Workstream:** D — delivery
**Phase:** Weeks 10–12

The instrument may be indistinguishable from an attack to runtime security tooling.
This is the §12 mitigation.

**Done when**
- [ ] A documented signature for the probe image is published, so operators can
      allowlist it deliberately
- [ ] A reduced corpus omits the probes most likely to raise alerts
- [ ] Which probes are omitted, and why, is documented
- [ ] Tested against at least one runtime monitor

**Proposal reference:** §12
EOF

# ----------------------------------------------------- W15 — evaluation -----

mkissue "[D] Metric: divergence across cells, reported per divergence class" \
        "evaluation" "$M15" <<'EOF'
**Workstream:** D, with C
**Phase:** Weeks 13–15

Number of probes whose verdict differs between cell pairs, reported separately for
each divergence class.

**Success criterion (§11.2)**
- [ ] Policy-explained divergence measured in **at least four cell pairs**
- [ ] Architecture-explained divergence correctly separated from it in **every** pair

**Proposal reference:** §11.2
EOF

mkissue "[C] Metric: expectation and claim violations by category and cell" \
        "evaluation" "$M15" <<'EOF'
**Workstream:** C
**Phase:** Weeks 13–15

**Success criterion (§11.2)**
- [ ] At least one expectation violation found in **at least three distinct cells**
- [ ] Violations broken down by category and by cell
- [ ] Expectation violations reported separately from claim violations, so a reader
      can weigh them differently

**Proposal reference:** §11.2, §12
EOF

mkissue "[A+B] Metric: reproduce the AF_ALG case unaided" \
        "evaluation,critical-path" "$M15" <<'EOF'
**Workstream:** A and B
**Phase:** Weeks 13–15

The headline result. Detection of what previously required bespoke test images and a
hand-authored profile — establishing the original finding took exactly that, and this
is the demonstration that the instrument removes the need.

**Success criterion (§11.2): binary.**

**Done when**
- [ ] AF_ALG reachability detected on a `RuntimeDefault` + PSS Restricted workload
      with no hand-built image and no bespoke profile
- [ ] Reported as an expectation violation, citing CVE-2026-31431 via the posture
- [ ] Reproduced on containerd, matching the published Talos and EKS testing
- [ ] `algif_aead` module presence recorded in the environment cell, since
      exploitability depends on it

**Proposal reference:** §2, §11.2
EOF

mkissue "[B] Metric: attribution accuracy against constructed ground truth" \
        "evaluation" "$M15" <<'EOF'
**Workstream:** B
**Phase:** Weeks 13–15

Measured against a constructed ground truth: environments in which each denial has a
single known cause.

**Success criteria (§11.2)**
- [ ] Ground-truth environments constructed, one known denial cause each
- [ ] Attribution **at least 90 per cent** correct
- [ ] Undecidable fraction reported and **not exceeding 10 per cent**

**Proposal reference:** §6.1, §11.2
EOF

mkissue "[D] Metric: remediation closure rate, verified by re-probing" \
        "evaluation" "$M15" <<'EOF'
**Workstream:** D
**Phase:** Weeks 13–15

**Success criteria (§11.2)**
- [ ] **100 per cent** closure for seccomp-attributed divergences
- [ ] Closure for divergences attributed to other mechanisms reported **without a
      threshold** — the instrument may identify these but cannot always close them
- [ ] Every closure verified by re-probing, not asserted
- [ ] Performed on self-managed nodes

**Proposal reference:** §11.2, §12
EOF

mkissue "[A] Metric: residual state across five object classes, and runtime cost" \
        "evaluation" "$M15" <<'EOF'
**Workstream:** A
**Phase:** Weeks 13–15

**Success criteria (§11.2)**
- [ ] **Zero unreclaimed objects** after a full run, across all five tracked classes:
      mount table, session and user keyrings, cgroup entries, System V and POSIX IPC
      objects, network namespaces
- [ ] Full corpus completes in **under 60 seconds**
- [ ] Reduced CI corpus completes in **under 5 seconds**
- [ ] Measured directly per class, not by whole-host comparison

**Proposal reference:** §6.2, §11.2
EOF

mkissue "[C] Comparison against amicontained and seccomp-diff on identical targets" \
        "evaluation" "$M15" <<'EOF'
**Workstream:** C
**Phase:** Weeks 13–15

The two direct ancestors, compared on identical targets and reported as findings
produced by each.

`amicontained` reports runtime, namespaces, capabilities and a coarse list of blocked
syscalls; last release v0.4.9, November 2019. `seccomp-diff` extracts and disassembles
the seccomp-BPF filter from a running process and diffs two of them — confined to
seccomp, requires privilege an unprivileged container does not hold, and reasons about
the filter rather than about reachability, so it cannot account for capabilities, LSM
policy, mount masking, loaded modules or architecture.

**Done when**
- [ ] Both run on identical targets to CALIPER
- [ ] Findings produced by each are reported side by side
- [ ] Cases CALIPER finds that neither ancestor can are identified explicitly
- [ ] The comparison is fair — where an ancestor is not designed to answer the
      question, that is stated rather than scored

**Proposal reference:** §3, §11.2
EOF

# -------------------------------------------------------- W17 — release -----

mkissue "[ALL] Final report" \
        "" "$M17" <<'EOF'
**Workstream:** all four
**Phase:** Week 17

**Done when**
- [ ] Every §11.2 metric reported with its measured value, including those that
      missed their threshold
- [ ] The undecidable attribution fraction stated rather than omitted
- [ ] What the compression gave up is stated as §9.2 states it: deferred corpus set,
      unbuilt privileged helper, six-cell matrix, deferred SARIF
- [ ] Coordinated disclosure obligations discharged — any genuine defect found in a
      runtime, distribution or managed platform, rather than an operator
      misconfiguration, reported to the vendor before publication

**Proposal reference:** §9.2, §11.2, §13
EOF

mkissue "[ALL] Demonstration" \
        "" "$M17" <<'EOF'
**Workstream:** all four
**Phase:** Week 17

**Done when**
- [ ] End-to-end demonstration: measure, diff, classify, evaluate, remediate,
      verify closure
- [ ] The AF_ALG case shown unaided
- [ ] At least two environment cells shown diverging, with the divergence correctly
      classified as policy rather than architecture

**Proposal reference:** §9.1
EOF

mkissue "[D] Release — probe image, reference posture, documentation" \
        "ws:delivery" "$M17" <<'EOF'
**Workstream:** D, as integrator
**Phase:** Week 17

**Done when**
- [ ] Probe image published with its documented signature
- [ ] Reference posture released with the instrument — in practical terms the most
      reusable artefact the project produces
- [ ] Documentation states the instrument measures and reports; it does not enforce,
      and is not a substitute for the mechanisms whose effect it measures
- [ ] Documentation states it is intended for infrastructure the operator owns or has
      written authorisation to test
- [ ] Confirmed: the corpus contains no exploit code and no operation whose success
      confers privilege

**Proposal reference:** §7, §13, §14
EOF

echo
echo "Done. $(gh issue list --repo "$REPO" --state all --limit 100 --json number --jq 'length') issues on $REPO."
echo "Issues are unassigned by design — claim one with:"
echo "  gh issue edit <n> --add-assignee <handle>"
