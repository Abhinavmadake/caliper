# Posture changelog

This file records changes to the reference posture. Released revisions are
immutable; changing an assertion, tier definition, rationale, or citation
requires a new revision directory and a new entry here.

## v1 — draft — 2026-10-10

- Initial draft reference posture for CALIPER; release is blocked on issue #94.
- Defines the `privileged`, `baseline`, `restricted`, and
  `untrusted-multi-tenant` tiers and their stronger-than-PSS boundaries.
- Records the auditable assertions and citations from issues #21 and #22.
- Findings evaluated against this posture must record `posture_revision: v1`.
