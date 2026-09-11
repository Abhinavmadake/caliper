# Fixed interfaces

These two documents are the contract between the four workstreams. The
proposal commits to agreeing them in week 2 and treating them as fixed
thereafter, because every other workstream develops against them rather than
against the engine itself.

Both passed the week 2 gate on **2026-09-11**. The six questions they left open
are resolved in a `## Decisions` section in each file, with the reasoning and
its proposal citation kept alongside the decision — so a later reader can tell
whether a change is a correction or a reversal.

`probe.md` is frozen outright. `fingerprint.md` is fixed for week 2 purposes
and finally frozen at the end of week 9 (§5, issue #28), after which a change
is a new format version.

§8 makes both freezes a decision of all four members. The team delegated it to
A, who took it, and each file records that at the top: the decisions are A's
under a delegation rather than four members' consensus, which is worth knowing
if one of them has to be reopened.

The interface is now fixed, so the other three workstreams develop against
these files rather than against the engine — which is the whole point of
freezing them this early (§5).

- `probe.md` — how a probe is specified, including its attribution metadata
- `fingerprint.md` — what a measurement run emits
