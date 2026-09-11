# Security policy

CALIPER is an instrument for measuring what a kernel permits a container to
reach. That makes the boundary between "measurement" and "exploitation" the
property that matters most, and it is the one we want to hear about first.

## What counts

Report it here if you find that:

- a probe does more than establish reachability — it succeeds at an operation
  whose success confers privilege, leaves state behind that is not declared as
  a side effect, or can be made to do either by an argument the engine accepts;
- a probe can escape fork isolation, or a probe's termination (SIGSYS, timeout,
  panic) can take the engine down with it or corrupt the run's verdicts;
- the engine issues a syscall that is not in `engine/baseline/` — its own
  footprint pollutes the measurement and the baseline check should have caught
  it;
- a remediation the tool emits weakens the policy it was asked to tighten;
- anything in the usual sense — memory safety in the engine, a dependency
  advisory, a CI workflow that can be made to run untrusted code.

A probe that is denied where you expected it to be permitted, or the reverse,
is a measurement result, not a vulnerability. Open an ordinary issue for that.

## How to report

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). Do not open a public issue for
anything in the list above.

We aim to acknowledge a report within a week, and to follow it with a fix or a
written assessment of why it is not one. CALIPER is a final-year project
maintained alongside coursework: those are intentions, not guarantees, and
they will be slower around university deadlines. We would rather say so than
publish a service level we cannot hold to.

If a report goes unacknowledged for two weeks, please escalate by opening a
public issue saying only that you are waiting on a security report — no
details, no reproducer. That tells us to look without putting the finding in
the open.

We will credit you in the release notes unless you ask us not to.

## Scope of use

CALIPER is intended for infrastructure you own or have written authorisation
to test. Running it against a system you are not authorised to test is out of
scope for this policy and for the project.
