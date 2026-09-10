# Probe engine (Rust)

Owner: A. Fork isolation, SIGSYS survival, timeout handling, verdict
classification, side-effect accounting, the probe specification format, and
the errno oracle attribution engine.

Attribution is split between A and B: B decides what a given errno proves —
oracle design, the capability and security-module correlation, the confidence
model — and A builds the machinery that proves it. Establishing that a call was
intercepted before the kernel reached the point at which the oracle guaranteed
its error is a property of the fork-and-verdict path, so it lives here rather
than in the corpus that declares the oracles.

Rust rather than Go: the engine must fork before each risky probe, must not
issue syscalls of its own that pollute the measurement, and must survive a
probe terminated by SECCOMP_RET_KILL_PROCESS. A managed runtime that spawns
threads and issues background syscalls is unsuitable on all three counts.

The engine snapshots the loaded module set before the first probe and after the
last, because socket-family probes can trigger module autoload; the difference
is reported as a finding and the environment cell uses the first snapshot.

Weeks 1-3 deliver the engine plus a ten-probe reference corpus end to end.
This is the critical path — every probe family depends on it.
