# Probe engine (Rust)

Owner: A. Fork isolation, SIGSYS survival, timeout handling, verdict
classification, side-effect accounting, and the probe specification format.

Rust rather than Go: the engine must fork before each risky probe, must not
issue syscalls of its own that pollute the measurement, and must survive a
probe terminated by SECCOMP_RET_KILL_PROCESS. A managed runtime that spawns
threads and issues background syscalls is unsuitable on all three counts.

Weeks 1-3 deliver the engine plus a ten-probe reference corpus end to end.
This is the critical path — every probe family depends on it.
