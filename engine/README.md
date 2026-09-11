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

## Layout

| Crate | Contents |
|-------|----------|
| `crates/engine` | `caliper-engine` — everything that touches the kernel on the instrument's own behalf. One crate to audit for the engine's syscall set |
| `crates/corpus` | `caliper-corpus` — probe definitions, compiled in (`spec/probe.md`, decision 1). A and B author here |
| `crates/probe` | `caliper-probe` — the binary. The image contains it and nothing else |

`nix` and `libc` are the only syscall-facing dependencies; `serde` is the
serialisation named in §10. Adding a dependency means accounting for the
syscalls it brings.

## Building

The targets are `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`;
`rust-toolchain.toml` installs both. They are self-contained, so a build from
any host needs only a linker that emits ELF, and `.cargo/config.toml` names
`rust-lld`, which ships with the toolchain:

    cargo build --release --target x86_64-unknown-linux-musl

The release profile is the image profile: `panic = "abort"` (a probe child
must never unwind), LTO, stripped. The image is `Dockerfile` here — two
stages, Alpine to build and `scratch` to ship:

    docker build -t caliper-probe engine/

## Fork isolation

`caliper_engine::run_isolated` runs one probe in one child and returns how
the child ended (`harness.rs`). The child is made with musl's `fork()`, and
the parent then opens a pidfd on it so its wait is a bounded `ppoll` — the
timeout from the probe's risk class, with no signals. Not a raw `clone`:
musl caches the thread id and delivers `abort()`/`raise()` to it with
`tkill`, so a raw-cloned child that aborted killed the parent. `fork()`
fixes the id up in the child, at the cost of `set_tid_address` and
`rt_sigprocmask` there before the probe, both already in the engine's
start-up set.

The child's exit status is the measurement. `_exit(0)` means the operation
succeeded; `_exit(errno)` carries the errno (Linux errnos on x86_64 and
aarch64 stop at 133; 253 and 254 are reserved for a probe that panicked or
an errno that does not fit). A child the kernel terminates — SIGSYS from a
`KILL_PROCESS` filter, SIGSEGV from a crash — is reported by signal, and the
parent goes on to the next probe. The child allocates nothing and issues no
syscall of its own but `exit_group`; the parent issues `clone`,
`pidfd_open`, `ppoll`, `wait4`, `close`, and `kill` on a timeout. `examples/harness-trace` under
`strace -f` shows exactly that and nothing else.

The engine forks for every probe, whether or not its risk class says it
requires isolation: a probe that declares it does not need the rollback still
must not be able to end the run.

`caliper_engine::init` runs once at start-up and marks the engine
non-dumpable (`PR_SET_DUMPABLE = 0`), which every child inherits. A child
killed by SIGSYS would otherwise dump core, and inside a container
`core_pattern` — not namespaced — commonly pipes that to the host's crash
handler, which is both a side effect on the node and a stall of a second or
more per crash. `RLIMIT_CORE = 0` does not prevent piped cores; the dumpable
flag does.

## The engine's own syscalls

A probe measures what the kernel permits; the engine must not add syscalls of
its own to that measurement, and the parent runs under the same seccomp filter
as the probe, so its start-up set must survive `RuntimeDefault` and a
hand-hardened profile.

`baseline/<arch>.txt` is that set — the output of `scripts/baseline-syscalls.sh`,
an strace of `caliper-probe --noop`. Twelve syscalls on aarch64, thirteen on
x86_64, all Rust std and musl start-up plus the engine's init (standard-descriptor check, SIGPIPE,
the stack-overflow handler and its alternate stack, malloc). CI diffs the
observed set against the file, so a dependency that starts issuing syscalls
fails the build rather than the measurement.

`fixtures/seccomp/hardened.json` is the hand-hardened profile: an exact
allowlist with `KILL_PROCESS` as the default, in three groups — the start-up
set, the isolation harness set (fork, wait, kill, write, exit), and runc's own
pre-exec set, which is a property of the runtime and was found empirically
(runc 1.5.1, on aarch64 and x86_64). It is verified two ways:

- `crates/probe/tests/hardened.rs` applies the first two groups with
  `seccompiler` in a forked child immediately before `execve`, so nothing but
  the engine is under the filter. A negative control drops one start-up
  syscall and checks the child dies of SIGSYS. Runs in CI on the musl target.
- `docker run --security-opt seccomp=fixtures/seccomp/hardened.json
  caliper-probe --noop` exercises the whole profile under a real runtime,
  alongside a run under the runtime's default profile.

## Developing on a Mac

`scripts/dev-vm.yaml` at the repository root is a Lima VM with strace,
Docker and a Rust toolchain, mounting the repository at its host path:

    limactl start --name caliper scripts/dev-vm.yaml
    limactl shell caliper -- bash -lc 'cd $PWD/engine && cargo test --target aarch64-unknown-linux-musl'

Cross-build on the host, run in the VM. The same file boots an emulated
x86_64 VM (`--arch x86_64 --vm-type qemu`; slow, but a real kernel and a real
runc), which is how the x86_64 baseline and profile were verified.
