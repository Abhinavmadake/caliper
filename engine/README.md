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

## The engine's own syscalls

A probe measures what the kernel permits; the engine must not add syscalls of
its own to that measurement, and the parent runs under the same seccomp filter
as the probe, so its start-up set must survive `RuntimeDefault` and a
hand-hardened profile.

`baseline/<arch>.txt` is that set — the output of `scripts/baseline-syscalls.sh`,
an strace of `caliper-probe --noop`. Eleven syscalls on aarch64, twelve on
x86_64, all Rust std and musl start-up (standard-descriptor check, SIGPIPE,
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
