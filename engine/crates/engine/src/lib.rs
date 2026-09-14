// Copyright 2026 Abhinav Ajit Madake, Sahil Tatyabhau Waje,
// Ritesh Aresh Saindane, Yogesh Babaji Palve
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The probe engine. Everything that touches the kernel on the instrument's
//! own behalf lives here, so that the set of syscalls the engine issues is
//! one crate's worth of code to audit (issue #4) rather than a property of
//! the whole workspace.
//!
//! - [`probe`] — what a probe is (`spec/probe.md`)
//! - [`harness`] — fork isolation: one child per probe, its exit status the
//!   measurement (#5), including termination by SIGSYS (#6) and the timeout
//!   from the probe's risk class (#7)
//! - [`verdict`] — how the child ended, as the fingerprint records it:
//!   `killed` is SIGSYS and nothing else (#6); `unimplemented` is the
//!   absent errno from a kernel that may lack the entry point (#8)
//! - [`cell`] — the environment cell as the probe sees it: architecture,
//!   kernel, LSM (#8)
//! - [`measurement`] — the run over the corpus and the document it emits,
//!   the probe-side half of a fingerprint (#8)
//! - [`effects`] — the side-effect declaration every probe carries, and the
//!   sentinel the engine refuses to run (#9)
//! - [`residual`] — the five residual classes counted directly around each
//!   probe, the module snapshot, and the end-of-run janitor (#9)

pub mod cell;
pub mod effects;
pub mod harness;
pub mod measurement;
pub mod probe;
pub mod residual;
pub mod verdict;

pub use cell::{Arch, Cell, KernelVersion, Lsm};
pub use effects::{ResidualClass, SideEffects};
pub use harness::{run_isolated, Outcome};
pub use measurement::{measure, Measurement, ProbeResult, Unmeasurable, Unmeasured};
/// Re-exported because `RawResult` is `Result<(), Errno>`: the corpus cannot
/// express a probe's error path without it, and should not have to depend on
/// `nix` directly to author one.
pub use nix::errno::Errno;
pub use probe::{
    Applicability, Capability, Isolates, KernelDependency, Oracle, Probe, ProbeFn, RawResult,
    RiskClass,
};
pub use verdict::{classify, Measured, Verdict};

/// One-time engine set-up, before any probe runs.
///
/// Marks the process non-dumpable, which every child inherits. A child
/// killed by SIGSYS or SIGSEGV would otherwise dump core, and inside a
/// container `core_pattern` — not namespaced — commonly pipes that to the
/// host's crash handler: a side effect on the node this instrument must not
/// have, and a stall of a second or more per crash while the handler runs.
/// `RLIMIT_CORE = 0` does not do this job: the kernel consults the limit
/// only for cores written to a file, not for piped ones (Ubuntu's apport,
/// systemd-coredump). `PR_SET_DUMPABLE = 0` is the gate for both. One
/// `prctl` at start-up, recorded in `baseline/`.
///
/// Side effect to know about: a non-dumpable process cannot be attached to
/// by a same-uid tracer after the fact (`strace -p`). A tracer present from
/// exec — `strace ./caliper-probe` — is unaffected.
pub fn init() -> nix::Result<()> {
    // SAFETY: prctl with a constant option and a scalar argument.
    let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if r == 0 {
        Ok(())
    } else {
        Err(nix::errno::Errno::last())
    }
}
