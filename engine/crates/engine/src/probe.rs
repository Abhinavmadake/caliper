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

//! A probe: one kernel operation at argument granularity, and what the
//! engine needs to know to run it safely. The fields follow
//! `spec/probe.md`; every one of them is here (#10), and each probe is
//! authored complete — the spec is explicit that attribution metadata is
//! not deferred.

use std::time::Duration;

use nix::errno::Errno;
use serde::{Serialize, Serializer};

use crate::cell::{Arch, KernelVersion};
use crate::effects::SideEffects;

/// What the probed operation returned — the kernel's answer, untouched.
/// `Ok` means the operation succeeded; `Err` carries the errno as returned.
/// Whether success or a given errno is a finding is not the probe's business
/// and not the engine's either (§6.1): that is attribution, downstream.
pub type RawResult = Result<(), Errno>;

/// The operation. Runs in a forked child with nothing between `clone` and
/// this call, so the rules are strict: no allocation, no `std` I/O, no
/// panics, nothing but the syscalls the probe is about. A libc wrapper can
/// hide a second syscall — musl's `socket()` retries without `SOCK_CLOEXEC`
/// on `EINVAL` — so prefer `libc::syscall(SYS_…)` where the exact sequence
/// matters to the oracle.
pub type ProbeFn = fn() -> RawResult;

/// Whether the probe requires fork isolation, and its timeout
/// (`spec/probe.md`, risk class).
///
/// The engine forks for every probe regardless of `requires_fork`: a probe
/// that declares it does not need the rollback still must not be able to end
/// the run, and isolation changes nothing about what the child can reach.
/// The field records the probe author's claim about the probe's side
/// effects, which is what the corpus review (#18) checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RiskClass {
    pub requires_fork: bool,
    /// Wall-clock budget for the child, in milliseconds. Exceeding it is the
    /// `timed-out` verdict; hung and slow are not distinguished
    /// (`spec/probe.md`, decision 2). Travels in the fingerprint so a
    /// `timed-out` verdict is readable against the deadline that produced it.
    pub timeout_ms: u64,
}

impl RiskClass {
    pub const fn new(requires_fork: bool, timeout: Duration) -> Self {
        Self {
            requires_fork,
            timeout_ms: timeout.as_millis() as u64,
        }
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// Which architectures the entry point exists on (`spec/probe.md`,
/// architecture applicability). A probe outside its set is recorded
/// `not-applicable` without being run, so the diff engine never sees
/// architecture as policy.
///
/// Presence that is a kernel property rather than an architecture property
/// (the 32-bit compatibility ABI on arm64) is not declared here: the spec
/// has it detected at run time, which is what [`KernelDependency`] and the
/// `unimplemented` verdict are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Applicability {
    All,
    Only(&'static [Arch]),
}

impl Applicability {
    pub fn includes(&self, arch: Arch) -> bool {
        match self {
            Applicability::All => true,
            Applicability::Only(set) => set.contains(&arch),
        }
    }
}

/// What the entry point needs from the kernel, and how the kernel answers
/// when it lacks it (`spec/probe.md`, kernel dependency). This is what
/// separates `unimplemented` from `denied` in [`crate::verdict::classify`]:
/// an address family the kernel does not build is not a policy finding.
///
/// The rule is structural, not a judgement. `absent_errno` is what the
/// kernel returns when the entry point is missing — `ENOSYS` for a syscall,
/// `EAFNOSUPPORT` for a family, `EPROTONOSUPPORT` for a netlink family.
/// Seeing it is `unimplemented` only if this kernel *may* lack the entry
/// point: it is older than `since`, or presence is a configuration or
/// module property that no version number settles (`since == None`).
/// Seeing it from a kernel that is known to implement the entry point is a
/// filter answering in the kernel's voice — `denied`, per spec/probe.md
/// ("`ENOSYS` from a syscall the cell's kernel implements is a filter").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KernelDependency {
    /// The kernel release the entry point appeared in, as (major, minor).
    /// `None` when presence is decided by configuration or a module rather
    /// than by version.
    pub since: Option<(u32, u32)>,
    /// The errno the kernel produces when the entry point is absent. `None`
    /// for an entry point every supported kernel has: any errno is then a
    /// denial. Serialised as the raw integer, like every errno in the
    /// fingerprint.
    #[serde(serialize_with = "errno_as_int")]
    pub absent_errno: Option<Errno>,
}

impl KernelDependency {
    /// Every kernel the project supports (6.1 or later, §10) has the entry
    /// point; nothing it returns can mean "absent".
    pub const NONE: KernelDependency = KernelDependency {
        since: None,
        absent_errno: None,
    };

    /// Whether `errno`, from `running`, means the entry point is absent
    /// rather than filtered.
    pub fn means_absent(&self, errno: i32, running: KernelVersion) -> bool {
        match (self.absent_errno, self.since) {
            (Some(e), since) if e as i32 == errno => match since {
                Some(v) => !running.at_least(v),
                None => true,
            },
            _ => false,
        }
    }
}

fn errno_as_int<S: Serializer>(e: &Option<Errno>, s: S) -> Result<S::Ok, S::Error> {
    match e {
        Some(e) => s.serialize_some(&(*e as i32)),
        None => s.serialize_none(),
    }
}

/// The errno oracle (`spec/probe.md`): the argument set is chosen so that,
/// if the call reaches the kernel past every filter, a specific error is
/// structurally guaranteed — or the call succeeds. Receiving something else
/// proves interception before the point at which the kernel would have
/// produced it; what that isolates is per syscall and is recorded here,
/// with the reasoning.
///
/// The oracle is what makes a guaranteed errno `permitted` rather than
/// `denied` in [`crate::verdict::classify`]: the call was not intercepted.
/// The errno is still recorded raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Oracle {
    /// The errno the argument set guarantees when nothing intercepts the
    /// call. `None`: the call succeeds. Serialised as the raw integer.
    #[serde(serialize_with = "errno_as_int")]
    pub guarantees: Option<Errno>,
    /// What an `EPERM` against the guarantee separates.
    pub isolates: Isolates,
    /// The hook-order argument: where in the kernel the guaranteed answer is
    /// produced, and what runs before it. Goes onto the fingerprint's
    /// `attribution.reason` verbatim, so it is written for a reader.
    pub reason: &'static str,
}

/// Which mechanism an `EPERM` against the oracle can be pinned to. The
/// mechanism ordering is fixed by the kernel: seccomp runs at syscall entry,
/// before any argument is looked at; LSM hooks run inside the syscall, at
/// points that differ per call; capability checks are the syscall's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Isolates {
    /// The guaranteed answer is produced before any LSM hook or capability
    /// check — descriptor resolution, an out-of-range family, a flag the
    /// syscall rejects up front — so only a filter at entry can pre-empt it.
    Seccomp,
    /// The guaranteed answer is produced after the LSM hook, so `EPERM`
    /// could be either; it is not the syscall's own capability check.
    SeccompOrLsm,
    /// `EPERM` is what the syscall itself returns when the caller lacks the
    /// capability, so nothing separates a filter from a dropped capability
    /// from inside the container. The capability field is the correlate.
    Undecidable,
}

/// A Linux capability, as the operation's documented requirement
/// (`spec/probe.md`, capability requirement), for correlation against the
/// effective and bounding sets. Only the capabilities the corpus names are
/// listed; add a variant, serialised by its kernel name, when a probe needs
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Capability {
    #[serde(rename = "CAP_NET_ADMIN")]
    NetAdmin,
    #[serde(rename = "CAP_NET_RAW")]
    NetRaw,
    #[serde(rename = "CAP_SYS_ADMIN")]
    SysAdmin,
}

#[derive(Debug, Clone, Serialize)]
pub struct Probe {
    /// Stable identity; the key the diff engine joins on across runs.
    pub id: &'static str,
    /// Entry family (`socket`, `io_uring`, `mount`, …).
    pub family: &'static str,
    pub description: &'static str,
    pub risk: RiskClass,
    pub arch: Applicability,
    pub kernel: KernelDependency,
    /// The argument set's guaranteed answer and what an `EPERM` against it
    /// isolates.
    pub oracle: Oracle,
    /// The operation's documented capability, `None` where it needs none.
    pub capability: Option<Capability>,
    /// What the probe creates and how it is reclaimed (`crate::effects`).
    /// Defaults to `Undeclared`, which the engine refuses to run.
    pub effects: SideEffects,
    /// The operation. An output of `--dump-corpus` cannot carry a function,
    /// and the JSON is a view of the corpus, not a way to run it.
    #[serde(skip)]
    pub run: ProbeFn,
}
