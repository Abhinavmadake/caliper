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
//! `spec/probe.md`; the ones not yet here (errno oracle, capability
//! requirement, side effects, kernel dependency, applicability) arrive with
//! #8–#10, each as an addition to this struct.

use std::time::Duration;

use nix::errno::Errno;
use serde::Serialize;

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

#[derive(Debug, Clone, Serialize)]
pub struct Probe {
    /// Stable identity; the key the diff engine joins on across runs.
    pub id: &'static str,
    /// Entry family (`socket`, `io_uring`, `mount`, …).
    pub family: &'static str,
    pub description: &'static str,
    pub risk: RiskClass,
    /// The operation. An output of `--dump-corpus` cannot carry a function,
    /// and the JSON is a view of the corpus, not a way to run it.
    #[serde(skip)]
    pub run: ProbeFn,
}
