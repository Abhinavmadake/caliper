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

//! The verdict: the fingerprint's per-probe result (`spec/fingerprint.md`),
//! a fact about how the kernel answered and never an interpretation of it.
//!
//! What this module decides is fixed by the spec's enumeration and by #6
//! and #8: a child the kernel terminated with SIGSYS is `killed`, and only
//! that signal is — SIGABRT, SIGSEGV and the rest are the probe crashing,
//! which is a fault of the instrument and not a measurement. An errno is
//! `denied` unless the probe's kernel dependency says this kernel may lack
//! the entry point and the errno is the one absence produces, which is
//! `unimplemented` (#8; the rule is on [`KernelDependency`]).
//! `not-applicable` is decided before anything runs, in
//! [`crate::measurement::measure`], from the probe's applicability.
//!
//! Nothing here is attribution. Which mechanism produced a denial, and how
//! sure one can be, is the control plane's to compute from the oracle;
//! the engine records what the kernel said and the errno it said it with.

use nix::errno::Errno;
use serde::Serialize;

use crate::cell::KernelVersion;
use crate::harness::{Fault, Outcome};
use crate::probe::KernelDependency;

/// The six verdicts of `spec/fingerprint.md`, serialised by those names.
/// Additive-only within a format version: variants are never removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Permitted,
    Denied,
    Unimplemented,
    /// Terminated by SIGSYS: a seccomp `KILL_PROCESS` or `KILL_THREAD`
    /// (or `TRAP` with no handler, which is the same death).
    Killed,
    TimedOut,
    NotApplicable,
}

/// A verdict with the raw errno that produced it. `errno` is `0` for
/// `permitted`, and for the verdicts that have no errno because the child
/// did not return (`killed`, `timed-out`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Measured {
    pub verdict: Verdict,
    pub errno: i32,
}

/// Why an outcome is not a measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotMeasured {
    /// The child died of a signal other than SIGSYS: the probe crashed.
    Crashed {
        signal: i32,
    },
    Fault(Fault),
}

/// Turn how the child ended into what the kernel said.
///
/// `dep` is the probe's kernel dependency and `running` the cell's kernel,
/// `None` when its release did not parse: then every version-gated entry
/// point is one this kernel may lack, and the absent errno reads as
/// `unimplemented` — the reading that does not put a policy finding where
/// there may be none.
///
/// `Err` is not a verdict and must not be recorded as one: a crashing or
/// panicking probe on a permissive node would otherwise read as a hardened
/// one.
pub fn classify(
    outcome: Outcome,
    dep: &KernelDependency,
    running: Option<KernelVersion>,
) -> Result<Measured, NotMeasured> {
    let sigsys = libc::SIGSYS;
    Ok(match outcome {
        Outcome::Returned { errno: 0 } => Measured {
            verdict: Verdict::Permitted,
            errno: 0,
        },
        Outcome::Returned { errno } => {
            let absent = match running {
                Some(k) => dep.means_absent(errno, k),
                None => dep.absent_errno.is_some_and(|e| e as i32 == errno),
            };
            Measured {
                verdict: if absent {
                    Verdict::Unimplemented
                } else {
                    Verdict::Denied
                },
                errno,
            }
        }
        Outcome::Signaled { signal } if signal == sigsys => Measured {
            verdict: Verdict::Killed,
            errno: 0,
        },
        Outcome::Signaled { signal } => return Err(NotMeasured::Crashed { signal }),
        Outcome::TimedOut => Measured {
            verdict: Verdict::TimedOut,
            errno: 0,
        },
        Outcome::Fault(f) => return Err(NotMeasured::Fault(f)),
    })
}

impl Measured {
    /// The errno's name — `EPERM`, not "Operation not permitted" — for a
    /// human-readable report (#35). `None` when there is no errno, or the
    /// number has no name on this build.
    pub fn errno_name(&self) -> Option<String> {
        if self.errno == 0 {
            return None;
        }
        match Errno::from_raw(self.errno) {
            Errno::UnknownErrno => None,
            e => Some(format!("{e:?}")),
        }
    }
}
