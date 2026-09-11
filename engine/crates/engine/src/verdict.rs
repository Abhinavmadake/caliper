//! The verdict: the fingerprint's per-probe result (`spec/fingerprint.md`),
//! a fact about how the kernel answered and never an interpretation of it.
//!
//! What this module decides is fixed by the spec's enumeration and by #6:
//! a child the kernel terminated with SIGSYS is `killed`, and only that
//! signal is. SIGABRT, SIGSEGV and the rest are the probe crashing, which
//! is a fault of the instrument and not a measurement. Separating
//! `unimplemented` from `denied` needs the probe's kernel-dependency field
//! and the cell's kernel, and `not-applicable` needs its applicability
//! field; both are #8 and arrive as arguments to [`classify`], not as a
//! change to it.

use nix::errno::Errno;
use serde::Serialize;

use crate::harness::{Fault, Outcome};

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
/// `Err` is not a verdict and must not be recorded as one: a crashing or
/// panicking probe on a permissive node would otherwise read as a hardened
/// one.
pub fn classify(outcome: Outcome) -> Result<Measured, NotMeasured> {
    let sigsys = libc::SIGSYS;
    Ok(match outcome {
        Outcome::Returned { errno: 0 } => Measured {
            verdict: Verdict::Permitted,
            errno: 0,
        },
        // #8 separates `unimplemented` from `denied` here, with the probe's
        // kernel dependency in hand. Until then an errno is a denial.
        Outcome::Returned { errno } => Measured {
            verdict: Verdict::Denied,
            errno,
        },
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
