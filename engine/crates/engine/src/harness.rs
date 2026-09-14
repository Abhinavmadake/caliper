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

//! Fork isolation (#5). One child per probe; the child's exit status is the
//! measurement.
//!
//! The child is made with `fork(2)` — musl's wrapper, not a raw `clone`.
//! That is deliberate and was learned the hard way: musl caches the thread
//! id, and `abort()`/`raise()` deliver their signal with `tkill` to the
//! cached id. A raw clone leaves the parent's id in the child, so a child
//! that aborted (a probe panicking under `panic = "abort"`) killed the
//! parent. `fork()` fixes the id up in the child, at the cost of two
//! syscalls there before the probe — `set_tid_address` and `rt_sigprocmask`,
//! both already in the engine's start-up set — and of `pidfd_open` in the
//! parent, which gives the bounded wait a descriptor to `ppoll` on: the
//! timeout #7 needs, without signals, using a syscall already in the
//! baseline.
//!
//! The child calls the probe and `_exit`s with the result encoded in the
//! exit code: `0` for success, the errno otherwise. It allocates nothing and
//! issues no syscall of its own but `exit_group`. If the kernel terminates it
//! instead — SIGSYS from a `KILL_PROCESS` filter (#6), SIGSEGV from a crash —
//! the wait status says so, and the parent carries on to the next probe.
//!
//! The parent's syscalls per probe: `clone` (musl's fork), `pidfd_open`,
//! `ppoll`, `wait4`, `close`, and `kill` on a timeout. All are in groups 1–2
//! of the hardened profile.
//!
//! The same child is what the end-of-run janitor (#9) removes objects
//! with, one per object: a removal runs under the same filter the probe
//! did, so it can be killed the same way, and a killed child is a record
//! where a killed parent is a lost run.

use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use crate::probe::{Probe, RawResult};

/// Largest errno the exit-code encoding carries. Linux errnos on x86_64
/// and aarch64 stop at 133 (`EHWPOISON`); the gap up to 200 is headroom,
/// and 253/254 are reserved for harness faults.
const MAX_ERRNO: i32 = 200;
/// The probe function panicked. Not a measurement of anything.
const EXIT_PANIC: i32 = 253;
/// The probe returned an errno outside `1..=MAX_ERRNO`.
const EXIT_ERRNO_RANGE: i32 = 254;

/// How the child ended: the wait status decoded, and nothing more. Turning
/// this into a verdict is #8's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// The operation returned. `errno == 0` means it succeeded.
    Returned { errno: i32 },
    /// The kernel terminated the child with this signal. `SIGSYS` is a
    /// seccomp `KILL_PROCESS`/`KILL_THREAD`; anything else is the probe
    /// crashing. Raw signal number, so an unnamed one is still recorded.
    Signaled { signal: i32 },
    /// Exceeded the risk class's timeout and was killed by the parent.
    TimedOut,
    /// The harness could not measure: the probe panicked, or returned an
    /// errno the encoding cannot carry.
    Fault(Fault),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fault {
    Panicked,
    ErrnoOutOfRange,
    /// An exit code outside the encoding — cannot happen from this harness's
    /// own child, recorded rather than guessed at.
    UnknownExit(i32),
}

impl Outcome {
    pub fn signaled_by(&self, sig: Signal) -> bool {
        matches!(self, Outcome::Signaled { signal } if *signal == sig as i32)
    }
}

/// Run one probe in a forked child and report how the child ended.
///
/// `Err` is a failure of the harness itself (clone, wait or poll failing),
/// not of the probe. Sequential by design: the module snapshot and residual
/// state accounting (#9) depend on probes not overlapping.
pub fn run_isolated(probe: &Probe) -> nix::Result<Outcome> {
    run_isolated_with(&probe.run, probe.risk.timeout())
}

/// Run `f` in a forked child, bounded by `timeout`, and report how the
/// child ended. `run_isolated` is this with the probe's function and risk
/// class; the janitor passes a removal.
pub fn run_isolated_with(f: &dyn Fn() -> RawResult, timeout: Duration) -> nix::Result<Outcome> {
    // SAFETY: the engine is single-threaded, and the child calls nothing but
    // `f` and _exit. See the module comment for why this is fork(2) and not
    // a raw clone.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Errno::last());
    }
    if pid == 0 {
        child(f)
    }
    // SAFETY: plain syscall on a pid this process just created and has not
    // yet reaped, so it cannot have been recycled.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as libc::c_int;
    if pidfd < 0 {
        // The wait below is unbounded, so kill first: a harness fault must
        // not become a hang.
        let err = Errno::last();
        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        let _ = waitpid(Pid::from_raw(pid), None);
        return Err(err);
    }
    let outcome = wait_bounded(Pid::from_raw(pid), pidfd, timeout);
    // SAFETY: pidfd is a descriptor this function owns and closes once.
    unsafe { libc::close(pidfd) };
    outcome
}

/// The child. Never returns.
fn child(f: &dyn Fn() -> RawResult) -> ! {
    // catch_unwind is a no-op under panic = "abort" (the image profile) and
    // turns a debug-build panic into a recorded fault rather than an unwind
    // through the harness. It allocates nothing unless a panic occurs.
    // AssertUnwindSafe: nothing `f` borrows is used again in this process.
    let code = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(errno)) => match errno as i32 {
            n @ 1..=MAX_ERRNO => n,
            _ => EXIT_ERRNO_RANGE,
        },
        Err(_) => EXIT_PANIC,
    };
    // SAFETY: _exit is async-signal-safe and runs no destructors, which is
    // the point: the child must not touch parent state on the way out.
    unsafe { libc::_exit(code) }
}

/// Wait for the child up to `timeout`, killing it on expiry.
fn wait_bounded(pid: Pid, pidfd: libc::c_int, timeout: Duration) -> nix::Result<Outcome> {
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut ts = libc::timespec {
        tv_sec: timeout.as_secs() as _,
        tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
    };
    // Raw ppoll rather than the libc wrapper: the kernel writes the time
    // remaining back into the timespec, so an EINTR restart continues the
    // same deadline instead of starting a fresh one, and the risk class's
    // timeout is a hard bound — readable against a `timed-out` verdict, as
    // spec/probe.md decision 2 requires. musl's wrapper passes a copy.
    let ready = loop {
        // SAFETY: one valid pollfd, a valid mutable timespec, no sigmask.
        let r = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                &mut pfd as *mut libc::pollfd,
                1usize,
                &mut ts as *mut libc::timespec,
                std::ptr::null::<libc::sigset_t>(),
                std::mem::size_of::<libc::sigset_t>(),
            )
        };
        match r {
            0 => break false,
            r if r > 0 => break true,
            _ if Errno::last() == Errno::EINTR => continue,
            _ => return Err(Errno::last()),
        }
    };
    if !ready {
        kill(pid, Signal::SIGKILL)?;
        waitpid(pid, None)?;
        return Ok(Outcome::TimedOut);
    }
    Ok(match waitpid(pid, None)? {
        WaitStatus::Exited(_, 0) => Outcome::Returned { errno: 0 },
        WaitStatus::Exited(_, n @ 1..=MAX_ERRNO) => Outcome::Returned { errno: n },
        WaitStatus::Exited(_, EXIT_PANIC) => Outcome::Fault(Fault::Panicked),
        WaitStatus::Exited(_, EXIT_ERRNO_RANGE) => Outcome::Fault(Fault::ErrnoOutOfRange),
        WaitStatus::Exited(_, n) => Outcome::Fault(Fault::UnknownExit(n)),
        WaitStatus::Signaled(_, sig, _) => Outcome::Signaled { signal: sig as i32 },
        // Stopped/continued are not requested (no WUNTRACED/WCONTINUED), so
        // this does not happen; recorded rather than assumed.
        _ => Outcome::Fault(Fault::UnknownExit(-1)),
    })
}
