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

use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use crate::probe::Probe;

/// Largest errno the exit-code encoding carries. Linux errnos on x86_64
/// and aarch64 stop at 133 (`EHWPOISON`); the two codes above the range
/// are reserved for harness faults.
const MAX_ERRNO: i32 = 200;
/// The probe function panicked. Not a measurement of anything.
const EXIT_PANIC: i32 = 253;
/// The probe returned an errno outside `1..=MAX_ERRNO`.
const EXIT_ERRNO_RANGE: i32 = 254;

/// How the child ended: the wait status decoded, and nothing more. Turning
/// this into a verdict is #8's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    // SAFETY: the engine is single-threaded, and the child calls nothing but
    // the probe and _exit. See the module comment for why this is fork(2)
    // and not a raw clone.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Errno::last());
    }
    if pid == 0 {
        child(probe)
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
    let outcome = wait_bounded(Pid::from_raw(pid), pidfd, probe.risk.timeout());
    // SAFETY: pidfd is a descriptor this function owns and closes once.
    unsafe { libc::close(pidfd) };
    outcome
}

/// The child. Never returns.
fn child(probe: &Probe) -> ! {
    // catch_unwind is a no-op under panic = "abort" (the image profile) and
    // turns a debug-build panic into a recorded fault rather than an unwind
    // through the harness. It allocates nothing unless a panic occurs.
    let code = match std::panic::catch_unwind(probe.run) {
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
    let ts = libc::timespec {
        tv_sec: timeout.as_secs() as _,
        tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
    };
    let ready = loop {
        // SAFETY: one valid pollfd, a valid timespec, no sigmask.
        let r = unsafe { libc::ppoll(&mut pfd, 1, &ts, std::ptr::null()) };
        match r {
            0 => break false,
            r if r > 0 => break true,
            // The engine installs no handlers, so EINTR is rare; restarting
            // with the full timeout is the simple, slightly generous choice.
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
