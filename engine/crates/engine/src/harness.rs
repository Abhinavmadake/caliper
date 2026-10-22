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
/// How long a SIGKILLed child may take to be reapable. A child stuck in an
/// uninterruptible sleep would otherwise hang the run (#99).
const KILL_GRACE: Duration = Duration::from_secs(10);

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
    /// A helper call before the probed operation failed with this errno:
    /// not the probed operation's answer (#96, #99).
    SetupFailed(i32),
    /// The child died of this signal before reaching the probed operation,
    /// for instance a filter killing a helper: not a kill of the operation.
    SetupKilled(i32),
    /// The child exceeded the timeout before reaching the probed operation:
    /// a helper hung, not the operation.
    SetupTimedOut,
    /// The child exceeded the timeout and was still not reapable
    /// [`KILL_GRACE`] after SIGKILL. It outlives the probe, so neither this
    /// probe's snapshots nor any later probe's are its own (#99).
    Unreaped,
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

/// Where a probe's child got to, shared with the parent through an
/// anonymous shared page mapped for that one run: a probe with helper calls
/// marks [`setup`] first and [`probing`] just before the operation it
/// measures. Plain stores, so marking issues no syscall. The page's address
/// is thread-local, which fork copies into the child, so concurrent callers
/// (libtest's threads) each see only their own run.
const STAGE_PROBING: u8 = 0;
const STAGE_SETUP: u8 = 1;

thread_local! {
    static STAGE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn stage_at(addr: usize) -> Option<&'static std::sync::atomic::AtomicU8> {
    // SAFETY: a live, page-aligned mapping of this run, accessed atomically.
    (addr != 0).then(|| unsafe { &*(addr as *const std::sync::atomic::AtomicU8) })
}

fn mark(value: u8) {
    if let Some(s) = stage_at(STAGE.with(std::cell::Cell::get)) {
        s.store(value, std::sync::atomic::Ordering::SeqCst);
    }
}

/// In a probe's child: the calls that follow are helpers, not the measured
/// operation. Their failure or a death among them is recorded as such.
pub fn setup() {
    mark(STAGE_SETUP);
}

/// In a probe's child: the next call is the measured operation.
pub fn probing() {
    mark(STAGE_PROBING);
}

/// Run `f` in a forked child, bounded by `timeout`, and report how the
/// child ended. `run_isolated` is this with the probe's function and risk
/// class; the janitor passes a removal.
pub fn run_isolated_with(f: &dyn Fn() -> RawResult, timeout: Duration) -> nix::Result<Outcome> {
    // SAFETY: a fresh anonymous shared page, unmapped below.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let addr = if page == libc::MAP_FAILED {
        0
    } else {
        page as usize
    };
    STAGE.with(|s| s.set(addr));
    let outcome = fork_and_wait(f, timeout);
    STAGE.with(|s| s.set(0));
    let in_setup =
        stage_at(addr).is_some_and(|s| s.load(std::sync::atomic::Ordering::SeqCst) == STAGE_SETUP);
    if addr != 0 {
        // SAFETY: the page mapped above. A child that shared it is reaped,
        // or unreaped and keeping its own mapping.
        unsafe { libc::munmap(page, 4096) };
    }
    Ok(match outcome? {
        Outcome::Returned { errno } if in_setup => Outcome::Fault(Fault::SetupFailed(errno)),
        Outcome::Signaled { signal } if in_setup => Outcome::Fault(Fault::SetupKilled(signal)),
        Outcome::TimedOut if in_setup => Outcome::Fault(Fault::SetupTimedOut),
        other => other,
    })
}

fn fork_and_wait(f: &dyn Fn() -> RawResult, timeout: Duration) -> nix::Result<Outcome> {
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
        let _ = reap(pid);
        return Err(err);
    }
    let outcome = wait_bounded(Pid::from_raw(pid), pidfd, timeout);
    // SAFETY: pidfd is a descriptor this function owns and closes once.
    unsafe { libc::close(pidfd) };
    outcome
}

/// The child. Never returns.
fn child(f: &dyn Fn() -> RawResult) -> ! {
    // The hook runs before any unwind or abort. Under panic = "abort" a
    // panic would otherwise end in musl's abort(), whose tkill a strict
    // profile answers with SIGSYS, read as a seccomp kill (#95). The
    // closure is zero-sized, so the Box does not allocate.
    std::panic::set_hook(Box::new(|_| unsafe { libc::_exit(EXIT_PANIC) }));
    let code = match f() {
        Ok(()) => 0,
        // nix maps an errno it has no name for to 0; the raw value is still
        // in errno, from the call that failed (#99).
        // SAFETY: reads this thread's errno.
        Err(errno) => match (errno as i32, unsafe { *libc::__errno_location() }) {
            (0, n @ 1..=MAX_ERRNO) | (n @ 1..=MAX_ERRNO, _) => n,
            _ => EXIT_ERRNO_RANGE,
        },
    };
    // SAFETY: _exit is async-signal-safe and runs no destructors, which is
    // the point: the child must not touch parent state on the way out.
    unsafe { libc::_exit(code) }
}

/// Wait for the child up to `timeout`, killing it on expiry.
fn wait_bounded(pid: Pid, pidfd: libc::c_int, timeout: Duration) -> nix::Result<Outcome> {
    let ready = match poll_exit(pidfd, timeout) {
        Ok(ready) => ready,
        Err(err) => {
            // The child is still ours to reap: kill it first, so a poll
            // failure leaves neither a running child nor a zombie (#99).
            // The pidfd cannot be polled, so the reap is unbounded, as when
            // pidfd_open fails.
            let _ = kill(pid, Signal::SIGKILL);
            let _ = reap(pid.as_raw());
            return Err(err);
        }
    };
    if !ready {
        return Ok(if kill_and_reap(pid, pidfd)? {
            Outcome::TimedOut
        } else {
            Outcome::Fault(Fault::Unreaped)
        });
    }
    let status = reap(pid.as_raw())?;
    Ok(if libc::WIFEXITED(status) {
        match libc::WEXITSTATUS(status) {
            0 => Outcome::Returned { errno: 0 },
            n @ 1..=MAX_ERRNO => Outcome::Returned { errno: n },
            EXIT_PANIC => Outcome::Fault(Fault::Panicked),
            EXIT_ERRNO_RANGE => Outcome::Fault(Fault::ErrnoOutOfRange),
            n => Outcome::Fault(Fault::UnknownExit(n)),
        }
    } else if libc::WIFSIGNALED(status) {
        // Raw signal number: nix's waitpid rejects real-time signals, which
        // made such a death a harness error (#99).
        Outcome::Signaled {
            signal: libc::WTERMSIG(status),
        }
    } else {
        // Stopped/continued are not requested (no WUNTRACED/WCONTINUED), so
        // this does not happen; recorded rather than assumed.
        Outcome::Fault(Fault::UnknownExit(-1))
    })
}

/// Whether the pidfd became readable (the child exited) within `timeout`.
fn poll_exit(pidfd: libc::c_int, timeout: Duration) -> nix::Result<bool> {
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
    loop {
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
            0 => return Ok(false),
            r if r > 0 => return Ok(true),
            _ if Errno::last() == Errno::EINTR => continue,
            _ => return Err(Errno::last()),
        }
    }
}

/// SIGKILL the child and reap it, waiting at most [`KILL_GRACE`]. `false`
/// is a child still not reapable, left rather than waited on into a hang.
fn kill_and_reap(pid: Pid, pidfd: libc::c_int) -> nix::Result<bool> {
    kill(pid, Signal::SIGKILL)?;
    if !poll_exit(pidfd, KILL_GRACE)? {
        return Ok(false);
    }
    reap(pid.as_raw()).map(|_| true)
}

/// waitpid for one child, retried on EINTR; the raw wait status.
fn reap(pid: libc::pid_t) -> nix::Result<libc::c_int> {
    let mut status = 0;
    loop {
        // SAFETY: a child of this process and a valid status pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return Ok(status);
        }
        if Errno::last() != Errno::EINTR {
            return Err(Errno::last());
        }
    }
}
