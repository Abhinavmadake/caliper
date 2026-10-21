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

//! Fork isolation (#5): the child's exit status is the measurement, a crash
//! does not lose the run, descriptor-shaped side effects die with the child.
//! Linux only; `cargo test --target <arch>-unknown-linux-musl`.

#![cfg(target_os = "linux")]

use std::time::Duration;

use caliper_engine::harness::{Fault, Outcome};
use caliper_engine::{
    run_isolated, Applicability, Isolates, KernelDependency, Oracle, Probe, RawResult, RiskClass,
    SideEffects, Status,
};
use nix::errno::Errno;
use nix::sys::signal::Signal;

const RISK: RiskClass = RiskClass::new(true, Duration::from_secs(5));

fn probe(id: &'static str, run: fn() -> RawResult) -> Probe {
    // What caliper-probe's main does once; idempotent, so once per probe
    // here. Without it a crashing child goes through the node's core
    // handler — a second per crash under apport.
    caliper_engine::init().unwrap();
    Probe {
        id,
        family: "test",
        status: Status::Committed,
        description: id,
        risk: RISK,
        arch: Applicability::All,
        kernel: KernelDependency::NONE,
        oracle: Oracle {
            guarantees: None,
            isolates: Isolates::Seccomp,
            reason: "test probe",
        },
        capability: None,
        effects: SideEffects::NONE,
        run,
    }
}

/// Raw syscall result → the probe's answer. Every test probe goes through
/// libc::syscall so exactly one syscall is what the child issues.
fn raw(r: libc::c_long) -> RawResult {
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

fn succeeds() -> RawResult {
    raw(unsafe { libc::syscall(libc::SYS_getpid) })
}

fn ebadf() -> RawResult {
    // close(2) on an invalid descriptor: EBADF is structurally guaranteed —
    // the shape every errno oracle in the corpus has.
    raw(unsafe { libc::syscall(libc::SYS_close, -1) })
}

fn crashes() -> RawResult {
    let p: *mut u8 = std::ptr::null_mut();
    unsafe { std::ptr::write_volatile(p, 1) };
    Ok(())
}

/// Abstract unix socket name: no filesystem residue, freed when the last
/// descriptor referring to the socket is gone.
const ABSTRACT: &[u8] = b"\0caliper.harness.reclaim";

fn addr() -> (libc::sockaddr_un, libc::socklen_t) {
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in ABSTRACT.iter().enumerate() {
        sa.sun_path[i] = *b as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + ABSTRACT.len();
    (sa, len as libc::socklen_t)
}

/// Binds the abstract name and exits without closing anything.
fn leaks_a_bound_socket() -> RawResult {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(Errno::last());
    }
    let (sa, len) = addr();
    raw(unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len) }.into())
}

#[test]
fn success_and_errno_come_back_in_the_exit_status() {
    let ok = run_isolated(&probe("getpid", succeeds)).unwrap();
    assert_eq!(ok, Outcome::Returned { errno: 0 });

    let bad = run_isolated(&probe("close-bad-fd", ebadf)).unwrap();
    assert_eq!(
        bad,
        Outcome::Returned {
            errno: Errno::EBADF as i32
        }
    );
}

#[test]
fn a_crashing_probe_does_not_lose_the_run() {
    let crashed = run_isolated(&probe("segv", crashes)).unwrap();
    assert!(crashed.signaled_by(Signal::SIGSEGV), "got {crashed:?}");

    // The run continues: the next probe measures normally.
    let next = run_isolated(&probe("after-crash", ebadf)).unwrap();
    assert_eq!(
        next,
        Outcome::Returned {
            errno: Errno::EBADF as i32
        }
    );
}

#[test]
fn descriptor_shaped_side_effects_die_with_the_child() {
    let out = run_isolated(&probe("leak-socket", leaks_a_bound_socket)).unwrap();
    assert_eq!(out, Outcome::Returned { errno: 0 }, "child could not bind");

    // The child is reaped, its table torn down, the abstract name free: the
    // parent can bind it. Had it survived, this would be EADDRINUSE.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);
    let (sa, len) = addr();
    let r = unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len) };
    let err = Errno::last();
    unsafe { libc::close(fd) };
    assert_eq!(r, 0, "abstract name still bound after child exit: {err}");
    // (The parent's own table is not checked here: tests share one process
    // and run concurrently, so another test's pidfd may be open at any
    // moment. The pidfd close is visible in `examples/harness-trace`.)
}

#[test]
fn an_errno_the_encoding_cannot_carry_is_a_fault_not_a_measurement() {
    fn out_of_range() -> RawResult {
        Err(Errno::from_raw(4095))
    }
    let out = run_isolated(&probe("errno-4095", out_of_range)).unwrap();
    assert_eq!(out, Outcome::Fault(Fault::ErrnoOutOfRange));
}

fn dies_of_a_realtime_signal() -> RawResult {
    let sig = libc::SIGRTMIN() + 1;
    raw(unsafe { libc::syscall(libc::SYS_kill, libc::syscall(libc::SYS_getpid), sig) })
}

fn errno_nix_cannot_name() -> RawResult {
    // 150 is inside the exit-code encoding but no errno nix knows.
    unsafe { *libc::__errno_location() = 150 };
    Err(Errno::UnknownErrno)
}

#[test]
fn a_realtime_signal_death_is_recorded_not_a_harness_error() {
    let out = run_isolated(&probe("rt-signal", dies_of_a_realtime_signal)).unwrap();
    assert_eq!(
        out,
        Outcome::Signaled {
            signal: libc::SIGRTMIN() + 1
        }
    );
}

#[test]
fn an_errno_nix_cannot_name_keeps_its_value() {
    let out = run_isolated(&probe("errno-150", errno_nix_cannot_name)).unwrap();
    assert_eq!(out, Outcome::Returned { errno: 150 });
}

fn fails_in_setup() -> RawResult {
    caliper_engine::harness::setup();
    raw(unsafe { libc::syscall(libc::SYS_close, -1) })
}

fn dies_in_setup() -> RawResult {
    caliper_engine::harness::setup();
    raw(unsafe {
        libc::syscall(
            libc::SYS_kill,
            libc::syscall(libc::SYS_getpid),
            libc::SIGKILL,
        )
    })
}

fn setup_then_probed_errno() -> RawResult {
    caliper_engine::harness::setup();
    caliper_engine::harness::probing();
    ebadf()
}

#[test]
fn a_failure_or_death_in_setup_is_not_the_probed_answer() {
    let failed = run_isolated(&probe("setup-fails", fails_in_setup)).unwrap();
    assert_eq!(failed, Outcome::Fault(Fault::SetupFailed(libc::EBADF)));
    let killed = run_isolated(&probe("setup-dies", dies_in_setup)).unwrap();
    assert_eq!(killed, Outcome::Fault(Fault::SetupKilled(libc::SIGKILL)));
    // Past setup, the errno is the probed operation's again.
    let probed = run_isolated(&probe("setup-then-probe", setup_then_probed_errno)).unwrap();
    assert_eq!(probed, Outcome::Returned { errno: libc::EBADF });
    // And the next probe starts clean.
    let next = run_isolated(&probe("after-setup", ebadf)).unwrap();
    assert_eq!(next, Outcome::Returned { errno: libc::EBADF });
}

fn hangs_in_setup() -> RawResult {
    caliper_engine::harness::setup();
    raw(unsafe { libc::pause() }.into())
}

fn hangs_when_probed() -> RawResult {
    caliper_engine::harness::setup();
    caliper_engine::harness::probing();
    raw(unsafe { libc::pause() }.into())
}

#[test]
fn a_timeout_in_setup_is_not_the_probed_operation_timing_out() {
    let short = |id, run| Probe {
        risk: RiskClass::new(true, Duration::from_millis(200)),
        ..probe(id, run)
    };
    let setup = run_isolated(&short("setup-hangs", hangs_in_setup)).unwrap();
    assert_eq!(setup, Outcome::Fault(Fault::SetupTimedOut));
    let probed = run_isolated(&short("probe-hangs", hangs_when_probed)).unwrap();
    assert_eq!(probed, Outcome::TimedOut);
}
