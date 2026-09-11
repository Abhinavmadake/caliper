//! Fork isolation (#5): the child's exit status is the measurement, a crash
//! does not lose the run, descriptor-shaped side effects die with the child.
//! Linux only; `cargo test --target <arch>-unknown-linux-musl`.

#![cfg(target_os = "linux")]

use std::time::Duration;

use caliper_engine::harness::{Fault, Outcome};
use caliper_engine::{run_isolated, Probe, RawResult, RiskClass};
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
        description: id,
        risk: RISK,
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
    assert_eq!(bad, Outcome::Returned { errno: Errno::EBADF as i32 });
}

#[test]
fn a_crashing_probe_does_not_lose_the_run() {
    let crashed = run_isolated(&probe("segv", crashes)).unwrap();
    assert!(crashed.signaled_by(Signal::SIGSEGV), "got {crashed:?}");

    // The run continues: the next probe measures normally.
    let next = run_isolated(&probe("after-crash", ebadf)).unwrap();
    assert_eq!(next, Outcome::Returned { errno: Errno::EBADF as i32 });
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
