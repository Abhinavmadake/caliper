//! Timeouts (#7): a probe that blocks past its risk class's deadline is
//! killed and recorded `timed-out` — not `denied`, not a hang. Linux only.

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use caliper_engine::harness::Outcome;
use caliper_engine::verdict::{classify, Verdict};
use caliper_engine::{run_isolated, Probe, RawResult, RiskClass};

fn probe(id: &'static str, timeout: Duration, run: fn() -> RawResult) -> Probe {
    caliper_engine::init().unwrap();
    Probe {
        id,
        family: "test",
        description: id,
        risk: RiskClass::new(true, timeout),
        run,
    }
}

/// Blocks forever: `pause(2)` returns only on a signal, and the parent's
/// SIGKILL never returns to the caller.
fn hangs() -> RawResult {
    unsafe { libc::pause() };
    Ok(())
}

/// Sleeps for a bounded time — long against a short deadline, short
/// against a long one. What the harness sees is the same as `hangs` up to
/// the deadline; hung and slow are not distinguished (spec/probe.md).
fn slow_200ms() -> RawResult {
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 200_000_000,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    Ok(())
}

#[test]
fn a_hung_probe_is_killed_at_the_deadline_and_recorded_timed_out() {
    let deadline = Duration::from_millis(300);
    let started = Instant::now();
    let out = run_isolated(&probe("hangs", deadline, hangs)).unwrap();
    let took = started.elapsed();

    assert_eq!(out, Outcome::TimedOut);
    let m = classify(out).unwrap();
    assert_eq!(m.verdict, Verdict::TimedOut);
    assert_eq!(m.errno, 0);
    // Killed at the deadline, not stalled: generous upper bound for a
    // loaded CI runner, but nowhere near "indefinitely".
    assert!(took >= deadline, "returned before the deadline: {took:?}");
    assert!(
        took < deadline * 4,
        "stalled well past the deadline: {took:?}"
    );
}

#[test]
fn the_deadline_comes_from_the_risk_class() {
    // Same probe, two risk classes: over the deadline it is timed-out,
    // under it the sleep completes and the probe is permitted.
    let over = run_isolated(&probe("slow-tight", Duration::from_millis(50), slow_200ms)).unwrap();
    assert_eq!(over, Outcome::TimedOut);

    let under = run_isolated(&probe("slow-loose", Duration::from_secs(2), slow_200ms)).unwrap();
    assert_eq!(classify(under).unwrap().verdict, Verdict::Permitted);
}

#[test]
fn the_run_continues_after_a_timeout() {
    fn fine() -> RawResult {
        Ok(())
    }
    let _ = run_isolated(&probe("hangs", Duration::from_millis(50), hangs)).unwrap();
    let next = run_isolated(&probe("after", Duration::from_secs(1), fine)).unwrap();
    assert_eq!(classify(next).unwrap().verdict, Verdict::Permitted);
}
