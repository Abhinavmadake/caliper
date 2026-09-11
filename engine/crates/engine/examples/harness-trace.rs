//! One probe through the harness, for strace. Shows what the parent issues
//! between `clone` and the child's syscall — which should be nothing — and
//! what the child issues, which should be the probe and `exit_group`:
//!
//!     strace -f target/<triple>/debug/examples/harness-trace
//!
//! With `panic` as the argument the probe panics instead. Built `--release`
//! this is the image's `panic = "abort"` profile, which `cargo test` never
//! uses (Cargo forces unwind for test targets), so this is where the
//! SIGABRT shape of a panicking probe is actually observable:
//!
//!     target/<triple>/release/examples/harness-trace panic

use std::time::Duration;

use caliper_engine::{run_isolated, Probe, RawResult, RiskClass};

fn getppid() -> RawResult {
    unsafe { libc::syscall(libc::SYS_getppid) };
    Ok(())
}

fn panics() -> RawResult {
    panic!("probe bug");
}

fn main() {
    caliper_engine::init().unwrap();
    let panic = std::env::args().nth(1).as_deref() == Some("panic");
    if panic {
        std::panic::set_hook(Box::new(|_| {}));
    }
    let probe = Probe {
        id: "trace",
        family: "test",
        description: "getppid in a child",
        risk: RiskClass::new(true, Duration::from_secs(1)),
        run: if panic { panics } else { getppid },
    };
    let out = run_isolated(&probe).unwrap();
    // One write, after the measurement.
    println!("{out:?}");
}
