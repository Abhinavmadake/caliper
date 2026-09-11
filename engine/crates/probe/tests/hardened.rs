//! The engine survives an exact seccomp allowlist (issue #4).
//!
//! `fixtures/seccomp/hardened.json` has three groups: the engine's start-up
//! set, the isolation harness set, and the set runc itself needs between
//! applying a profile and `execve`. The third is a property of the runtime.
//! This test applies the first two alone, from inside a forked child at the
//! last instant before `execve`, so what is measured is the engine and nothing
//! in front of it. Mismatch action is `kill_process`: a single syscall outside
//! the list terminates the child with SIGSYS, and the negative control below
//! shows the filter is actually enforced.
//!
//! Linux only, and meaningful only when the test binary and `caliper-probe`
//! are the musl build: `cargo test --target x86_64-unknown-linux-musl`.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::io::Cursor;

use seccompiler::{apply_filter, compile_from_json, BpfProgram, TargetArch};

const PROFILE: &str = include_str!("../../../fixtures/seccomp/hardened.json");
const PROBE: &str = env!("CARGO_BIN_EXE_caliper-probe");

/// Names listed for the other architecture. seccompiler rejects a name the
/// target architecture does not have, so they are dropped before compiling.
#[cfg(target_arch = "aarch64")]
const FOREIGN: &[&str] = &["arch_prctl", "poll"];
#[cfg(target_arch = "x86_64")]
const FOREIGN: &[&str] = &[];

#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;

/// Groups 1 and 2 of the profile as a seccompiler program, minus `drop`.
fn engine_filter(drop: Option<&str>) -> BpfProgram {
    let profile: serde_json::Value = serde_json::from_str(PROFILE).unwrap();
    let groups = profile["syscalls"].as_array().unwrap();
    let names: Vec<&str> = groups[..2]
        .iter()
        .flat_map(|g| g["names"].as_array().unwrap())
        .map(|n| n.as_str().unwrap())
        .filter(|n| !FOREIGN.contains(n) && Some(*n) != drop)
        .collect();
    let rules: Vec<serde_json::Value> = names
        .iter()
        .map(|n| serde_json::json!({ "syscall": n }))
        .collect();
    let spec = serde_json::json!({
        "engine": {
            "mismatch_action": "kill_process",
            "match_action": "allow",
            "filter": rules,
        }
    });
    let mut map = compile_from_json(Cursor::new(spec.to_string()), ARCH).unwrap();
    map.remove("engine").unwrap()
}

/// Fork, install `filter` in the child, exec `caliper-probe --noop`, and
/// return the raw wait status. Everything the child does after `fork` and
/// before `execve` is `apply_filter` (prctl + seccomp, both issued before
/// the filter is live) and `execv` itself.
fn run_under(filter: &BpfProgram) -> libc::c_int {
    let path = CString::new(PROBE).unwrap();
    let arg = CString::new("--noop").unwrap();
    let argv = [path.as_ptr(), arg.as_ptr(), std::ptr::null()];

    // SAFETY: the child calls only async-signal-safe functions before exec;
    // every allocation it needs was made above.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        if apply_filter(filter).is_err() {
            unsafe { libc::_exit(126) };
        }
        unsafe {
            libc::execv(path.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(r, pid, "waitpid failed");
    status
}

#[test]
fn noop_survives_the_engine_allowlist() {
    let status = run_under(&engine_filter(None));
    assert!(libc::WIFEXITED(status), "not a normal exit: status {status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), 0, "exec or run failed");
}

#[test]
fn allowlist_is_enforced() {
    // Remove one syscall std issues at start-up: the child must die of SIGSYS.
    let victim = if cfg!(target_arch = "x86_64") { "poll" } else { "ppoll" };
    let status = run_under(&engine_filter(Some(victim)));
    assert!(libc::WIFSIGNALED(status), "child was not killed: status {status:#x}");
    assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
}
