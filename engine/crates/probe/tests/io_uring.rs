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

//! The io_uring family (#12), end to end: the distinction the issue asks
//! for. Either io_uring is denied outright, and every opcode probe says so
//! with the same errno as the reach probe, or the ring is reachable and an
//! opcode is `permitted` or, absent from this kernel, `unimplemented 61`.
//! Which of the two holds depends on the test host's policy; the shape
//! holds on every cell.

#![cfg(target_os = "linux")]

mod common;

use std::collections::BTreeMap;
use std::io::Cursor;
use std::os::unix::process::CommandExt;
use std::process::Command;

use seccompiler::{apply_filter, compile_from_json, BpfProgram, TargetArch};

const PROBE: &str = env!("CARGO_BIN_EXE_caliper-probe");

#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;

fn results() -> BTreeMap<String, (String, u64)> {
    results_under(None)
}

fn results_under(filter: Option<BpfProgram>) -> BTreeMap<String, (String, u64)> {
    let (status, doc) = common::settled(|| {
        let mut cmd = Command::new(PROBE);
        if let Some(filter) = filter.clone() {
            // SAFETY: prctl and seccomp on a program built before the fork.
            unsafe {
                cmd.pre_exec(move || {
                    apply_filter(&filter).map_err(|e| std::io::Error::other(e.to_string()))
                });
            }
        }
        cmd.arg("--run");
        cmd
    });
    assert!(status.success(), "caliper-probe --run: {status:?}");
    doc["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["probe_id"].as_str().unwrap().to_owned(),
                (
                    r["verdict"].as_str().unwrap().to_owned(),
                    r["errno"].as_u64().unwrap(),
                ),
            )
        })
        .collect()
}

#[test]
fn denied_outright_and_opcode_absent_are_different_records() {
    let r = results();
    let (setup_verdict, setup_errno) = &r["io_uring.setup.zero_entries"];
    let opcodes: Vec<_> = r
        .iter()
        .filter(|(id, _)| id.starts_with("io_uring.opcode."))
        .collect();
    assert!(opcodes.len() >= 50, "{} opcode probes", opcodes.len());
    // The control is the first opcode any ring supports.
    assert!(r.contains_key("io_uring.opcode.nop"));

    if setup_verdict == "denied" {
        // Outright: nothing reaches the ring, and every opcode probe
        // carries the same answer the reach probe got.
        for (id, (verdict, errno)) in &opcodes {
            assert_eq!(verdict, "denied", "{id}");
            assert_eq!(errno, setup_errno, "{id}");
        }
    } else {
        // Reachable: the reach probe got its structural EINVAL, the ring
        // could be probed, and the control opcode is supported.
        assert_eq!(
            (setup_verdict.as_str(), *setup_errno),
            ("permitted", libc::EINVAL as u64)
        );
        assert_eq!(r["io_uring.opcode.nop"], ("permitted".into(), 0));
        assert_eq!(
            r["io_uring.register.probe"],
            ("permitted".into(), libc::EBADF as u64)
        );
        for (id, (verdict, errno)) in &opcodes {
            match verdict.as_str() {
                "permitted" => assert_eq!(*errno, 0, "{id}"),
                "unimplemented" => assert_eq!(*errno, libc::ENODATA as u64, "{id}"),
                other => panic!("{id}: {other} {errno} on a reachable ring"),
            }
        }
    }
}

/// The containers/common profile's shape: `ENOSYS` for anything unlisted.
fn enosys_for_io_uring() -> BpfProgram {
    let spec = serde_json::json!({
        "io_uring": {
            "mismatch_action": "allow",
            "match_action": { "errno": libc::ENOSYS },
            "filter": [{ "syscall": "io_uring_setup" }, { "syscall": "io_uring_register" }],
        }
    });
    let mut map = compile_from_json(Cursor::new(spec.to_string()), ARCH).unwrap();
    map.remove("io_uring").unwrap()
}

#[test]
fn enosys_from_a_filter_is_denied_on_a_kernel_with_io_uring() {
    if std::fs::metadata("/proc/sys/kernel/io_uring_disabled").is_err() {
        eprintln!("skipped: no io_uring_disabled sysctl, presence unknown");
        return;
    }
    let r = results_under(Some(enosys_for_io_uring()));
    let io_uring: Vec<_> = r
        .iter()
        .filter(|(id, _)| id.starts_with("io_uring."))
        .collect();
    assert!(io_uring.len() >= 52, "{} io_uring probes", io_uring.len());
    for (id, (verdict, errno)) in io_uring {
        assert_eq!(
            (verdict.as_str(), *errno),
            ("denied", libc::ENOSYS as u64),
            "{id}"
        );
    }
}
