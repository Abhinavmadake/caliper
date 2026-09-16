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

//! `caliper-probe --run` end to end (#10): the reference corpus, from image
//! start to the emitted document, checked against `spec/fingerprint.md`'s
//! conventions; and the same run under a filter that kills every probed
//! syscall, so the ten children die of SIGSYS and the parent survives to
//! record ten `killed` verdicts.
//!
//! The filter is applied in the forked child at the last instant before
//! `execve`, as `hardened.rs` does, so what is measured is the engine and
//! nothing in front of it. Linux only, musl build.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch};
use serde_json::Value;

const PROBE: &str = env!("CARGO_BIN_EXE_caliper-probe");

#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;

/// The syscalls the reference corpus probes, and nothing else: a
/// `KILL_PROCESS` on each is the SIGSYS path, and the parent — which
/// issues none of them — carries on.
const PROBED: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_io_uring_register,
    libc::SYS_io_uring_setup,
    libc::SYS_mount,
    libc::SYS_unshare,
    libc::SYS_clone3,
    libc::SYS_clone,
];

fn kill_probed() -> BpfProgram {
    let rules: BTreeMap<_, _> = PROBED.iter().map(|&s| (s, vec![])).collect();
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        ARCH,
    )
    .unwrap()
    .try_into()
    .unwrap()
}

/// Run `caliper-probe <mode>`, with `filter` installed in the child before
/// exec, and parse what it printed.
fn run(mode: &str, filter: Option<BpfProgram>) -> Value {
    let mut cmd = Command::new(PROBE);
    cmd.arg(mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(filter) = filter {
        // SAFETY: pre_exec runs in the forked child; apply_filter is two
        // syscalls on a program built before the fork, and the error path
        // constructs nothing that allocates.
        unsafe {
            cmd.pre_exec(move || {
                apply_filter(&filter).map_err(|_| io::Error::from_raw_os_error(libc::EPERM))
            });
        }
    }
    let out = cmd.output().expect("spawn caliper-probe");
    assert!(
        out.status.success(),
        "caliper-probe {mode} failed: {:?}",
        out.status
    );
    serde_json::from_slice(&out.stdout).expect("output is JSON")
}

const VERDICTS: &[&str] = &[
    "permitted",
    "denied",
    "unimplemented",
    "killed",
    "timed-out",
    "not-applicable",
];

fn is_snake_case(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Every object key below `v` is snake_case (`spec/fingerprint.md`,
/// conventions).
fn check_keys(v: &Value, path: &str) {
    if let Value::Object(m) = v {
        for (k, child) in m {
            assert!(is_snake_case(k), "{path}.{k}: object key is not snake_case");
            check_keys(child, &format!("{path}.{k}"));
        }
    }
    if let Value::Array(a) = v {
        for (i, child) in a.iter().enumerate() {
            check_keys(child, &format!("{path}[{i}]"));
        }
    }
}

#[test]
fn the_run_emits_the_probe_side_of_a_fingerprint() {
    let corpus = run("--dump-corpus", None);
    let ids: Vec<&str> = corpus
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert!(ids.len() >= 10, "{ids:?}");

    let doc = run("--run", None);
    // Identity and cell, the probe-side fields of spec/fingerprint.md.
    assert!(doc["format_version"].is_u64());
    assert!(doc["corpus_revision"].is_string());
    assert!(doc["cell"]["architecture"].is_string());
    assert!(doc["cell"]["kernel"]["release"].is_string());
    assert!(doc["cell"]["lsm"].is_string());
    assert!(
        doc.get("digest").is_none(),
        "the digest is the control plane's"
    );
    assert!(
        doc.get("attribution").is_none(),
        "attribution is the control plane's"
    );

    // One result per probe, in corpus order, each the three fields and no
    // interpretation.
    let results = doc["results"].as_array().unwrap();
    assert_eq!(
        doc["unmeasured"],
        serde_json::json!([]),
        "{}",
        doc["unmeasured"]
    );
    let got: Vec<&str> = results
        .iter()
        .map(|r| r["probe_id"].as_str().unwrap())
        .collect();
    assert_eq!(got, ids);
    for r in results {
        assert_eq!(r.as_object().unwrap().len(), 3, "{r}");
        let verdict = r["verdict"].as_str().unwrap();
        assert!(VERDICTS.contains(&verdict), "{r}");
        assert!(r["errno"].is_u64(), "errno is the raw integer: {r}");
        if matches!(verdict, "killed" | "timed-out" | "not-applicable") {
            assert_eq!(r["errno"], 0, "{r}");
        }
    }

    // Module delta and residual report are present (#9), with the shapes
    // the fixtures carry.
    if let Some(delta) = doc.get("module_delta") {
        assert!(delta["before"].is_array() && delta["loaded_by_run"].is_array());
    }
    for key in [
        "observability",
        "before",
        "after",
        "leaks",
        "unverifiable",
        "audit",
        "janitor",
    ] {
        assert!(!doc["residual"][key].is_null(), "residual.{key}");
    }

    // snake_case keys throughout, kebab-case enumeration values — the
    // residual snapshots included, whose keys are the classes' snake_case
    // spelling.
    check_keys(&doc, "$");
}

#[test]
fn under_a_kill_filter_every_probe_is_killed_and_the_run_survives() {
    let doc = run("--run", Some(kill_probed()));
    let results = doc["results"].as_array().unwrap();
    assert!(results.len() >= 10, "{}", doc["results"]);
    for r in results {
        assert_eq!(r["verdict"], "killed", "{r}");
        assert_eq!(r["errno"], 0, "{r}");
    }
    assert_eq!(doc["unmeasured"], serde_json::json!([]));
}
