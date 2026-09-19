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

//! End-to-end tests for the device-node probe family (#16).

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use serde_json::Value;

const PROBE: &str = env!("CARGO_BIN_EXE_caliper-probe");

#[test]
fn device_opens_are_safe_and_reach_the_kernel() {
    let out = Command::new(PROBE)
        .arg("--run")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .expect("spawn caliper-probe");
    assert!(out.status.success(), "caliper-probe --run failed");
    let doc: Value = serde_json::from_slice(&out.stdout).expect("output is JSON");
    let results: BTreeMap<_, _> = doc["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["probe_id"].as_str().unwrap(), r))
        .collect();

    let ids = [
        "device.open.fuse",
        "device.open.net_tun",
        "device.open.kvm",
        "device.open.kmsg",
        "device.open.mem",
        "device.open.port",
        "device.open.null",
        "device.open.sda",
    ];
    for id in ids {
        let result = results.get(id).copied().expect(id);
        assert!(
            result["verdict"] == "permitted" || result["verdict"] == "denied",
            "{result}"
        );
    }

    let null = results["device.open.null"];
    assert_eq!(null["verdict"], "permitted", "{null}");
    assert_eq!(null["errno"], 0, "{null}");
    assert_eq!(doc["residual"]["leaks"], serde_json::json!([]));
    assert_eq!(doc["residual"]["audit"], serde_json::json!([]));
}
