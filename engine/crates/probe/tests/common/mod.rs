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

//! Shared by the end-to-end tests: a `--run` on a CI host shares the mount
//! table and cgroups with the runner, whose housekeeping can land in a
//! probe's snapshot window (#99). A leak the corpus causes repeats on every
//! run; host noise does not. So a run with residual changes is repeated, up
//! to three times, and the last run is what the test asserts on.

use std::process::{Command, ExitStatus, Stdio};

use serde_json::Value;

fn clean(status: &ExitStatus, doc: &Value) -> bool {
    let empty = |key: &str| doc["residual"][key].as_array().is_some_and(Vec::is_empty);
    status.success() && empty("leaks") && empty("audit")
}

pub fn settled(make: impl Fn() -> Command) -> (ExitStatus, Value) {
    let mut attempt = 1;
    loop {
        let out = make()
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()
            .expect("spawn caliper-probe");
        let doc: Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("output is not JSON ({e}); status {:?}", out.status));
        if clean(&out.status, &doc) || attempt == 3 {
            return (out.status, doc);
        }
        eprintln!("residual changes on attempt {attempt}, measuring again");
        attempt += 1;
    }
}
