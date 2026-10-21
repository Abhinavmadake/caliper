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

//! corpus_revision moves with the corpus (#99): the index this build dumps
//! must be the one corpus/revisions records for this revision.

const PROBE: &str = env!("CARGO_BIN_EXE_caliper-probe");

fn fnv1a64(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[test]
fn the_dumped_corpus_is_the_one_its_revision_records() {
    let out = std::process::Command::new(PROBE)
        .arg("--dump-corpus")
        .output()
        .expect("spawn caliper-probe");
    assert!(out.status.success());
    let revisions = include_str!("../../../../corpus/revisions");
    let entries: Vec<(&str, &str)> = revisions
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_once(' ').expect("revision hash"))
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    for (rev, _) in &entries {
        assert!(seen.insert(*rev), "revision {rev} listed twice");
    }
    let rev = caliper_corpus::REVISION;
    let recorded = entries.iter().find(|(r, _)| *r == rev).unwrap_or_else(|| {
        panic!("corpus/revisions has no line for {rev}: bump the corpus version")
    });
    assert_eq!(
        format!("{:016x}", fnv1a64(&out.stdout)),
        recorded.1,
        "the corpus changed without a new revision: bump engine/crates/corpus's version and append it to corpus/revisions"
    );
}
