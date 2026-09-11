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

//! `caliper-probe` is the whole of the probe image: a static binary and
//! nothing else. No argument parser crate — `std::env::args` is enough for
//! four flags, and every dependency is a source of syscalls to account for.

use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "\
usage: caliper-probe <mode>

  --noop           start up, do nothing, exit. Establishes the engine's own
                   syscall footprint under strace (issue #4)
  --dump-corpus    emit the compiled-in corpus as JSON. An output, never an
                   input (spec/probe.md)
  --version        print the version and exit
";

fn main() -> ExitCode {
    if let Err(e) = caliper_engine::init() {
        eprintln!("caliper-probe: init: {e}");
        return ExitCode::FAILURE;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--noop"] => ExitCode::SUCCESS,
        ["--dump-corpus"] => dump_corpus(),
        ["--version"] => {
            println!("caliper-probe {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            let _ = std::io::stderr().write_all(USAGE.as_bytes());
            ExitCode::from(2)
        }
    }
}

fn dump_corpus() -> ExitCode {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match serde_json::to_writer_pretty(&mut out, caliper_corpus::probes()) {
        Ok(()) => {
            let _ = out.write_all(b"\n");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("caliper-probe: {e}");
            ExitCode::FAILURE
        }
    }
}
