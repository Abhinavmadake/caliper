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

//! The probe corpus. Probes are Rust definitions compiled into the engine
//! (`spec/probe.md`, decision 1): there is no data file read at run time.
//! `caliper-probe --dump-corpus` emits this crate's contents as JSON, as an
//! output only.
//!
//! A and B both author here. What a probe *is* — [`Probe`] and its fields —
//! is defined in `caliper-engine`; the ten-probe reference corpus arrives
//! with #10 and the committed families with #11–#17.

pub use caliper_engine::Probe;

/// Every probe the engine knows about, in corpus order.
pub fn probes() -> &'static [Probe] {
    &[]
}
