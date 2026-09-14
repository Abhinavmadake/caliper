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

//! What every probe function shares: the raw-syscall discipline
//! (`ProbeFn`'s rules — no allocation, no `std`, nothing but the call).

use caliper_engine::{Errno, RawResult, RiskClass};
use std::time::Duration;

/// The return of a raw `libc::syscall`, as the kernel's answer.
pub(crate) fn result(r: libc::c_long) -> RawResult {
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

/// Every reference probe is one syscall that returns at once; a second is
/// generous, and a hang past it is the `timed-out` verdict. `requires_fork`
/// is true throughout: any of these can be answered with SIGSYS.
pub(crate) const ONE_CALL: RiskClass = RiskClass::new(true, Duration::from_secs(1));
