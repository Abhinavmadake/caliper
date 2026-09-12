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

//! # Authoring a probe
//!
//! The pattern to copy. This compiles and is checked by `cargo test --doc`, so
//! it cannot rot silently.
//!
//! ```
//! use std::time::Duration;
//! use caliper_corpus::Probe;
//! use caliper_engine::{Errno, RawResult, RiskClass};
//!
//! /// `close(2)` on a descriptor that cannot be valid.
//! ///
//! /// The oracle: `EBADF` is structurally guaranteed if the call reaches the
//! /// kernel at all, because descriptor resolution happens before every LSM
//! /// hook. So `EPERM` here proves interception *before* that point, which
//! /// isolates seccomp specifically (`spec/probe.md`, errno oracle).
//! fn close_bad_fd() -> RawResult {
//!     // A raw syscall, not the libc wrapper: a wrapper can hide a second
//!     // syscall — musl's `socket()` retries without SOCK_CLOEXEC on EINVAL —
//!     // and the oracle reasons about the exact sequence the child issues.
//!     let r = unsafe { libc::syscall(libc::SYS_close, -1) };
//!     if r < 0 {
//!         Err(Errno::last())
//!     } else {
//!         Ok(())
//!     }
//! }
//!
//! const EXAMPLE: Probe = Probe {
//!     id: "example.close.bad_fd",
//!     family: "example",
//!     description: "close(2) on an invalid descriptor",
//!     // requires_fork is the author's claim about side effects, reviewed in
//!     // #18; the engine forks for every probe regardless.
//!     risk: RiskClass::new(true, Duration::from_millis(500)),
//!     run: close_bad_fd,
//! };
//! ```
//!
//! Rules the probe function must hold to, from `spec/probe.md` and §6.2. It runs
//! in a forked child with nothing between the `clone` and the call:
//!
//! - no allocation, no `std` I/O, no panics — nothing but the syscalls under test
//! - reachability only. Never an operation whose success confers privilege
//! - prefer an enumeration interface where one answers the question:
//!   `IORING_REGISTER_PROBE` over submitting queue entries
//! - a probe that can make the kernel autoload a module declares it; that side
//!   effect cannot be rolled back

pub use caliper_engine::Probe;

/// Every probe the engine knows about, in corpus order.
pub fn probes() -> &'static [Probe] {
    &[]
}
