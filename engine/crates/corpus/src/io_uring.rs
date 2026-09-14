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

//! io_uring opcode reach (`corpus/README.md`, committed set). The proposal
//! prefers the enumeration interface: `IORING_REGISTER_PROBE` reports the
//! supported opcodes without submitting a queue entry (§6.2). These two
//! probes measure whether the two syscalls that interface needs are
//! reachable at all, each with an answer the kernel produces before any
//! hook; the opcode table itself is the committed family's (#12).

use caliper_engine::{
    Applicability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult, SideEffects,
};

use crate::common::{result, ONE_CALL};

/// `include/uapi/linux/io_uring.h`; not in the libc crate.
const IORING_REGISTER_PROBE: libc::c_uint = 8;

/// `sizeof(struct io_uring_params)`, as sixteen zeroed words: the kernel
/// copies exactly that many bytes and rejects a non-zero `resv`.
const IO_URING_PARAMS_WORDS: usize = 15;

fn register_probe_bad_fd() -> RawResult {
    // SAFETY: integer arguments and a null pointer the kernel never reads,
    // because -1 fails descriptor resolution first.
    result(unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            -1 as libc::c_int,
            IORING_REGISTER_PROBE,
            std::ptr::null::<libc::c_void>(),
            0 as libc::c_uint,
        )
    })
}

fn setup_zero_entries() -> RawResult {
    let params = [0u64; IO_URING_PARAMS_WORDS];
    // SAFETY: a zeroed, correctly sized params block on the stack; the
    // kernel reads it and rejects the entry count before it creates anything.
    result(unsafe { libc::syscall(libc::SYS_io_uring_setup, 0 as libc::c_uint, params.as_ptr()) })
}

/// `CONFIG_IO_URING=n` leaves the syscalls out: `ENOSYS` is absence.
const CONFIG_GATED: KernelDependency = KernelDependency {
    since: None,
    absent_errno: Some(Errno::ENOSYS),
};

pub const REGISTER_PROBE: Probe = Probe {
    id: "io_uring.register.probe",
    family: "io_uring",
    description: "io_uring_register(-1, IORING_REGISTER_PROBE, NULL, 0): guaranteed EBADF",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: CONFIG_GATED,
    oracle: Oracle {
        guarantees: Some(Errno::EBADF),
        isolates: Isolates::Seccomp,
        reason: "io_uring_register resolves the descriptor with fdget as soon as the opcode \
                 is in range, and -1 is never a descriptor; EBADF is produced before any \
                 LSM hook, so only a filter at syscall entry answers EPERM first",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: register_probe_bad_fd,
};

pub const SETUP_ZERO_ENTRIES: Probe = Probe {
    id: "io_uring.setup.zero_entries",
    family: "io_uring",
    description: "io_uring_setup(0, &params): guaranteed EINVAL, no ring is created",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: CONFIG_GATED,
    oracle: Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::Seccomp,
        reason: "io_uring_create rejects zero entries with EINVAL and io_uring_setup has no \
                 LSM hook. Since 6.6 the kernel.io_uring_disabled sysctl makes the kernel \
                 itself answer EPERM before that check; on such a cell EPERM does not \
                 isolate the filter",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: setup_zero_entries,
};
