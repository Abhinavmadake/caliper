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

//! The environment cell, as far as the probe can see it from inside the
//! container (`spec/fingerprint.md`, "Identity"). Architecture, kernel
//! release and the active LSM are the probe's to record; distribution,
//! runtime and RuntimeClass are the control plane's, from the Node object
//! and the pod spec, and are not here. `sandbox_claimed` is not here either:
//! whether the kernel release is a sandbox's synthetic claim is decided by
//! the RuntimeClass, which the probe cannot see — the key is left out, which
//! the spec reads as "the producer did not know", not as `false`.
//!
//! Syscalls, all outside `--noop` and so outside `baseline/`: `uname`,
//! `openat`/`read`/`close` on `/proc/self/status` for the capability sets,
//! and `openat`/`read`/`close` on `/proc/self/attr/<lsm>/current` for each
//! LSM tried. The module set is filled in by the measurement run, which
//! snapshots it before the first probe (`crate::residual`).

use std::fmt;

use serde::{Serialize, Serializer};

/// The processor architectures the corpus can name. Serialised by the
/// `uname -m` spelling the fingerprint uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Arch {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
}

impl Arch {
    /// The architecture this binary was built for, which is the one it is
    /// running on: the probe image is static and per-architecture.
    pub const fn current() -> Arch {
        #[cfg(target_arch = "x86_64")]
        {
            Arch::X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Arch::Aarch64
        }
    }

    /// The other one. A probe restricted to it is `not-applicable` here,
    /// which is what a test of that verdict needs.
    pub const fn other(self) -> Arch {
        match self {
            Arch::X86_64 => Arch::Aarch64,
            Arch::Aarch64 => Arch::X86_64,
        }
    }
}

/// The running kernel's `major.minor`, from the release string. Enough to
/// answer "is this kernel older than the one an entry point appeared in";
/// patch level and distribution suffix are kept in `release` for the record
/// and not compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
}

impl KernelVersion {
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    pub fn at_least(self, (major, minor): (u32, u32)) -> bool {
        self >= KernelVersion::new(major, minor)
    }

    /// Parse the leading `major.minor` of a release string such as
    /// `6.8.0-51-generic` or `6.12-rc3`. `None` if it does not start that
    /// way — recorded as unknown rather than guessed.
    pub fn parse(release: &str) -> Option<Self> {
        let mut parts = release.split(|c: char| !c.is_ascii_digit());
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some(Self { major, minor })
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The active LSM, from the probe's own label
/// (`spec/fingerprint.md`, "active LSM (AppArmor / SELinux / none)").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lsm {
    Apparmor,
    Selinux,
    None,
}

impl Lsm {
    /// Which LSM labels this process. Each LSM that supports labels exposes
    /// its own `/proc/self/attr/<lsm>/current` (kernel 5.1 and later, so
    /// every supported kernel); the one that answers is the one that is
    /// active. The generic `/proc/self/attr/current` is not used: it belongs
    /// to whichever LSM registered first and does not say which.
    pub fn detect() -> Lsm {
        if label("apparmor") {
            Lsm::Apparmor
        } else if label("selinux") {
            Lsm::Selinux
        } else {
            Lsm::None
        }
    }
}

/// Whether `/proc/self/attr/<lsm>/current` exists and is non-empty. Raw
/// syscalls rather than `std::fs::read`, which adds `fstat` and `fcntl` of
/// its own — and a raw `openat` rather than musl's `open()`, which follows
/// `O_CLOEXEC` with an `fcntl` for kernels that ignored the flag. The run
/// path's footprint is meant to be the three named in the module comment
/// and nothing else.
fn label(lsm: &str) -> bool {
    let path = std::ffi::CString::new(format!("/proc/self/attr/{lsm}/current")).unwrap();
    // SAFETY: a NUL-terminated path and constant flags.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    } as libc::c_int;
    if fd < 0 {
        return false;
    }
    let mut buf = [0u8; 1];
    // SAFETY: fd is open and buf is a valid one-byte buffer.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    // SAFETY: fd is a descriptor this function owns and closes once.
    unsafe { libc::close(fd) };
    n > 0
}

fn serialize_cap<S>(cap: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{cap:016x}"))
}

/// The process capability sets from `/proc/self/status`, read before any
/// probe runs. The kernel publishes them as fixed-width hex masks; the
/// struct keeps numbers for correlation and serialises back to that spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    #[serde(serialize_with = "serialize_cap")]
    pub effective: u64,
    #[serde(serialize_with = "serialize_cap")]
    pub permitted: u64,
    #[serde(serialize_with = "serialize_cap")]
    pub bounding: u64,
    #[serde(serialize_with = "serialize_cap")]
    pub ambient: u64,
}

impl Capabilities {
    pub const EMPTY: Capabilities = Capabilities {
        effective: 0,
        permitted: 0,
        bounding: 0,
        ambient: 0,
    };

    pub fn detect() -> nix::Result<Capabilities> {
        let status = read_proc_self_status()?;
        let text = std::str::from_utf8(&status).map_err(|_| nix::errno::Errno::EINVAL)?;
        Ok(Capabilities {
            effective: cap_line(text, "CapEff")?,
            permitted: cap_line(text, "CapPrm")?,
            bounding: cap_line(text, "CapBnd")?,
            ambient: cap_line(text, "CapAmb")?,
        })
    }
}

fn read_proc_self_status() -> nix::Result<Vec<u8>> {
    let path = c"/proc/self/status";
    // SAFETY: a NUL-terminated path and constant flags.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    } as libc::c_int;
    if fd < 0 {
        return Err(nix::errno::Errno::last());
    }
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: fd is open and buf is valid for its full length.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    let read_errno = if n < 0 {
        Some(nix::errno::Errno::last())
    } else {
        None
    };
    // SAFETY: fd is a descriptor this function owns and closes once.
    let close_rc = unsafe { libc::close(fd) };
    if let Some(errno) = read_errno {
        return Err(errno);
    }
    if close_rc < 0 {
        return Err(nix::errno::Errno::last());
    }
    let n = usize::try_from(n).map_err(|_| nix::errno::Errno::EINVAL)?;
    buf.truncate(n);
    Ok(buf)
}

fn cap_line(status: &str, key: &str) -> nix::Result<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .ok_or(nix::errno::Errno::EINVAL)?
        .trim();
    u64::from_str_radix(value, 16).map_err(|_| nix::errno::Errno::EINVAL)
}

/// The kernel as the probe sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Kernel {
    /// `uname -r`, verbatim.
    pub release: String,
    /// `major.minor` parsed from `release`; absent when it did not parse,
    /// in which case every version-gated entry point is treated as one the
    /// kernel may lack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<KernelVersion>,
    /// Loaded modules before any probe ran, so the cell describes the node
    /// and not the instrument (§6.2). Absent where `/proc/modules` could
    /// not be read — unknown, not empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modules: Option<Vec<String>>,
}

impl Kernel {
    pub fn running() -> nix::Result<Kernel> {
        // SAFETY: utsname is plain old data; uname fills it or fails.
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } != 0 {
            return Err(nix::errno::Errno::last());
        }
        // SAFETY: the kernel NUL-terminates every utsname field.
        let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let version = KernelVersion::parse(&release);
        Ok(Kernel {
            release,
            version,
            modules: None,
        })
    }
}

/// The probe-side half of the cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cell {
    pub architecture: Arch,
    pub kernel: Kernel,
    pub lsm: Lsm,
    pub capabilities: Capabilities,
}

impl Cell {
    pub fn detect() -> nix::Result<Cell> {
        Ok(Cell {
            architecture: Arch::current(),
            kernel: Kernel::running()?,
            lsm: Lsm::detect(),
            capabilities: Capabilities::detect()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_distribution_and_rc_releases() {
        assert_eq!(
            KernelVersion::parse("6.8.0-51-generic"),
            Some(KernelVersion::new(6, 8))
        );
        assert_eq!(
            KernelVersion::parse("6.12-rc3"),
            Some(KernelVersion::new(6, 12))
        );
        assert_eq!(
            KernelVersion::parse("5.15.0"),
            Some(KernelVersion::new(5, 15))
        );
        assert_eq!(
            KernelVersion::parse("4.4.0"),
            Some(KernelVersion::new(4, 4))
        );
        assert_eq!(KernelVersion::parse("linux"), None);
        assert_eq!(KernelVersion::parse("6"), None);
    }

    #[test]
    fn compares_by_major_then_minor() {
        let k = KernelVersion::new(6, 8);
        assert!(k.at_least((6, 8)));
        assert!(k.at_least((5, 19)));
        assert!(!k.at_least((6, 9)));
        assert!(!k.at_least((7, 0)));
    }

    #[test]
    fn arch_serialises_by_uname_spelling() {
        assert_eq!(serde_json::to_string(&Arch::X86_64).unwrap(), "\"x86_64\"");
        assert_eq!(
            serde_json::to_string(&Arch::Aarch64).unwrap(),
            "\"aarch64\""
        );
        assert_eq!(serde_json::to_string(&Lsm::None).unwrap(), "\"none\"");
    }

    #[test]
    fn parses_capability_lines() {
        let status = "\
Name:\tcaliper\n\
CapPrm:\t00000000a80425fb\n\
CapEff:\t0000000000000000\n\
CapBnd:\t00000000a80425fb\n\
CapAmb:\t0000000000000000\n";
        assert_eq!(cap_line(status, "CapEff").unwrap(), 0);
        assert_eq!(cap_line(status, "CapPrm").unwrap(), 0x00000000a80425fb);
        assert_eq!(cap_line(status, "CapBnd").unwrap(), 0x00000000a80425fb);
        assert_eq!(cap_line(status, "CapAmb").unwrap(), 0);
    }

    #[test]
    fn capabilities_serialise_as_status_hex() {
        let caps = Capabilities {
            effective: 0,
            permitted: 0x00000000a80425fb,
            bounding: 0xffff_ffff_ffff_ffff,
            ambient: 0x20,
        };
        let v = serde_json::to_value(caps).unwrap();
        assert_eq!(v["effective"], "0000000000000000");
        assert_eq!(v["permitted"], "00000000a80425fb");
        assert_eq!(v["bounding"], "ffffffffffffffff");
        assert_eq!(v["ambient"], "0000000000000020");
    }
}
