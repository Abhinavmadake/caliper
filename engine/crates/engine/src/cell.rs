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
//! LSM tried and `/sys/fs/selinux/enforce` when SELinux is active. The module
//! set is filled in by the measurement run, which snapshots it before the first
//! probe (`crate::residual`).

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
    /// Which LSM labels this process. Only AppArmor and Smack have their own
    /// `/proc/self/attr/<lsm>/current`; SELinux answers only through the
    /// generic `/proc/self/attr/current` (#89).
    pub fn detect() -> Lsm {
        Lsm::from_labels(read_attr)
    }

    /// Reads `/proc/self/attr/<lsm>/current`, or the generic file when `lsm`
    /// is empty. The generic file can contain non-SELinux labels (for example
    /// `kernel` on WSL), so SELinux is identified by its colon-separated
    /// security context rather than by the file merely being non-empty.
    /// Smack is not in the cell's enumeration and is recorded as none.
    fn from_labels(read_label: impl Fn(&str) -> Option<String>) -> Lsm {
        if read_label("apparmor").is_some() {
            Lsm::Apparmor
        } else if read_label("smack").is_some() {
            Lsm::None
        } else if read_label("").is_some_and(|label| is_selinux_context(&label)) {
            Lsm::Selinux
        } else {
            Lsm::None
        }
    }
}

fn is_selinux_context(label: &str) -> bool {
    // The MLS range is optional: user:role:type[:range].
    label.split(':').count() >= 3
}

/// Whether `/proc/self/attr/<lsm>/current` exists and is non-empty, or the
/// generic `/proc/self/attr/current` when `lsm` is empty. Raw
/// syscalls rather than `std::fs::read`, which adds `fstat` and `fcntl` of
/// its own — and a raw `openat` rather than musl's `open()`, which follows
/// `O_CLOEXEC` with an `fcntl` for kernels that ignored the flag. The run
/// path's footprint is meant to be the three named in the module comment
/// and nothing else.
fn read_attr(lsm: &str) -> Option<String> {
    let path = if lsm.is_empty() {
        c"/proc/self/attr/current".to_owned()
    } else {
        std::ffi::CString::new(format!("/proc/self/attr/{lsm}/current")).unwrap()
    };
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
        return None;
    }
    let mut buf = [0u8; 4096];
    // SAFETY: fd is open and buf is a valid buffer.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    // SAFETY: fd is a descriptor this function owns and closes once.
    unsafe { libc::close(fd) };
    if n <= 0 {
        return None;
    }
    clean_label(&buf[..usize::try_from(n).ok()?])
}

/// SELinux ends the context with a NUL, AppArmor with a newline.
fn clean_label(raw: &[u8]) -> Option<String> {
    let label = String::from_utf8_lossy(raw)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_owned();
    (!label.is_empty()).then_some(label)
}

fn read_selinux_enforce() -> Option<bool> {
    let path = c"/sys/fs/selinux/enforce";
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
        return None;
    }
    let mut byte = [0u8; 1];
    // SAFETY: fd is open and byte is valid for one byte.
    let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) };
    // SAFETY: fd is a descriptor this function owns.
    unsafe { libc::close(fd) };
    match (n, byte[0]) {
        (1, b'1') => Some(true),
        (1, b'0') => Some(false),
        _ => None,
    }
}

fn serialize_cap<S>(cap: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match cap {
        Some(cap) => serializer.serialize_str(&format!("{cap:016x}")),
        None => serializer.serialize_none(),
    }
}

/// The process capability sets from `/proc/self/status`, read before any
/// probe runs. The kernel publishes them as fixed-width hex masks; the
/// struct keeps numbers for correlation and serialises back to that spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
/// A set whose line is missing from `/proc/self/status` is `None` and left
/// out of the fingerprint, rather than ending the run (#99).
pub struct Capabilities {
    #[serde(
        serialize_with = "serialize_cap",
        skip_serializing_if = "Option::is_none"
    )]
    pub effective: Option<u64>,
    #[serde(
        serialize_with = "serialize_cap",
        skip_serializing_if = "Option::is_none"
    )]
    pub permitted: Option<u64>,
    #[serde(
        serialize_with = "serialize_cap",
        skip_serializing_if = "Option::is_none"
    )]
    pub bounding: Option<u64>,
    #[serde(
        serialize_with = "serialize_cap",
        skip_serializing_if = "Option::is_none"
    )]
    pub ambient: Option<u64>,
}

impl Capabilities {
    pub const EMPTY: Capabilities = Capabilities {
        effective: Some(0),
        permitted: Some(0),
        bounding: Some(0),
        ambient: Some(0),
    };

    pub const UNKNOWN: Capabilities = Capabilities {
        effective: None,
        permitted: None,
        bounding: None,
        ambient: None,
    };

    fn parse(status: &str) -> Capabilities {
        Capabilities {
            effective: cap_line(status, "CapEff").ok(),
            permitted: cap_line(status, "CapPrm").ok(),
            bounding: cap_line(status, "CapBnd").ok(),
            ambient: cap_line(status, "CapAmb").ok(),
        }
    }
}

/// The process's seccomp state from `/proc/self/status`: the mode (0 none,
/// 1 strict, 2 filter) and the number of installed filters. Their contents
/// are not visible from inside (§6.1), but mode 0 rules seccomp out of every
/// denial. Either line missing is `None` and left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Seccomp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<u64>,
}

impl Seccomp {
    fn parse(status: &str) -> Seccomp {
        Seccomp {
            mode: decimal_line(status, "Seccomp"),
            filters: decimal_line(status, "Seccomp_filters"),
        }
    }
}

fn decimal_line(status: &str, key: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))?
        .trim()
        .parse()
        .ok()
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lsm_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lsm_enforcing: Option<bool>,
    pub capabilities: Capabilities,
    pub seccomp: Seccomp,
    /// The kernel's own limits on creating a user namespace, which answer a
    /// user-namespace probe before or instead of a filter (#96).
    pub user_namespaces: UserNamespaces,
}

/// Each value is the sysctl's, `None` (and left out) where the kernel has no
/// such sysctl or it cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct UserNamespaces {
    /// `user.max_user_namespaces`: 0 makes every creation ENOSPC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
    /// Debian's `kernel.unprivileged_userns_clone`: 0 makes an unprivileged
    /// creation EPERM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprivileged_clone: Option<u64>,
    /// Ubuntu's `kernel.apparmor_restrict_unprivileged_userns`: 1 has
    /// AppArmor refuse an unprivileged creation without a userns rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apparmor_restricted: Option<u64>,
}

impl UserNamespaces {
    pub fn detect() -> UserNamespaces {
        UserNamespaces {
            max: read_number(c"/proc/sys/user/max_user_namespaces"),
            unprivileged_clone: read_number(c"/proc/sys/kernel/unprivileged_userns_clone"),
            apparmor_restricted: read_number(
                c"/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            ),
        }
    }
}

/// A sysctl holding one decimal number, read with the run path's raw
/// openat/read/close.
fn read_number(path: &std::ffi::CStr) -> Option<u64> {
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
        return None;
    }
    let mut buf = [0u8; 32];
    // SAFETY: fd is open and buf is a valid buffer.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    // SAFETY: fd is a descriptor this function owns and closes once.
    unsafe { libc::close(fd) };
    let n = usize::try_from(n).ok()?;
    std::str::from_utf8(&buf[..n]).ok()?.trim().parse().ok()
}

impl Cell {
    pub fn detect() -> nix::Result<Cell> {
        let lsm = Lsm::detect();
        let (lsm_label, lsm_enforcing) = match lsm {
            Lsm::Apparmor => {
                let label = read_attr("apparmor");
                let enforcing = label.as_deref().map(|label| label.contains(" (enforce)"));
                (label, enforcing)
            }
            Lsm::Selinux => {
                let label = read_attr("");
                let enforcing = read_selinux_enforce();
                (label, enforcing)
            }
            Lsm::None => (None, None),
        };
        let (capabilities, seccomp) = match read_proc_self_status() {
            Ok(status) => {
                let text = String::from_utf8_lossy(&status);
                (Capabilities::parse(&text), Seccomp::parse(&text))
            }
            Err(_) => (Capabilities::UNKNOWN, Seccomp::default()),
        };
        Ok(Cell {
            architecture: Arch::current(),
            kernel: Kernel::running()?,
            lsm,
            lsm_label,
            lsm_enforcing,
            capabilities,
            seccomp,
            user_namespaces: UserNamespaces::detect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_lose_the_terminator_their_lsm_writes() {
        assert_eq!(
            clean_label(b"system_u:system_r:container_t:s0:c33,c217\0").as_deref(),
            Some("system_u:system_r:container_t:s0:c33,c217")
        );
        assert_eq!(
            clean_label(b"cri-containerd.apparmor.d (enforce)\n").as_deref(),
            Some("cri-containerd.apparmor.d (enforce)")
        );
        assert_eq!(clean_label(b"\0"), None);
    }

    #[test]
    fn reads_seccomp_mode_and_filter_count() {
        let status = "CapEff:\t0000000000000000\nSeccomp:\t2\nSeccomp_filters:\t1\n";
        assert_eq!(
            Seccomp::parse(status),
            Seccomp {
                mode: Some(2),
                filters: Some(1)
            }
        );
        assert_eq!(Seccomp::parse("CapEff:\t0\n"), Seccomp::default());
        assert_eq!(
            serde_json::to_string(&Seccomp::parse("Seccomp:\t0\n")).unwrap(),
            r#"{"mode":0}"#
        );
    }

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
    fn lsm_is_read_from_the_attr_files_that_exist() {
        let only = |labels: &'static [(&'static str, &'static str)]| {
            move |lsm: &str| {
                labels
                    .iter()
                    .find(|(name, _)| *name == lsm)
                    .map(|(_, label)| (*label).to_owned())
            }
        };
        // AppArmor is the major LSM, so it also answers the generic file.
        assert_eq!(
            Lsm::from_labels(only(&[("apparmor", "unconfined"), ("", "unconfined")])),
            Lsm::Apparmor
        );
        assert_eq!(
            Lsm::from_labels(only(&[("", "system_u:system_r:container_t:s0")])),
            Lsm::Selinux
        );
        assert_eq!(
            Lsm::from_labels(only(&[("", "system_u:system_r:container_t")])),
            Lsm::Selinux
        );
        assert_eq!(
            Lsm::from_labels(only(&[("smack", "*"), ("", "kernel")])),
            Lsm::None
        );
        assert_eq!(Lsm::from_labels(only(&[("", "kernel\0")])), Lsm::None);
        assert_eq!(Lsm::from_labels(only(&[])), Lsm::None);
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
            effective: Some(0),
            permitted: Some(0x00000000a80425fb),
            bounding: Some(0xffff_ffff_ffff_ffff),
            ambient: Some(0x20),
        };
        let v = serde_json::to_value(caps).unwrap();
        assert_eq!(v["effective"], "0000000000000000");
        assert_eq!(v["permitted"], "00000000a80425fb");
        assert_eq!(v["bounding"], "ffffffffffffffff");
        assert_eq!(v["ambient"], "0000000000000020");
    }

    #[test]
    fn a_missing_cap_line_drops_that_set_only() {
        let caps = Capabilities {
            ambient: None,
            ..Capabilities::EMPTY
        };
        let v = serde_json::to_value(caps).unwrap();
        assert_eq!(v["effective"], "0000000000000000");
        assert!(v.get("ambient").is_none(), "{v}");
    }
}
