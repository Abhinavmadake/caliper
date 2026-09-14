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

//! Residual state (#9): the five object classes that outlive a process
//! (§6.2), counted directly before and after each probe and before and
//! after the run, and the loaded module set, snapshotted before the first
//! probe and after the last.
//!
//! Everything here runs in the parent, between probes, so none of it is in
//! any child's measurement. It reads `/proc` and `/sys` with `std::fs`;
//! the syscalls that adds — `openat`, `fcntl` (musl's `open` after
//! `O_CLOEXEC`), `read`, `fstat`, `newfstatat`, `getdents64`,
//! `readlinkat`, `close` — are outside `--noop` and so outside
//! `baseline/`, and are the run path's, not the probe's. The janitor's
//! removals — `unlink`/`unlinkat` and the three `*ctl(IPC_RMID)` calls —
//! are made from a forked child each, through the same harness as a probe:
//! they run under the filter the probe ran under, so on the profile that
//! blocks the remove they get the same `EPERM`, or the same `SIGSYS`, and
//! either is a record. In the parent they would be a lost run.
//!
//! A count is never synthesised. A class this environment does not expose
//! — `/proc/keys` is a masked path under RuntimeDefault, `/dev/mqueue` may
//! not be mounted — is [`Observation::Unobservable`] with the reason, and a
//! read that failed unexpectedly is [`Observation::Error`] with the errno.
//! Both serialise as `null` in a snapshot; the reason lives once, in the
//! run's `observability`. A `0` in place of either would be the
//! exculpatory value, and the error would read as a pass.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::time::Duration;

use nix::errno::Errno;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::effects::{is_instrument_sysv_key, ResidualClass, POSIX_IPC_PREFIX};
use crate::harness::{run_isolated_with, Outcome};
use crate::probe::RawResult;

/// One class, counted — or not, and why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    Observed(usize),
    /// This environment does not expose the class. Decided per run, not
    /// per probe: the reason is a property of the cell.
    Unobservable(&'static str),
    /// The read failed in a way that is not "not exposed".
    Error(i32),
}

impl Observation {
    pub fn count(self) -> Option<usize> {
        match self {
            Observation::Observed(n) => Some(n),
            _ => None,
        }
    }
}

/// How a class stands in this environment, for the run's `observability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Observability {
    Observed,
    Unobservable { reason: &'static str },
    Error { errno: i32 },
}

impl From<Observation> for Observability {
    fn from(o: Observation) -> Self {
        match o {
            Observation::Observed(_) => Observability::Observed,
            Observation::Unobservable(reason) => Observability::Unobservable { reason },
            Observation::Error(errno) => Observability::Error { errno },
        }
    }
}

/// The five classes at one instant. Serialises as `{class: count | null}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot(pub [Observation; ResidualClass::ALL.len()]);

impl Snapshot {
    pub fn take() -> Snapshot {
        Snapshot(ResidualClass::ALL.map(observe))
    }

    pub fn get(&self, class: ResidualClass) -> Observation {
        self.0[class.index()]
    }

    /// Per-class change from `self` to `after`, where both were observed.
    pub fn delta(&self, after: &Snapshot) -> [Option<i64>; ResidualClass::ALL.len()] {
        ResidualClass::ALL.map(|c| Some(after.get(c).count()? as i64 - self.get(c).count()? as i64))
    }

    /// The environment's observability, per class: what this snapshot says
    /// about whether each class can be counted here at all.
    pub fn observability(&self) -> ObservabilityMap {
        ObservabilityMap(self.0.map(Observability::from))
    }
}

impl Serialize for Snapshot {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(ResidualClass::ALL.len()))?;
        for class in ResidualClass::ALL {
            m.serialize_entry(&class, &self.get(class).count())?;
        }
        m.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservabilityMap(pub [Observability; ResidualClass::ALL.len()]);

impl Serialize for ObservabilityMap {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(ResidualClass::ALL.len()))?;
        for class in ResidualClass::ALL {
            m.serialize_entry(&class, &self.0[class.index()])?;
        }
        m.end()
    }
}

fn observe(class: ResidualClass) -> Observation {
    match class {
        ResidualClass::Mounts => lines("/proc/self/mountinfo"),
        ResidualClass::Keyrings => lines("/proc/keys"),
        ResidualClass::Cgroups => directories_below("/sys/fs/cgroup"),
        ResidualClass::SysvIpc => sum([
            // Each file has a header line.
            lines("/proc/sysvipc/shm").map_count(|n| n.saturating_sub(1)),
            lines("/proc/sysvipc/sem").map_count(|n| n.saturating_sub(1)),
            lines("/proc/sysvipc/msg").map_count(|n| n.saturating_sub(1)),
        ]),
        ResidualClass::PosixIpc => sum([entries("/dev/shm"), entries("/dev/mqueue")]),
        ResidualClass::NetNamespaces => net_namespaces(),
    }
}

impl Observation {
    fn map_count(self, f: impl FnOnce(usize) -> usize) -> Observation {
        match self {
            Observation::Observed(n) => Observation::Observed(f(n)),
            other => other,
        }
    }
}

/// Sum of several observations; the first that is not a count wins, so
/// a class is either fully counted or not counted.
fn sum<const N: usize>(parts: [Observation; N]) -> Observation {
    let mut total = 0;
    for p in parts {
        match p {
            Observation::Observed(n) => total += n,
            other => return other,
        }
    }
    Observation::Observed(total)
}

/// A `/proc` file the runtime has masked is bind-mounted over with
/// `/dev/null`: it reads as empty, which is indistinguishable from "no
/// objects". So the file type is checked first.
fn masked(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.file_type().is_char_device())
        .unwrap_or(false)
}

fn unobservable(err: &io::Error, what: &'static str) -> Observation {
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {
            Observation::Unobservable(what)
        }
        _ => Observation::Error(err.raw_os_error().unwrap_or(0)),
    }
}

fn lines(path: &'static str) -> Observation {
    let p = Path::new(path);
    if masked(p) {
        return Observation::Unobservable("masked");
    }
    match fs::read(p) {
        Ok(b) => Observation::Observed(b.iter().filter(|&&c| c == b'\n').count()),
        Err(e) => unobservable(&e, "absent"),
    }
}

fn entries(path: &'static str) -> Observation {
    match fs::read_dir(path) {
        Ok(rd) => Observation::Observed(rd.count()),
        Err(e) => unobservable(&e, "not mounted"),
    }
}

/// Directories at any depth below `root`, not counting `root`.
fn directories_below(root: &'static str) -> Observation {
    fn walk(dir: &Path, n: &mut usize) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                *n += 1;
                walk(&entry.path(), n)?;
            }
        }
        Ok(())
    }
    let mut n = 0;
    match walk(Path::new(root), &mut n) {
        Ok(()) => Observation::Observed(n),
        // The root itself: absent or unreadable is "not mounted". A failure
        // below it is a subtree this process may not list, and the count
        // would be short — reported as an error, not as a smaller number.
        Err(e) if n == 0 => unobservable(&e, "not mounted"),
        Err(e) => Observation::Error(e.raw_os_error().unwrap_or(0)),
    }
}

/// Distinct network namespaces among the processes this one can see —
/// the only way a namespace outlives a probe's child without a mount (which
/// the mount class counts) is a process still holding it. Other users'
/// processes cannot be read and are skipped; inside a container there are
/// none.
fn net_namespaces() -> Observation {
    let rd = match fs::read_dir("/proc") {
        Ok(rd) => rd,
        Err(e) => return unobservable(&e, "no /proc"),
    };
    let mut seen = BTreeSet::new();
    for entry in rd.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(target) = fs::read_link(entry.path().join("ns/net")) {
            seen.insert(target);
        }
    }
    Observation::Observed(seen.len())
}

// --- modules ---------------------------------------------------------------

/// The loaded module set, from `/proc/modules`. `None` where it cannot be
/// read: recorded as unknown, never as empty.
pub fn loaded_modules() -> Option<Vec<String>> {
    let p = Path::new("/proc/modules");
    if masked(p) {
        return None;
    }
    let text = fs::read_to_string(p).ok()?;
    let mut names: Vec<String> = text
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_owned)
        .collect();
    names.sort_unstable();
    Some(names)
}

/// `module_delta` as the fingerprint records it. Module autoload is a
/// declared, non-reclaimable side effect (§6.2): reported here, never
/// counted as residual.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleDelta {
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub loaded_by_run: Vec<String>,
}

impl ModuleDelta {
    pub fn new(before: Vec<String>, after: Vec<String>) -> ModuleDelta {
        let was: BTreeSet<&str> = before.iter().map(String::as_str).collect();
        let loaded_by_run = after
            .iter()
            .filter(|m| !was.contains(m.as_str()))
            .cloned()
            .collect();
        ModuleDelta {
            before,
            after,
            loaded_by_run,
        }
    }
}

// --- janitor ---------------------------------------------------------------

/// How long one removal may take. A removal is a single syscall; the bound
/// exists so that a filter which traps rather than answers cannot hang the
/// end of the run.
const REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);

/// One thing the janitor tried to remove at the end of the run, and how it
/// went. Loud by design: a removal is a finding about the corpus, and a
/// failed removal is the asymmetric filter — create permitted, remove
/// blocked — caught in the act, which is the finding the janitor exists
/// for. Neither is a silent fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Removal {
    pub class: ResidualClass,
    pub object: String,
    /// The removal returned success. Anything else is `false`, and
    /// `attempt` says what: `EPERM` from an `ERRNO` filter, `SIGSYS` from
    /// a `KILL_PROCESS` one, a harness fault.
    pub removed: bool,
    pub attempt: Attempt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Attempt {
    /// A child ran the removal and ended this way, in the harness's terms.
    Child(Outcome),
    /// The harness could not run a child — fork, pidfd or wait failed —
    /// so nothing was attempted.
    Harness { errno: i32 },
}

/// Remove what is recognisably the instrument's and was left behind:
/// POSIX objects named with [`POSIX_IPC_PREFIX`], System V objects keyed in
/// the instrument's range. Runs once, after the run's final snapshot, so
/// what it removes has already been measured and attributed. Each removal
/// is made in its own forked child; the parent only lists.
pub fn janitor() -> Vec<Removal> {
    let mut removals = Vec::new();
    for dir in ["/dev/shm", "/dev/mqueue"] {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(POSIX_IPC_PREFIX) {
                continue;
            }
            let object = format!("{dir}/{name}");
            // Built here so the child allocates nothing. `unlink` is what
            // `shm_unlink` and `mq_unlink` are on Linux.
            let Ok(path) = CString::new(object.as_str()) else {
                continue;
            };
            let remove = || {
                // SAFETY: a NUL-terminated path owned by the parent, which
                // the child reads and does not touch again.
                if unsafe { libc::unlink(path.as_ptr()) } == 0 {
                    Ok(())
                } else {
                    Err(Errno::last())
                }
            };
            removals.push(attempt(ResidualClass::PosixIpc, object, &remove));
        }
    }
    for (file, kind) in [
        ("/proc/sysvipc/shm", SysvKind::Shm),
        ("/proc/sysvipc/sem", SysvKind::Sem),
        ("/proc/sysvipc/msg", SysvKind::Msg),
    ] {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let mut f = line.split_whitespace();
            let (Some(key), Some(id)) = (f.next(), f.next()) else {
                continue;
            };
            let (Ok(key), Ok(id)) = (key.parse::<i32>(), id.parse::<i32>()) else {
                continue;
            };
            if !is_instrument_sysv_key(key) {
                continue;
            }
            let object = format!("{} key {key:#x} id {id}", kind.name());
            let remove = || kind.remove(id);
            removals.push(attempt(ResidualClass::SysvIpc, object, &remove));
        }
    }
    removals
}

fn attempt(class: ResidualClass, object: String, remove: &dyn Fn() -> RawResult) -> Removal {
    let attempt = match run_isolated_with(remove, REMOVAL_TIMEOUT) {
        Ok(outcome) => Attempt::Child(outcome),
        Err(errno) => Attempt::Harness {
            errno: errno as i32,
        },
    };
    Removal {
        class,
        object,
        removed: attempt == Attempt::Child(Outcome::Returned { errno: 0 }),
        attempt,
    }
}

#[derive(Clone, Copy)]
enum SysvKind {
    Shm,
    Sem,
    Msg,
}

impl SysvKind {
    fn name(self) -> &'static str {
        match self {
            SysvKind::Shm => "shm",
            SysvKind::Sem => "sem",
            SysvKind::Msg => "msg",
        }
    }

    fn remove(self, id: i32) -> RawResult {
        // SAFETY: IPC_RMID with a null buffer; the id came from /proc.
        let r = unsafe {
            match self {
                SysvKind::Shm => libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()),
                SysvKind::Sem => libc::semctl(id, 0, libc::IPC_RMID),
                SysvKind::Msg => libc::msgctl(id, libc::IPC_RMID, std::ptr::null_mut()),
            }
        };
        if r == 0 {
            Ok(())
        } else {
            Err(Errno::last())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_delta_is_what_the_run_loaded() {
        let d = ModuleDelta::new(
            vec!["overlay".into(), "nf_tables".into()],
            vec!["algif_aead".into(), "nf_tables".into(), "overlay".into()],
        );
        assert_eq!(d.loaded_by_run, vec!["algif_aead".to_string()]);
    }

    #[test]
    fn a_class_that_cannot_be_counted_is_null_not_zero() {
        let s = Snapshot([
            Observation::Observed(3),
            Observation::Unobservable("masked"),
            Observation::Error(13),
            Observation::Observed(0),
            Observation::Observed(0),
            Observation::Observed(1),
        ]);
        let v = serde_json::to_value(s).unwrap();
        assert_eq!(v["mounts"], 3);
        assert!(v["keyrings"].is_null());
        assert!(v["cgroups"].is_null());
        assert_eq!(v["sysv-ipc"], 0);
        let o = serde_json::to_value(s.observability()).unwrap();
        assert_eq!(o["mounts"], "observed");
        assert_eq!(o["keyrings"]["unobservable"]["reason"], "masked");
        assert_eq!(o["cgroups"]["error"]["errno"], 13);
        // Deltas exist only where both sides were counted.
        let d = s.delta(&s);
        assert_eq!(d[0], Some(0));
        assert_eq!(d[1], None);
    }

    #[test]
    fn a_sum_is_all_or_nothing() {
        assert_eq!(
            sum([Observation::Observed(2), Observation::Observed(3)]),
            Observation::Observed(5)
        );
        assert_eq!(
            sum([Observation::Observed(2), Observation::Unobservable("x")]),
            Observation::Unobservable("x")
        );
    }
}
