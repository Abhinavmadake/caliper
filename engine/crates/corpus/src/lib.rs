//! The probe corpus. Probes are Rust definitions compiled into the engine
//! (`spec/probe.md`, decision 1): there is no data file read at run time.
//! `caliper-probe --dump-corpus` emits this crate's contents as JSON, as an
//! output only.
//!
//! A and B both author here. The definition of a probe — the fields
//! `spec/probe.md` lists — is A's (#8, #9, #10); the ten-probe reference
//! corpus arrives with #10 and the committed families with #11–#17.

use serde::Serialize;

/// A probe definition. Placeholder: the fields fixed by `spec/probe.md`
/// (operation, errno oracle, capability requirement, side effects, risk
/// class, kernel dependency, applicability) are added under #8–#10.
#[derive(Debug, Clone, Serialize)]
pub struct Probe {
    pub id: &'static str,
    pub family: &'static str,
    pub description: &'static str,
}

/// Every probe the engine knows about, in corpus order.
pub fn probes() -> &'static [Probe] {
    &[]
}
