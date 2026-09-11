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
