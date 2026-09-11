//! The probe engine. Everything that touches the kernel on the instrument's
//! own behalf lives here, so that the set of syscalls the engine issues is
//! one crate's worth of code to audit (issue #4) rather than a property of
//! the whole workspace.
//!
//! Fork isolation (#5), SIGSYS survival (#6), timeouts (#7), verdicts (#8)
//! and side-effect accounting (#9) land in this crate.
