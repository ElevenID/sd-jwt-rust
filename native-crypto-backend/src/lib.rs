//! Native-only feature carrier for the maintained `jsonwebtoken` AWS-LC backend.
//!
//! Keeping this dependency behind a target-specific optional edge lets
//! issuer-planning builds use JOSE data types without compiling a cryptographic
//! backend, while browser WebAssembly installs the fork's restricted provider.

#![forbid(unsafe_code)]

/// Identifies the backend selected for native holder and verifier builds.
pub const BACKEND: &str = "aws-lc-rs";
