// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-core: domain types, error codes, limits, hash/id value objects.
//! No crypto, no CBOR, no I/O. All security-critical enums are closed.

pub mod error;
pub mod hash;
pub mod limits;
pub mod model;

pub use error::{ErrorCode, ProofError};
pub use hash::{HashAlgorithm, HashRef};
pub use limits::Limits;
// PE-SEC-004: no-panic invariant holds workspace-wide (no unwrap/expect/panic in
// production paths); enforced by soak mutation tests + fuzz no-panic asserts.
pub use model::LifecycleStatus;
