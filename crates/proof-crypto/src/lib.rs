// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-crypto: hashes, ids, COSE_Sign1 (-19 required, -9 optional).
//! Rejects deprecated polymorphic algs (-8/-7/-35/-36). No network, no policy.

pub mod alg;
pub mod build;
pub mod claim;
pub mod cose;
pub mod hash;
pub mod id;
pub mod keys;

pub use alg::{AllowedAlgs, COSE_ED25519, COSE_ESP256};
pub use build::{
    revoke_attestation, supersede_attestation, to_signed_status, verify_status_object,
    CreatedAttestation, SignedStatus,
};
pub use claim::{claim_kind, revocation_target, supersession_pair, ClaimKind};
pub use hash::{compute_digest, verify_content_digest};
pub use keys::{Ed25519Key, P256Key};
