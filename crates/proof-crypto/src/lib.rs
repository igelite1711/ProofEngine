// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-crypto: hashes, ids, COSE_Sign1 (-19 required, -9 optional).
//! Rejects deprecated polymorphic algs (-8/-7/-35/-36). No network, no policy.

pub mod alg;
pub mod build;
pub mod claim;
pub mod cose;
pub mod envelope;
pub mod hash;
pub mod id;
pub mod keys;

pub use envelope::verify_envelope;

pub use alg::{AllowedAlgs, COSE_ED25519, COSE_ESP256};
pub use build::{
    compromise_attestation, revoke_attestation, supersede_attestation, to_signed_status,
    verify_status_object, withdraw_attestation, CreatedAttestation, SignedStatus,
};
pub use claim::{
    claim_kind, compromise_mark, denial_target, revocation_target, supersession_pair,
    withdrawal_target, ClaimKind, CLAIM_COMPROMISE, CLAIM_DELEGATE, CLAIM_FIELD_DENIES,
    CLAIM_IDENTITY_BIND, CLAIM_REVOKE, CLAIM_SUPERSEDE, CLAIM_TRANSPARENCY_CHECKPOINT,
    CLAIM_WITHDRAW,
};
pub use hash::{compute_digest, verify_content_digest};
pub use keys::{Ed25519Key, P256Key};
