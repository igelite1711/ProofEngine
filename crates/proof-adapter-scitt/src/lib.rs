// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SCITT transparency adapter (ECOSYSTEM §6, P7).
//!
//! Maps IETF SCITT-style signed statements and transparency receipts to and
//! from the Proof Engine model, preserving a cryptographic binding that
//! survives the mapping in both directions (the sha256 of the canonical
//! SCITT JSON rides in a digest-bound `Evidence` item).
//!
//! ```text
//! SCITT concept            → Proof Engine representation
//! ─────────────────────────────────────────────────────────────────
//! signed statement         → Attestation (claim `scitt.statement`,
//!                            issuer = statement signer, subject =
//!                            statement id, fields feed/cti/digest)
//! statement registration   → Evidence `transparency_registration`
//!                            (digest = statement digest)
//! transparency receipt     → Evidence `transparency_receipt`
//!                            (digest = statement digest,
//!                             attestation_ref = checkpoint id)
//! log checkpoint/tree head → Attestation `transparency.checkpoint`
//!                            (issuer = log identity)
//! inclusion decision       → Policy v2 `transparency_inclusion{log}`
//! ```
//!
//! Trust boundary (read before relying): this adapter verifies Ed25519
//! statement signatures against `key:*` keyrefs. X.509 certificate chains,
//! DID-based issuers, and Merkle inclusion/consistency proofs are
//! **unmappable in this version** — they fail with a stable code
//! (`SCHEMA_VIOLATION`), never approximate. Chain validation and log
//! auditing stay outside the adapter, exactly like all PKI in this system:
//! the adapter maps authenticated statements, it is not a PKI verifier.
//! Log-issued checkpoints are ordinary attestations: signatures, validity
//! windows, revocation, and compromise semantics apply unchanged.

pub mod map;
pub mod statement;

pub use map::{
    checkpoint_content, receipt_evidence, registration_evidence, statement_content, statement_json,
    CLAIM_SCITT_STATEMENT,
};
pub use statement::{ScittStatement, SignedStatement};
