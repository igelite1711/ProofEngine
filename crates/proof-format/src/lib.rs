// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-format: deterministic CBOR (RFC 8949 §4.1 + §4.2.1) + closed schemas.
//! Allowed: uint, nint, text, bytes, array, map, bool, null.
//! Forbidden: floats, tags, indefinite lengths, bignums, simple/undefined, reserved ai.

pub mod cbor;
pub mod schema;

pub use cbor::{
    decode_and_check_canonical, decode_strict, encode_canonical, is_canonical, CborValue,
};
pub use schema::{
    attestation_to_cbor, cbor_to_attestation, cbor_to_event, cbor_to_evidence, cbor_to_proof,
    cbor_to_proposition, cbor_to_relationship, event_to_cbor, evidence_to_cbor, proof_to_cbor,
    proposition_to_cbor, relationship_to_cbor,
};
