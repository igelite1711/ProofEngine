// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-verify: Proof assembly (builder) and staged verification pipeline.
//! Stages 1–11 per ARCHITECTURE §4, including TIME and
//! REVOCATION/SUPERSESSION (Phase 6 lifecycle state machine, stages 7–8).
//! Policy (stage 12) is evaluated by the caller in `proof-policy`: the
//! pipeline reports `policy_decision: INDETERMINATE` and never decides trust.

pub mod builder;
pub mod pipeline;
pub mod report;

pub use builder::{BuiltProof, ProofBuilder};
pub use pipeline::{verify_proof, VerifyCtx};
pub use report::{CheckRecord, LifecycleRecord, PolicyDecision, Validity, VerifyReport};
