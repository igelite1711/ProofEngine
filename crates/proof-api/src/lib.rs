// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reference HTTP API (P9): thin interface around the core, never trust root.
//! See `main.rs` for the wire contract; request routing and verification
//! live in [`api`] so integration tests exercise the exact serve path.

pub mod api;
pub mod server;
