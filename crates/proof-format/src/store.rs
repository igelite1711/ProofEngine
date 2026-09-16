// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Storage seam (§35): the core never requires a database.
//!
//! A store is an index over immutable artifacts keyed by artifact id.
//! Mutating a row never redefines an id (ids are content-addressed); a store
//! that disagrees with recomputed ids is corrupt, and every loader
//! re-verifies. Store errors are transport (`String`), never verification
//! verdicts: persistence is infrastructure, proof semantics are not storage
//! semantics.

use std::collections::HashMap;

/// Key-value artifact storage. Keys are full artifact ids
/// (`evt:v1:…`, `att:v1:…`, `evd:v1:…`, `rel:v1:…`, `prf:v1:…`).
pub trait ArtifactStore {
    /// Store canonical CBOR bytes under `id`. Overwriting the same id with
    /// different bytes is a corruption signal: implementations SHOULD reject
    /// it (`Err`) rather than silently replace history.
    fn put(&mut self, id: &str, cbor: Vec<u8>) -> Result<(), String>;
    /// Fetch canonical CBOR bytes, or `None` when absent (absence is data:
    /// callers report REFERENCED/UNAVAILABLE, never assume content).
    fn get(&self, id: &str) -> Result<Option<Vec<u8>>, String>;
}

/// In-memory store. Test/dev default; production uses filesystem, object,
/// SQL, document, or content-addressed backends behind the same trait.
#[derive(Debug, Clone)]
pub struct MemoryStore {
    inner: HashMap<String, Vec<u8>>,
    /// Transport-level per-blob cap. Defaults to `Limits::default().max_proof_size`
    /// (1MiB) so store/verify bounds agree out of the box (F12); deployments
    /// tightening `max_proof_size` should construct via `with_limits`.
    max_bytes: usize,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            inner: HashMap::new(),
            max_bytes: proof_core::Limits::default().max_proof_size,
        }
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with an explicit `Limits` so store bounds track verifier
    /// bounds (deployments that tighten `max_proof_size`).
    pub fn with_limits(limits: &proof_core::Limits) -> Self {
        Self {
            inner: HashMap::new(),
            max_bytes: limits.max_proof_size,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl ArtifactStore for MemoryStore {
    fn put(&mut self, id: &str, cbor: Vec<u8>) -> Result<(), String> {
        if id.is_empty() || cbor.is_empty() {
            return Err("store put requires non-empty id and bytes".into());
        }
        // Transport-level DoS guard, tied to Limits (F12). Stores are
        // infrastructure so the error stays `String` by trait contract;
        // verification bounds live in `Limits` and the pipeline. Default is
        // Limits::default().max_proof_size (1MiB); use with_limits() to track
        // tightened deployments.
        if cbor.len() > self.max_bytes {
            return Err(format!(
                "store put: {} bytes exceeds {} (MemoryStore max_bytes)",
                cbor.len(),
                self.max_bytes
            ));
        }
        match self.inner.get(id) {
            Some(prev) if *prev != cbor => Err(format!(
                "store conflict: {id} already held with different bytes"
            )),
            _ => {
                self.inner.insert(id.to_string(), cbor);
                Ok(())
            }
        }
    }

    fn get(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.inner.get(id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trip_conflict_and_absence() {
        let mut s = MemoryStore::new();
        assert!(s.is_empty());
        assert_eq!(s.get("prf:v1:x").unwrap(), None);
        s.put("prf:v1:x", vec![1, 2, 3]).unwrap();
        // Identical rewrite is idempotent.
        s.put("prf:v1:x", vec![1, 2, 3]).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.get("prf:v1:x").unwrap(), Some(vec![1, 2, 3]));
        // Same id, different bytes: corruption, never a silent update.
        assert!(s.put("prf:v1:x", vec![9]).is_err());
        assert!(s.put("", vec![1]).is_err());
        assert!(s.put("prf:v1:y", vec![]).is_err());
    }

    #[test]
    fn memory_store_tracks_limits() {
        // F12: store bounds follow Limits instead of a hardcoded 1MiB.
        let mut s = MemoryStore::with_limits(&proof_core::Limits {
            max_proof_size: 16,
            ..Default::default()
        });
        assert!(s.put("prf:v1:x", vec![1; 16]).is_ok());
        assert!(s.put("prf:v1:y", vec![1; 17]).is_err());
        // Default tracks the default limit (1MiB).
        assert_eq!(
            MemoryStore::new().max_bytes,
            proof_core::Limits::default().max_proof_size
        );
    }
}
