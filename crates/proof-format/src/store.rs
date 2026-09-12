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
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    inner: HashMap<String, Vec<u8>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
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
        // Transport-level DoS guard (default 1MiB). Stores are infrastructure
        // so the error stays `String` by trait contract; verification bounds
        // live in `Limits` and the pipeline.
        if cbor.len() > 1024 * 1024 {
            return Err(format!("store put: {} bytes exceeds 1MiB", cbor.len()));
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
}
