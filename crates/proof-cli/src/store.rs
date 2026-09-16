// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Filesystem artifact store: the boring production default behind the
//! `ArtifactStore` seam. One file per artifact (`<id>.cbor`, raw canonical
//! bytes) under a directory. Files are transport: every load re-verifies.

use proof_format::ArtifactStore;
use std::path::{Path, PathBuf};

/// Directory-backed store (`<dir>/<artifact-id>.cbor`).
#[derive(Debug, Clone)]
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, String> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| format!("store open {}: {e}", dir.display()))?;
        Ok(Self { dir })
    }

    fn path(&self, id: &str) -> Result<PathBuf, String> {
        if id.is_empty() || id.contains('/') || id.contains('\\') || id.contains("..") {
            return Err(format!("store refuses unsafe id {id:?}"));
        }
        Ok(self.dir.join(format!("{id}.cbor")))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl ArtifactStore for FileStore {
    fn put(&mut self, id: &str, cbor: Vec<u8>) -> Result<(), String> {
        if cbor.is_empty() {
            return Err("store put requires non-empty bytes".into());
        }
        let path = self.path(id)?;
        if path.exists() {
            let prev =
                std::fs::read(&path).map_err(|e| format!("store read {}: {e}", path.display()))?;
            if prev != cbor {
                return Err(format!(
                    "store conflict: {id} already held with different bytes"
                ));
            }
            return Ok(());
        }
        std::fs::write(&path, &cbor).map_err(|e| format!("store write {}: {e}", path.display()))
    }

    fn get(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        let path = self.path(id)?;
        match std::fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("store read {}: {e}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_round_trip_and_conflict() {
        let dir = std::env::temp_dir().join(format!("pe-filestore-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = FileStore::open(&dir).unwrap();
        assert_eq!(s.get("evt:v1:abc").unwrap(), None);
        s.put("evt:v1:abc", vec![0xa0]).unwrap();
        // Idempotent rewrite of identical bytes.
        s.put("evt:v1:abc", vec![0xa0]).unwrap();
        assert_eq!(s.get("evt:v1:abc").unwrap(), Some(vec![0xa0]));
        // Conflicting bytes under one id are corruption, not an update.
        assert!(s.put("evt:v1:abc", vec![0xa1]).is_err());
        // Unsafe ids never touch the filesystem.
        assert!(s.get("../evil").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
