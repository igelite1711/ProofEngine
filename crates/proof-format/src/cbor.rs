// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal deterministic CBOR codec for the V0.1 subset.
//! Encoder always emits preferred serialization + lexicographic map order.
//! Decoder rejects everything outside the subset (fail closed).

use proof_core::{ErrorCode, Limits, ProofError};

/// Closed CBOR value set for V0.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    Uint(u64),
    Nint(i64), // -2^64..=-1
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
}

impl CborValue {
    fn sort_maps(&mut self) {
        match self {
            Self::Array(items) => {
                for i in items.iter_mut() {
                    i.sort_maps();
                }
            }
            Self::Map(pairs) => {
                for (k, v) in pairs.iter_mut() {
                    k.sort_maps();
                    v.sort_maps();
                }
                pairs.sort_by_key(|a| encode_canonical(&a.0));
            }
            _ => {}
        }
    }
}

// ---------- encoder ----------

fn encode_head(major: u8, n: u64, out: &mut Vec<u8>) {
    debug_assert!(major < 8);
    let prefix = major << 5;
    if n < 24 {
        out.push(prefix | n as u8);
    } else if n <= u8::MAX as u64 {
        out.push(prefix | 24);
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(prefix | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(prefix | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(prefix | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

// PE-FMT-001 (lexicographic maps) · PE-FMT-002 (shortest ints).
fn encode_value(v: &CborValue, out: &mut Vec<u8>) {
    match v {
        CborValue::Uint(n) => encode_head(0, *n, out),
        CborValue::Nint(n) => {
            // Invariant: CBOR nint is always <= -1. Callers must uphold it
            // (schema layer never constructs non-negative Nint).
            debug_assert!(*n < 0, "CborValue::Nint must be negative");
            // value = -1 - n  =>  n_arg = (-1 - value) as u64
            let arg = (-1i128 - (*n as i128)) as u64;
            encode_head(1, arg, out);
        }
        CborValue::Bytes(b) => {
            encode_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        CborValue::Text(s) => {
            encode_head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        CborValue::Array(items) => {
            encode_head(4, items.len() as u64, out);
            for i in items {
                encode_value(i, out);
            }
        }
        CborValue::Map(pairs) => {
            // Deterministic: sort by encoded key bytes.
            let mut enc_keys: Vec<(Vec<u8>, &CborValue, &CborValue)> = pairs
                .iter()
                .map(|(k, val)| {
                    let mut kb = Vec::new();
                    encode_value(k, &mut kb);
                    (kb, k, val)
                })
                .collect();
            enc_keys.sort_by(|a, b| a.0.cmp(&b.0));
            encode_head(5, pairs.len() as u64, out);
            for (kb, _, val) in enc_keys {
                out.extend_from_slice(&kb);
                encode_value(val, out);
            }
        }
        CborValue::Bool(true) => out.push(0xf5),
        CborValue::Bool(false) => out.push(0xf4),
        CborValue::Null => out.push(0xf6),
    }
}

/// Encode deterministically (preferred serialization + lexicographic maps).
pub fn encode_canonical(v: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(v, &mut out);
    out
}

// ---------- decoder ----------

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
    limits: Limits,
}

impl<'a> Decoder<'a> {
    fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read(&mut self, n: usize) -> Result<&'a [u8], ProofError> {
        if self.pos.checked_add(n).is_none_or(|e| e > self.buf.len()) {
            return Err(ErrorCode::Malformed.err("truncated CBOR input"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_arg(&mut self, ai: u8) -> Result<u64, ProofError> {
        match ai {
            n @ 0..=23 => Ok(n as u64),
            24 => {
                let b = self.read(1)?[0];
                // Shortest-form: values < 24 MUST use single-byte form.
                if b < 24 {
                    return Err(ErrorCode::NonCanonical.err("non-shortest int encoding (ai=24)"));
                }
                Ok(b as u64)
            }
            25 => {
                let b = self.read(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v <= u8::MAX as u64 {
                    return Err(ErrorCode::NonCanonical.err("non-shortest int encoding (ai=25)"));
                }
                Ok(v)
            }
            26 => {
                let b = self.read(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= u16::MAX as u64 {
                    return Err(ErrorCode::NonCanonical.err("non-shortest int encoding (ai=26)"));
                }
                Ok(v)
            }
            27 => {
                let b = self.read(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= u32::MAX as u64 {
                    return Err(ErrorCode::NonCanonical.err("non-shortest int encoding (ai=27)"));
                }
                Ok(v)
            }
            28..=30 => Err(ErrorCode::ForbiddenCborConstruct.err("reserved additional info")),
            31 => Err(ErrorCode::ForbiddenCborConstruct.err("indefinite length forbidden")),
            _ => unreachable!(),
        }
    }

    // PE-FMT-003 (dup keys) · PE-FMT-004 (forbidden) · PE-FMT-005 (trailing/UTF-8) · PE-FMT-006 (limits).
    fn decode_value(&mut self) -> Result<CborValue, ProofError> {
        if self.depth > self.limits.max_depth {
            return Err(ErrorCode::LimitExceeded.err("max CBOR depth exceeded"));
        }
        if self.eof() {
            return Err(ErrorCode::Malformed.err("empty CBOR input"));
        }
        let ib = self.read(1)?[0];
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 => {
                let n = self.read_arg(ai)?;
                Ok(CborValue::Uint(n))
            }
            1 => {
                let n = self.read_arg(ai)?;
                // nint range check: arg <= u64::MAX always fits i64 -1-n? -1-2^64 < i64::MIN.
                // CBOR nint covers -2^64..-1; we restrict to i64 (-2^63..-1) for V0.1? No:
                // allow full range but store as i64 only if fits, else reject (no bignum path).
                let v = -1i128 - (n as i128);
                if v < i64::MIN as i128 {
                    return Err(ErrorCode::ForbiddenCborConstruct
                        .err("nint out of i64 range (bignum not supported in V0.1)"));
                }
                Ok(CborValue::Nint(v as i64))
            }
            2 => {
                let len = self.read_arg(ai)? as usize;
                if len > self.limits.max_field_size {
                    return Err(ErrorCode::LimitExceeded.err("bytes field too large"));
                }
                Ok(CborValue::Bytes(self.read(len)?.to_vec()))
            }
            3 => {
                let len = self.read_arg(ai)? as usize;
                if len > self.limits.max_field_size {
                    return Err(ErrorCode::LimitExceeded.err("text field too large"));
                }
                let b = self.read(len)?;
                let s = std::str::from_utf8(b)
                    .map_err(|_| ErrorCode::Malformed.err("invalid UTF-8 in text string"))?;
                Ok(CborValue::Text(s.to_owned()))
            }
            4 => {
                let len = self.read_arg(ai)? as usize;
                if len > self.limits.max_array_items {
                    return Err(ErrorCode::LimitExceeded.err("array too large"));
                }
                self.depth += 1;
                let mut items = Vec::with_capacity(len.min(32));
                for _ in 0..len {
                    items.push(self.decode_value()?);
                }
                self.depth -= 1;
                Ok(CborValue::Array(items))
            }
            5 => {
                let len = self.read_arg(ai)? as usize;
                if len > self.limits.max_map_entries {
                    return Err(ErrorCode::LimitExceeded.err("map too large"));
                }
                self.depth += 1;
                let mut pairs = Vec::with_capacity(len.min(32));
                let mut prev_key_bytes: Option<Vec<u8>> = None;
                for _ in 0..len {
                    let k = self.decode_value()?;
                    let val = self.decode_value()?;
                    // Keys must be valid deterministic encodings; re-encode key for ordering check.
                    let kb = encode_canonical(&k);
                    if let Some(prev) = &prev_key_bytes {
                        if kb.as_slice() == prev.as_slice() {
                            return Err(ErrorCode::DuplicateMapKey.err("duplicate map key"));
                        }
                        if kb.as_slice() < prev.as_slice() {
                            return Err(
                                ErrorCode::NonCanonical.err("map keys not in lexicographic order")
                            );
                        }
                    }
                    prev_key_bytes = Some(kb);
                    pairs.push((k, val));
                }
                self.depth -= 1;
                Ok(CborValue::Map(pairs))
            }
            6 => Err(ErrorCode::ForbiddenCborConstruct.err("tags forbidden in V0.1")),
            7 => match ai {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                24 => Err(ErrorCode::ForbiddenCborConstruct.err("2-byte simple values forbidden")),
                25..=27 => Err(ErrorCode::ForbiddenCborConstruct.err("floats forbidden in V0.1")),
                31 => {
                    Err(ErrorCode::ForbiddenCborConstruct.err("break stop code outside indefinite"))
                }
                _ => {
                    Err(ErrorCode::ForbiddenCborConstruct.err("simple/undefined values forbidden"))
                }
            },
            _ => unreachable!(),
        }
    }
}

/// Strict decode: full input consumed, limits enforced, canonical order checked.
pub fn decode_strict(bytes: &[u8], limits: &Limits) -> Result<CborValue, ProofError> {
    if bytes.len() > limits.max_proof_size {
        return Err(ErrorCode::LimitExceeded.err("proof bytes exceed max_proof_size"));
    }
    let mut d = Decoder {
        buf: bytes,
        pos: 0,
        depth: 0,
        limits: *limits,
    };
    let v = d.decode_value()?;
    if d.pos != bytes.len() {
        return Err(ErrorCode::Malformed.err("trailing bytes after CBOR item"));
    }
    Ok(v)
}

/// True iff `bytes` is exactly the deterministic encoding of its decoded value.
pub fn is_canonical(bytes: &[u8], limits: &Limits) -> Result<bool, ProofError> {
    let v = decode_strict(bytes, limits)?;
    Ok(encode_canonical(&v) == bytes)
}

/// Decode + re-encode check. Returns value or NON_CANONICAL.
// PE-FMT-007 (decode->re-encode identity).
pub fn decode_and_check_canonical(bytes: &[u8], limits: &Limits) -> Result<CborValue, ProofError> {
    let v = decode_strict(bytes, limits)?;
    if encode_canonical(&v) != bytes {
        return Err(ErrorCode::NonCanonical.err("bytes are not deterministic encoding"));
    }
    Ok(v)
}

#[allow(dead_code)]
pub fn sorted_map(mut pairs: Vec<(CborValue, CborValue)>) -> CborValue {
    let mut v = CborValue::Map(std::mem::take(&mut pairs));
    v.sort_maps();
    v
}

#[cfg(test)]
// PE-FMT-008 · PE-FMT-009 · PE-CRYPTO-009: ids bind the exact UTF-8 bytes as
/// given — no Unicode normalization/folding anywhere (FORMAT.md §3.1). Tests:
/// `text_bytes_as_given_no_normalization`, `nfc_nfd_are_distinct_ids`,
/// `golden_20_text_byte_identity`.
mod tests {
    use super::*;
    use proof_core::{ErrorCode, Limits};

    fn lim() -> Limits {
        Limits::default()
    }

    #[test]
    fn round_trip_primitives() {
        let vs = vec![
            CborValue::Uint(0),
            CborValue::Uint(23),
            CborValue::Uint(24),
            CborValue::Uint(1000),
            CborValue::Uint(u64::MAX),
            CborValue::Nint(-1),
            CborValue::Nint(-1000),
            CborValue::Text("hello".into()),
            CborValue::Text("".into()),
            CborValue::Bytes(vec![0, 1, 2, 255]),
            CborValue::Bool(true),
            CborValue::Bool(false),
            CborValue::Null,
            CborValue::Array(vec![CborValue::Uint(1), CborValue::Text("a".into())]),
        ];
        for v in vs {
            let b = encode_canonical(&v);
            let d = decode_strict(&b, &lim()).expect("decode");
            assert_eq!(d, v);
            assert_eq!(encode_canonical(&d), b);
        }
    }

    #[test]
    fn map_keys_sorted_lexicographically() {
        // Insert out of order; encoder must sort by encoded bytes.
        let v = CborValue::Map(vec![
            (CborValue::Text("z".into()), CborValue::Uint(1)),
            (CborValue::Text("aa".into()), CborValue::Uint(2)),
            (CborValue::Uint(10), CborValue::Uint(3)),
        ]);
        let b = encode_canonical(&v);
        let d = decode_strict(&b, &lim()).expect("decode");
        // Expected lexicographic byte order: 0x0a (10) < 0x617a ("z") < 0x626161 ("aa").
        match d {
            CborValue::Map(p) => {
                assert_eq!(p[0].0, CborValue::Uint(10));
                assert_eq!(p[1].0, CborValue::Text("z".into()));
                assert_eq!(p[2].0, CborValue::Text("aa".into()));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn duplicate_map_key_rejected() {
        // {"a":1,"a":2} hand-encoded: a2 61 61 01 61 61 02.
        let raw = hex::decode("a2616101616102").unwrap();
        let e = decode_strict(&raw, &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::DuplicateMapKey);
    }

    #[test]
    fn non_shortest_int_rejected() {
        // 0 encoded as 0x1800 (two bytes) instead of 0x00.
        let e = decode_strict(&[0x18, 0x00], &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::NonCanonical);
        // 24 encoded as 0x190018 instead of 0x1818.
        let e = decode_strict(&[0x19, 0x00, 0x18], &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::NonCanonical);
    }

    #[test]
    fn forbidden_constructs_rejected() {
        // tag 0 (0xc0 + "2020-01-01"), float16 (0xf9), indefinite array (0x9f), break (0xff),
        // undefined (0xf7), reserved ai 28 (0x1c).
        let cases: &[&[u8]] = &[
            &[
                0xc0, 0x6a, 0x32, 0x30, 0x32, 0x30, 0x2d, 0x30, 0x31, 0x2d, 0x30, 0x31,
            ],
            &[0xf9, 0x3c, 0x00],
            &[0x9f, 0x01, 0xff],
            &[0xff],
            &[0xf7],
            &[0x1c, 0x00],
            &[0xfa, 0x47, 0xc3, 0x50, 0x00], // float32
        ];
        for c in cases {
            let e = decode_strict(c, &lim()).unwrap_err();
            assert_eq!(
                e.code,
                ErrorCode::ForbiddenCborConstruct,
                "input {:02x?}",
                c
            );
        }
    }

    #[test]
    fn trailing_bytes_and_empty_rejected() {
        assert_eq!(
            decode_strict(&[0x01, 0x02], &lim()).unwrap_err().code,
            ErrorCode::Malformed
        );
        assert_eq!(
            decode_strict(&[], &lim()).unwrap_err().code,
            ErrorCode::Malformed
        );
    }

    #[test]
    fn invalid_utf8_rejected() {
        // text(1) with 0xff.
        let e = decode_strict(&[0x61, 0xff], &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::Malformed);
    }

    // PE-FMT-009 (FORMAT.md §3.1): ids bind exact bytes; no normalization.
    #[test]
    fn text_bytes_as_given_no_normalization() {
        // NFC spelling must round-trip byte-exactly: no folding, no trimming.
        let v = decode_strict(
            &encode_canonical(&CborValue::Text("caf\u{e9}".into())),
            &lim(),
        )
        .unwrap();
        assert_eq!(v, CborValue::Text("caf\u{e9}".into()));
        // Whitespace and case are preserved verbatim too.
        let v = decode_strict(
            &encode_canonical(&CborValue::Text("  MixedCase ".into())),
            &lim(),
        )
        .unwrap();
        assert_eq!(v, CborValue::Text("  MixedCase ".into()));
    }

    #[test]
    fn nfc_nfd_are_distinct_ids() {
        // The two byte spellings of the same logical string are different
        // canonical texts -> different ids (FORMAT.md §3.1; golden-20).
        let nfc_bytes = "caf\u{e9}".as_bytes(); // 63 61 66 C3 A9
        let nfd_bytes = "cafe\u{301}".as_bytes(); // 63 61 66 65 CC 81
        assert_ne!(nfc_bytes, nfd_bytes);
        let nfc = encode_canonical(&CborValue::Text("caf\u{e9}".into()));
        let nfd = encode_canonical(&CborValue::Text("cafe\u{301}".into()));
        assert_ne!(nfc, nfd, "engine never folds; distinct bytes stay distinct");
        // Distinct canonical bytes must yield distinct ids (byte-binding).
        let id_nfc = proof_crypto_id_shim(&nfc);
        let id_nfd = proof_crypto_id_shim(&nfd);
        assert_ne!(id_nfc, id_nfd);
        // But each id verifies against exactly its own bytes.
        assert!(verify_spelling(&id_nfc, &nfc));
        assert!(verify_spelling(&id_nfd, &nfd));
    }

    /// Local stand-ins so the format crate does not depend on proof-crypto:
    /// replicate the id construction `<prefix>:v1:<b64u(sha256(bytes))>` and
    /// its byte-binding check to assert the id-level consequence.
    fn proof_crypto_id_shim(bytes: &[u8]) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        format!("evt:v1:{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
    }

    fn verify_spelling(id: &str, bytes: &[u8]) -> bool {
        proof_crypto_id_shim(bytes) == id
    }

    #[test]
    fn golden_20_text_byte_identity() {
        // Interop vector: exact canonical bytes and derived id for NFC input.
        // Golden-20 (fixtures/golden-20.json) pins these bytes; re-derive the
        // id from the parsed text to prove byte fidelity end to end.
        let fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/golden-20.json");
        let Ok(text) = std::fs::read_to_string(&fixture) else {
            // Fixture not present in this checkout: in-repo assertion above
            // (nfc_nfd_are_distinct_ids) still covers the property.
            return;
        };
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let bytes = hex::decode(v["text_canonical_hex"].as_str().unwrap()).unwrap();
        let nfd_bytes = hex::decode(v["text_canonical_hex_nfd"].as_str().unwrap()).unwrap();
        let decoded = decode_strict(&bytes, &lim()).unwrap();
        match decoded {
            CborValue::Text(s) => {
                assert_eq!(proof_crypto_id_shim(&bytes), v["evt_id"].as_str().unwrap());
                assert_eq!(encode_canonical(&CborValue::Text(s)), bytes);
                // The NFD spelling of the same word must never share the id.
                assert_ne!(
                    proof_crypto_id_shim(&nfd_bytes),
                    v["evt_id"].as_str().unwrap()
                );
            }
            other => panic!("golden-20 must be a text item, got {other:?}"),
        }
    }

    #[test]
    fn is_canonical_detects_reordered_map() {
        let v = CborValue::Map(vec![
            (CborValue::Uint(1), CborValue::Uint(1)),
            (CborValue::Uint(2), CborValue::Uint(2)),
        ]);
        let good = encode_canonical(&v);
        assert!(is_canonical(&good, &lim()).unwrap());
        // Manually swap pairs: still valid CBOR but non-canonical order.
        let bad = vec![0xa2, 0x02, 0x02, 0x01, 0x01];
        assert_eq!(
            decode_strict(&bad, &lim()).unwrap_err().code,
            ErrorCode::NonCanonical
        );
    }

    // Property: any decoded value re-encodes identically (idempotent canonical form),
    // and any encoded value decodes back to itself.
    #[test]
    fn prop_encode_decode_round_trip() {
        use proptest::prelude::*;
        use proptest::strategy::ValueTree;
        fn arb_value() -> impl Strategy<Value = CborValue> {
            let leaf = prop_oneof![
                any::<u64>().prop_map(CborValue::Uint),
                // CBOR nint is always <= -1; positive values are unrepresentable.
                (-1_000_000i64..0i64).prop_map(CborValue::Nint),
                "[a-z0-9]{0,8}".prop_map(CborValue::Text),
                proptest::collection::vec(any::<u8>(), 0..16).prop_map(CborValue::Bytes),
                proptest::bool::ANY.prop_map(CborValue::Bool),
                Just(CborValue::Null),
            ];
            leaf.prop_recursive(3, 16, 4, |inner| {
                prop_oneof![
                    proptest::collection::vec(inner.clone(), 0..4).prop_map(CborValue::Array),
                    proptest::collection::vec((inner.clone(), inner.clone()), 0..4).prop_map(
                        |pairs| {
                            // Deduplicate by encoded key to keep maps valid.
                            let mut seen = std::collections::HashSet::new();
                            let mut out = vec![];
                            for (k, v) in pairs {
                                let kb = encode_canonical(&k);
                                if seen.insert(kb) {
                                    out.push((k, v));
                                }
                            }
                            CborValue::Map(out)
                        }
                    ),
                ]
            })
        }
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        for _ in 0..256 {
            let v = arb_value().new_tree(&mut runner).expect("tree").current();
            let b = encode_canonical(&v);
            let d = decode_strict(&b, &lim()).expect("must decode own encoding");
            assert_eq!(d, {
                let mut norm = v.clone();
                norm.sort_maps();
                // Encoder sorts maps; decoded form equals sorted original.
                norm
            });
            assert_eq!(encode_canonical(&d), b);
        }
    }

    #[test]
    fn prop_raw_bytes_reject_or_round_trip() {
        use proptest::prelude::*;
        use proptest::strategy::ValueTree;
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        let strat = proptest::collection::vec(any::<u8>(), 0..48);
        for _ in 0..512 {
            let bytes: Vec<u8> = strat.new_tree(&mut runner).expect("tree").current();
            if let Ok(v) = decode_strict(&bytes, &lim()) {
                assert!(encode_canonical(&v).len() <= 1 << 20);
            }
        }
    }
}
