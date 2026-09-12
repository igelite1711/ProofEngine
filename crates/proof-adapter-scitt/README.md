# proof-adapter-scitt — SCITT transparency adapter (P7, perimeter)

Maps IETF SCITT-style signed statements ↔ Proof Engine attestations +
`transparency_registration` / `transparency_receipt` evidence +
`transparency.checkpoint` attestations. The sha256 of the canonical SCITT
JSON rides digest-bound in Evidence, so the mapping survives both
directions cryptographically.

```bash
cargo test -p proof-adapter-scitt
python3 crates/proof-adapter-scitt/differential.py
make scitt-check   # both (Rust tests + independent Python differential)
```

Boundary: Ed25519 statement signatures only. X.509 chains, DIDs, and
Merkle inclusion/consistency proofs fail `SCHEMA_VIOLATION` — never
approximated. See `src/lib.rs` trust-boundary docs and `fixtures/`.
