#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent (stdlib-only) differential for the SCITT adapter fixtures.

Recomputes the statement digest from the envelope WITHOUT Rust: canonical
bytes are rebuilt field-by-field in struct order
(v,feed,cti,payload_sha256,issued_at,kid — compact JSON, exact key order is
part of the adapter contract), sha256-hashed, and compared against the
expected mapping. Signature verification stays Rust-side (stdlib has no
Ed25519); binding preservation is what this script proves.

Usage: python3 crates/proof-adapter-scitt/differential.py
Exit 0 = all checks pass.
"""

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


def canonical_bytes(statement: dict) -> bytes:
    # Exact adapter wire order; separators eliminate whitespace ambiguity.
    ordered = (
        '{"v":%d,"feed":%s,"cti":%s,"payload_sha256":%s,"issued_at":%d,"kid":%s}'
        % (
            statement["v"],
            json.dumps(statement["feed"]),
            json.dumps(statement["cti"]),
            json.dumps(statement["payload_sha256"]),
            statement["issued_at"],
            json.dumps(statement["kid"]),
        )
    )
    return ordered.encode("utf-8")


def main() -> int:
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail and not ok else ""))
        if not ok:
            failures += 1

    env = json.loads((FIX / "scitt-statement-01.json").read_text())
    mapping = json.loads((FIX / "scitt-mapping-01.json").read_text())
    st = env["statement"]

    digest_hex = hashlib.sha256(canonical_bytes(st)).hexdigest()
    check("statement digest reproduces mapping", digest_hex == mapping["statement_digest_hex"],
          f"got {digest_hex}")
    check("subject convention matches",
          mapping["subject"] == f"scitt:{st['feed']}:{st['cti']}")
    check("issuer matches kid", mapping["issuer"] == st["kid"])
    check("envelope carries a signature", isinstance(env.get("signature_b64u"), str)
          and len(env["signature_b64u"]) > 0)
    check("mapping names both evidence kinds",
          set(mapping["evidence_kinds"]) == {"transparency_registration", "transparency_receipt"})

    print(f"DIFFERENTIAL: {5 - failures} pass, {failures} fail")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
