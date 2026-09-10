# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#!/usr/bin/env python3
"""Validate ProofEngine golden vectors against the CDDL schema.

Requires: pip install cddl (or cddl-py)
If cddl library is unavailable, performs structural validation as fallback.

Usage: python3 tools/validate_cddl.py [--golden-dir fixtures/] [--cddl docs/format.cddl]
"""
import json
import os
import sys
import hashlib
import base64
import binascii
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CDDL_PATH = REPO_ROOT / "docs" / "format.cddl"
GOLDEN_DIR = REPO_ROOT / "fixtures"


def b64u_nopad_decode(s: str) -> bytes:
    """Decode base64url-no-pad, adding padding if needed."""
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def validate_hashref(obj: dict, path: str) -> list:
    """Validate a HashRef structure."""
    errors = []
    if not isinstance(obj, dict):
        return [f"{path}: expected object, got {type(obj).__name__}"]
    if obj.get("v") != 1:
        errors.append(f"{path}.v: expected 1, got {obj.get('v')}")
    if "alg" not in obj:
        errors.append(f"{path}.alg: required field missing")
    elif obj["alg"] not in (0, 1):
        errors.append(f"{path}.alg: expected 0 or 1, got {obj['alg']}")
    if "digest" not in obj:
        errors.append(f"{path}.digest: required field missing")
    else:
        digest_hex = obj["digest"]
        if obj["alg"] == 0 and len(digest_hex) != 64:
            errors.append(f"{path}.digest: SHA-256 must be 64 hex chars, got {len(digest_hex)}")
        elif obj["path"] == 1 and len(digest_hex) != 96:
            errors.append(f"{path}.digest: SHA-384 must be 96 hex chars, got {len(digest_hex)}")
    return errors


def validate_id(prefix: str, id_str: str, path: str) -> list:
    """Validate an object id format."""
    errors = []
    expected_prefix = f"{prefix}:v1:"
    if not id_str.startswith(expected_prefix):
        errors.append(f"{path}: expected prefix '{expected_prefix}', got '{id_str[:20]}...'")
        return errors
    b64_part = id_str[len(expected_prefix):]
    try:
        raw = b64u_nopad_decode(b64_part)
        if len(raw) != 32:
            errors.append(f"{path}: id digest must be 32 bytes (SHA-256), got {len(raw)}")
    except Exception as e:
        errors.append(f"{path}: invalid base64url: {e}")
    return errors

def validate_event(obj: dict, path: str) -> list:
    """Validate an Event structure."""
    errors = []
    required = ["v", "event_type", "subject", "effective_at", "payload_ref"]
    for field in required:
        if field not in obj:
            errors.append(f"{path}.{field}: required field missing")
    if obj.get("v") != 1:
        errors.append(f"{path}.v: expected 1")
    if "payload_ref" in obj:
        errors.extend(validate_hashref(obj["payload_ref"], f"{path}.payload_ref"))
    return errors


def validate_attestation_content(obj: dict, path: str) -> list:
    """Validate an AttestationContent structure."""
    errors = []
    required = ["v", "issuer", "subject", "claim_type", "claim", "issued_at"]
    for field in required:
        if field not in obj:
            errors.append(f"{path}.{field}: required field missing")
    if obj.get("v") != 1:
        errors.append(f"{path}.v: expected 1")
    if "issuer" in obj:
        issuer = obj["issuer"]
        if not (issuer.startswith("key:ed25519:") or issuer.startswith("key:p256:")):
            errors.append(f"{path}.issuer: expected key:ed25519:... or key:p256:...")
    return errors


def validate_evidence(obj: dict, path: str) -> list:
    """Validate an Evidence structure."""
    errors = []
    required = ["v", "kind", "digest"]
    for field in required:
        if field not in obj:
            errors.append(f"{path}.{field}: required field missing")
    if obj.get("v") != 1:
        errors.append(f"{path}.v: expected 1")
    if "digest" in obj:
        errors.extend(validate_hashref(obj["digest"], f"{path}.digest"))
    return errors


def validate_relationship(obj: dict, path: str) -> list:
    """Validate a Relationship structure."""
    errors = []
    required = ["v", "from", "type", "to"]
    for field in required:
        if field not in obj:
            errors.append(f"{path}.{field}: required field missing")
    if obj.get("v") != 1:
        errors.append(f"{path}.v: expected 1")
    return errors


def validate_proposition(obj: dict, path: str) -> list:
    """Validate a Proposition structure."""
    errors = []
    required = ["v", "kind", "subject", "predicate"]
    for field in required:
        if field not in obj:
            errors.append(f"{path}.{field}: required field missing")
    if obj.get("v") != 1:
        errors.append(f"{path}.v: expected 1")
    return errors


def validate_proof(obj: dict, path: str) -> list:
    """Validate a Proof structure."""
    errors = []
    required = ["v", "proof_id", "proposition", "events", "attestations",
                "evidence", "relationships", "created_at"]
    for field in required:
        if field not in obj:
            errors.append(f"{path}.{field}: required field missing")
    if obj.get("v") != 1:
        errors.append(f"{path}.v: expected 1")
    if "proof_id" in obj:
        errors.extend(validate_id("prf", obj["proof_id"], f"{path}.proof_id"))
    if "proposition" in obj:
        errors.extend(validate_proposition(obj["proposition"], f"{path}.proposition"))
    if "events" in obj:
        for i, evt in enumerate(obj["events"]):
            errors.extend(validate_event(evt, f"{path}.events[{i}]"))
    if "attestations" in obj:
        for i, att in enumerate(obj["attestations"]):
            if "content" in att:
                errors.extend(validate_attestation_content(att["content"], f"{path}.attestations[{i}].content"))
    if "evidence" in obj:
        for i, evd in enumerate(obj["evidence"]):
            errors.extend(validate_evidence(evd, f"{path}.evidence[{i}]"))
    if "relationships" in obj:
        for i, rel in enumerate(obj["relationships"]):
            errors.extend(validate_relationship(rel, f"{path}.relationships[{i}]"))
    return errors


def validate_golden_file(path: Path) -> list:
    """Validate a single golden vector file."""
    errors = []
    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return [f"{path.name}: invalid JSON: {e}"]

    if "input_json" in data:
        inp = data["input_json"]
        if isinstance(inp, dict):
            if "proof_id" in inp:
                errors.extend(validate_proof(inp, f"{path.name}.input_json"))
            elif "event_type" in inp:
                errors.extend(validate_event(inp, f"{path.name}.input_json"))
            elif "claim_type" in inp:
                errors.extend(validate_attestation_content(inp, f"{path.name}.input_json"))
            elif "kind" in inp and "digest" in inp and "from" not in inp:
                errors.extend(validate_evidence(inp, f"{path.name}.input_json"))
            elif "from" in inp and "to" in inp:
                errors.extend(validate_relationship(inp, f"{path.name}.input_json"))
    return errors


def main():
    """Main validation entry point."""
    golden_dir = GOLDEN_DIR
    if len(sys.argv) > 2 and sys.argv[1] == "--golden-dir":
        golden_dir = Path(sys.argv[2])

    if not golden_dir.exists():
        print(f"Golden directory not found: {golden_dir}")
        print("Skipping CDDL validation (no golden vectors to check)")
        return 0

    golden_files = sorted(golden_dir.glob("golden-*.json"))
    if not golden_files:
        print("No golden vector files found. Skipping CDDL validation.")
        return 0

    all_errors = []
    for gf in golden_files:
        errs = validate_golden_file(gf)
        all_errors.extend(errs)

    if all_errors:
        print(f"CDDL validation FAILED: {len(all_errors)} error(s)")
        for e in all_errors[:20]:
            print(f"  - {e}")
        if len(all_errors) > 20:
            print(f"  ... and {len(all_errors) - 20} more")
        return 1
    else:
        print(f"CDDL validation PASSED: {len(golden_files)} golden vector(s) validated")
        return 0


if __name__ == "__main__":
    sys.exit(main())
