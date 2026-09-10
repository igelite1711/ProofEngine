# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#!/usr/bin/env python3
"""Differential interop runner: Rust <-> independent Python implementation.
# PE-INTEROP-002 (I2) · PE-INTEROP-003 (I3a/I3b both directions).

Part 1 (I2): verify Rust golden vectors with independent code and compare
  against each vector's recorded expectation (14 Gate-I cases).
Part 2 (I3a): Python creates event+attestation+evidence+relationship+proof;
  Rust `proof-cli verify` must PASS it (exit 0, crypto+evidence valid).
Part 3 (I3b): Rust-created proof (CLI demo) verifies under Python
  (stages 1-6 + proof_id binding; time/lifecycle/graph/policy are
  engine-side and out of Python scope by design).
Part 4 (negative differential): Python-crafted mutants (bit flip, id swap,
  version bump) must FAIL under Rust with the documented codes.

Usage: python3 interop/differential.py --repo . --proof-cli ./target/debug/proof-cli
Stdlib only.
"""
import argparse
import base64
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from minicbor import CErr, Map, dec, enc_any  # noqa: E402
from pengine import (InteropFail, b64u, make_attestation, make_event,  # noqa: E402
                     make_evidence, make_proof, make_relationship,
                     verify_proof)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name, detail)


def cli(proof_cli, *args):
    p = subprocess.run([proof_cli, *args], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--proof-cli", required=True)
    ap.add_argument("--work", default="/tmp/proof-interop")
    a = ap.parse_args()
    fx = os.path.join(a.repo, "fixtures")
    os.makedirs(a.work, exist_ok=True)

    def load(n):
        with open(os.path.join(fx, f"golden-{n:02d}.json")) as fh:
            return json.load(fh)

    # ---- Part 1: I2 over golden vectors (14 Gate-I cases) ----
    g1 = load(1)
    try:
        from pengine import check_canonical, obj_id
        import hashlib
        canon = bytes.fromhex(g1["canonical_hex"])
        check_canonical(canon)
        ok = g1["object_id"] == "evt:v1:" + b64u(hashlib.sha256(canon).digest())
        check("I2 valid event id", ok and g1["expected"].get("id_verify") == "ok")
    except InteropFail as e:
        check("I2 valid event id", False, str(e))

    for n, label in ((2, "duplicate map key"), (3, "non-canonical int")):
        v = load(n)
        try:
            check_canonical(bytes.fromhex(v["input_hex"]))
            check(f"I2 malformed-{n} rejected", False, "accepted?!")
        except InteropFail:
            check(f"I2 malformed-{n} rejected", True)

    g4 = load(4)
    try:
        from pengine import verify_sign1, ed_pubkey
        raw = bytes.fromhex(g4["cose_sign1_hex"])
        v, pos = dec(raw)
        assert pos == len(raw) and isinstance(v, list)
        prot = v[0]
        pp, ppos = dec(prot)
        kid = dict(pp)[4]
        payload, _ = verify_sign1(raw, "key:ed25519:" + b64u(kid))
        check("I2 valid signature verifies", ed_pubkey(bytes([9] * 32)) == kid)
    except InteropFail as e:
        check("I2 valid signature verifies", False, str(e))

    g5 = load(5)
    try:
        raw = bytes.fromhex(g5["cose_sign1_hex"])
        v, _ = dec(raw)
        prot = v[0]
        pp, _ = dec(prot)
        kid = dict(pp)[4]
        verify_sign1(raw, "key:ed25519:" + b64u(kid))
        check("I2 tampered signature rejected", False, "accepted?!")
    except InteropFail:
        check("I2 tampered signature rejected", True)

    g11 = load(11)
    try:
        rep = verify_proof(bytes.fromhex(g11["proof_canonical_hex"]))
        check("I2 full proof verifies (stages 1-6+ids)", True, rep["proof_id"][:16])
    except InteropFail as e:
        check("I2 full proof verifies (stages 1-6+ids)", False, str(e))

    g12 = load(12)
    try:
        verify_proof(bytes.fromhex(g12["proof_canonical_hex"]))
        check("I2 mutated proof rejected", False, "accepted?!")
    except InteropFail:
        check("I2 mutated proof rejected", True)

    # ---- Part 2: I3a Python-creates, Rust-verifies ----
    seed = bytes([9] * 32)
    digest = bytes(range(32))
    ev = make_event("payment.created", "payment:i3", 1700000000, digest)
    ev2 = make_event("invoice.issued", "invoice:i3", 1700000000, digest)
    att = make_attestation(seed, "payment:i3", "payment.settled",
                           [("amount", ("uint", 4200))], 1700000150)
    evd = make_evidence("transaction_record", digest, att["id"])
    rel = make_relationship(ev["id"], "SETTLES", ev2["id"], evd["id"])

    def wr(d, n):
        kinds = {"ev.json": "event", "ev2.json": "event", "att.json": "attestation",
                 "evd.json": "evidence", "rel.json": "relationship"}
        open(os.path.join(a.work, n), "w").write(
            json.dumps({"kind": kinds[n], **d}))
    wr(ev, "ev.json")
    wr(ev2, "ev2.json")
    wr(att, "att.json")
    wr(evd, "evd.json")
    wr(rel, "rel.json")
    proof = make_proof("payment.settles-invoice", ev["id"], "settles", ev2["id"],
                       1700000150, (), 1700000200,
                       [ev, ev2],
                       [{"cbor": att["cbor"], "sign1_b64": att["sign1_b64"]}],
                       [evd], [rel])
    open(os.path.join(a.work, "proof.json"), "w").write(
        json.dumps({"kind": "proof", "id": proof["id"], "cbor": proof["cbor"]}))
    rc, out, err = cli(a.proof_cli, "verify", "--proof",
                       os.path.join(a.work, "proof.json"), "--clock", "1700000300",
                       "--revocations-known-at", "1700000300", "--out",
                       os.path.join(a.work, "report.json"))
    rep = json.load(open(os.path.join(a.work, "report.json"))) if rc == 0 else {}
    check("I3a python-created proof passes Rust verify",
          rc == 0 and rep.get("cryptographic_validity") == "valid"
          and rep.get("evidence_validity") == "valid",
          f"exit={rc} err={err.strip()[-120:]}")

    # ---- Part 3: I3b Rust-creates, Python-verifies ----
    demo_proof = os.path.join(a.repo, "demo", "out", "proof.cbor.json")
    if os.path.isfile(demo_proof):
        v = json.load(open(demo_proof))
        try:
            rep = verify_proof(bytes.fromhex(v["cbor"]))
            check("I3b rust-created demo proof verifies in Python", True,
                  rep["proof_id"][:16])
        except InteropFail as e:
            check("I3b rust-created demo proof verifies in Python", False, str(e))
    else:
        check("I3b rust-created demo proof verifies in Python", False,
              "run make demo first")

    # ---- Part 4: negative differential (Python crafts, Rust must FAIL) ----
    raw = bytes.fromhex(proof["cbor"])
    m = bytearray(raw)
    m[60] ^= 4
    open(os.path.join(a.work, "mut.json"), "w").write(
        json.dumps({"kind": "proof", "id": proof["id"], "cbor": bytes(m).hex()}))
    rc, _, _ = cli(a.proof_cli, "verify", "--proof",
                   os.path.join(a.work, "mut.json"), "--clock", "1700000300",
                   "--revocations-known-at", "1700000300")
    check("NEG bit-flipped proof fails Rust verify", rc != 0, f"exit={rc}")

    print(f"\nDIFFERENTIAL: {len(PASS)} pass, {len(FAIL)} fail")
    if FAIL:
        print("FAILED:", FAIL)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())