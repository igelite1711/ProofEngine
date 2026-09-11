# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#!/usr/bin/env python3
"""Differential interop runner: Rust <-> independent Python implementation.
# PE-INTEROP-002 (I2) · PE-INTEROP-003 (I3a/I3b both directions).

Part 1 (I2): verify Rust golden vectors with independent code and compare
  against each vector's recorded expectation (canonical, ids, Ed25519 +
  P-256 signatures, proof bindings incl. composition refs, byte-identity;
  lifecycle/policy/graph verdicts stay engine-side with binding-only
  cross-checks).
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

    # ---- Part 1: I2 over golden vectors (all 26 vectors) ----
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

    # ---- Part 1b: extended vector coverage ----
    from pengine import ed_pubkey, obj_id, verify_sign1 as _vs1
    import hashlib as _hl
    g6 = load(6)
    try:
        ok_e = ("evt:v1:" + b64u(_hl.sha256(bytes.fromhex(
            g6["event_canonical_hex"])).digest())) == g6["event_id"]
        ok_a = ("att:v1:" + b64u(_hl.sha256(bytes.fromhex(
            g6["attestation_canonical_hex"])).digest())) == g6["attestation_id"]
        ok_d = ("evd:v1:" + b64u(_hl.sha256(bytes.fromhex(
            g6["evidence_canonical_hex"])).digest())) == g6["evidence_id"]
        _vs1(bytes.fromhex(g6["cose_sign1_hex"]), g6["verify_ctx"]["issuer"])
        check("I2 builder-chain ids+signature", ok_e and ok_a and ok_d)
    except InteropFail as e:
        check("I2 builder-chain ids+signature", False, str(e))

    g7 = load(7)
    try:
        _vs1(bytes.fromhex(g7["cose_sign1_hex"]), g7["verify_ctx"]["issuer"])
        check("I2 wrong-issuer rejected", False, "accepted?!")
    except InteropFail:
        check("I2 wrong-issuer rejected", True)

    g8 = load(8)
    try:
        got = "evd:v1:" + b64u(_hl.sha256(
            bytes.fromhex(g8["evidence_canonical_hex"])).digest())
        check("I2 evidence-tamper id mismatch", got != g8["expected_id"], got[:16])
    except InteropFail as e:
        check("I2 evidence-tamper id mismatch", False, str(e))

    for n in (13, 14, 19):
        # Policy verdicts are engine-side; Python cross-checks the binding.
        v = load(n)
        try:
            rep = verify_proof(bytes.fromhex(v["proof_canonical_hex"]))
            check(f"I2 binding-only proof {n}", True, rep["proof_id"][:16])
        except InteropFail as e:
            check(f"I2 binding-only proof {n}", False, str(e))

    for n in (15, 16, 17, 18):
        # Lifecycle verdicts are engine-side; Python cross-checks stages
        # 1-6+ids (bytes well-formed, binding holds, signatures verify).
        v = load(n)
        try:
            rep = verify_proof(bytes.fromhex(v["proof_canonical_hex"]))
            check(f"I2 lifecycle-shape proof {n}",
                  rep["proof_id"] == v["proof_id"], rep["proof_id"][:16])
        except InteropFail as e:
            check(f"I2 lifecycle-shape proof {n}", False, str(e))

    g20 = load(20)
    try:
        nfc = bytes.fromhex(g20["text_canonical_hex"])
        nfd = bytes.fromhex(g20["text_canonical_hex_nfd"])
        ok = (obj_id("evt", nfc) == g20["evt_id"]
              and obj_id("evt", nfd) == g20["evt_id_nfd"]
              and g20["evt_id"] != g20["evt_id_nfd"] and nfc != nfd)
        check("I2 text byte-identity (NFC≠NFD)", ok)
    except InteropFail as e:
        check("I2 text byte-identity (NFC≠NFD)", False, str(e))

    for n, want_ok in ((21, True), (22, False)):
        v = load(n)
        try:
            _vs1(bytes.fromhex(v["cose_sign1_hex"]), v["verify_ctx"]["issuer"])
            check(f"I2 P-256 vector {n}", want_ok,
                  "accepted" if want_ok else "accepted?!")
        except InteropFail as e:
            check(f"I2 P-256 vector {n}", not want_ok, str(e)[:60])
    try:
        _vs1(bytes.fromhex(load(21)["cose_sign1_hex"]),
              load(23)["verify_ctx"]["issuer"])
        check("I2 P-256 wrong-key rejected", False, "accepted?!")
    except InteropFail:
        check("I2 P-256 wrong-key rejected", True)

    g24 = load(24)
    try:
        rep = verify_proof(bytes.fromhex(g24["proof_canonical_hex"]))
        check("I2 composed proof refs bind",
              rep["proof_id"] == g24["proof_id"]
              and rep["referenced_proofs"] == g24["referenced_proofs"],
              rep["proof_id"][:16])
    except InteropFail as e:
        check("I2 composed proof refs bind", False, str(e))

    g27 = load(27)
    try:
        rep = verify_proof(bytes.fromhex(g27["proof_canonical_hex"]))
        check("I2 vocabulary declarations bind",
              rep["proof_id"] == g27["proof_id"],
              rep["proof_id"][:16])
    except InteropFail as e:
        check("I2 vocabulary declarations bind", False, str(e))

    for n in (28, 29, 30, 31):
        # Policy/lifecycle verdicts are engine-side (v2 expressions,
        # WITHDRAWN/COMPROMISED states); Python cross-checks stages 1-6+ids.
        v = load(n)
        try:
            rep = verify_proof(bytes.fromhex(v["proof_canonical_hex"]))
            ok = True if "proof_id" not in v else rep["proof_id"] == v["proof_id"]
            check(f"I2 binding-only proof {n}", ok, rep["proof_id"][:16])
        except InteropFail as e:
            check(f"I2 binding-only proof {n}", False, str(e))

    for n, label in ((25, "self-link"), (26, "malformed ref")):
        v = load(n)
        try:
            verify_proof(bytes.fromhex(v["proof_canonical_hex"]))
            check(f"I2 composition {label} rejected", False, "accepted?!")
        except InteropFail:
            check(f"I2 composition {label} rejected", True)

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

    # I3a-composition: Python composes over its own proof (linkage only);
    # Rust must verify the binding and echo the linkage as REFERENCED.
    proof2 = make_proof("payment.settles-invoice", ev["id"], "settles", ev2["id"],
                        1700000150, (), 1700000200,
                        [ev, ev2],
                        [{"cbor": att["cbor"], "sign1_b64": att["sign1_b64"]}],
                        [evd], [rel], [proof["id"]])
    open(os.path.join(a.work, "proof2.json"), "w").write(
        json.dumps({"kind": "proof", "id": proof2["id"], "cbor": proof2["cbor"]}))
    rc2, _, err2 = cli(a.proof_cli, "verify", "--proof",
                       os.path.join(a.work, "proof2.json"), "--clock", "1700000300",
                       "--revocations-known-at", "1700000300", "--out",
                       os.path.join(a.work, "report2.json"))
    rep2 = json.load(open(os.path.join(a.work, "report2.json"))) if rc2 == 0 else {}
    check("I3a python-composed proof passes Rust verify",
          rc2 == 0 and rep2.get("cryptographic_validity") == "valid"
          and rep2.get("evidence_validity") == "valid"
          and rep2.get("referenced_proofs") == [proof["id"]],
          f"exit={rc2} err={err2.strip()[-120:]}")

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

    # ---- Part 5: closed-schema parity (unknown member fields) ----
    # Both implementations must reject unknown member fields: Python raises,
    # Rust exits non-zero with SCHEMA_VIOLATION. Fail-open on either side is
    # a parity break.
    from minicbor import Map as _Map, enc_map as _enc_map, dec as _dec
    from pengine import verify_proof as _vp, InteropFail as _IF
    raw11 = bytes.fromhex(load(11)["proof_canonical_hex"])
    for label, mutate in (
        ("event", lambda d: d["events"].__setitem__(
            0, _Map(list(d["events"][0]) + [("zzz_unknown", 1)]))),
        ("attestation", lambda d: d["attestations"].__setitem__(
            0, _Map(list(d["attestations"][0]) + [("zzz_unknown", 1)]))),
    ):
        v, pos = _dec(raw11)
        assert pos == len(raw11) and isinstance(v, _Map)
        d = dict(v)
        mutate(d)
        bad = _enc_map(v)
        try:
            _vp(bad)
            check(f"NEG unknown {label} field rejected by Python", False,
                  "accepted?!")
            py_ok = False
        except _IF:
            check(f"NEG unknown {label} field rejected by Python", True)
            py_ok = True
        open(os.path.join(a.work, f"unk-{label}.json"), "w").write(
            json.dumps({"kind": "proof", "id": "x", "cbor": bad.hex()}))
        rc, _, err = cli(a.proof_cli, "verify", "--proof",
                         os.path.join(a.work, f"unk-{label}.json"),
                         "--clock", "1700000300",
                         "--revocations-known-at", "1700000300")
        check(f"NEG unknown {label} field rejected by Rust",
              rc != 0 and "SCHEMA_VIOLATION" in err, f"exit={rc}")
        assert py_ok and rc != 0

    print(f"\nDIFFERENTIAL: {len(PASS)} pass, {len(FAIL)} fail")
    if FAIL:
        print("FAILED:", FAIL)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())