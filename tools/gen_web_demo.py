#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate the browser demo data by running the real proof-cli.

Every proof, report, and policy outcome embedded in demo/web/index.html is
produced here by the core through proof-cli -- nothing is simulated.
Deterministic: fixed timestamps + `--seed test`, so two runs yield identical
data (the honesty gate depends on this).

Usage:
    python3 tools/gen_web_demo.py --work /tmp/webgen --out demo/web/index.html
    python3 tools/gen_web_demo.py --work /tmp/webgen --data-only /tmp/data.json
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLI_BIN = None

D1 = "5e" * 32
D2 = "a7" * 32
D3 = "e1" * 32


def cli_binary():
    """Build once from the repo, then resolve the real binary path.

    `cargo run` requires the workspace as cwd, but artifacts must land in
    the work dir -- so invoke the built binary directly instead.
    """
    global CLI_BIN
    if CLI_BIN is not None:
        return CLI_BIN
    subprocess.run(
        ["cargo", "build", "--locked", "-p", "proof-cli"],
        cwd=REPO, check=True, capture_output=True,
    )
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1",
         "--manifest-path", str(REPO / "Cargo.toml")],
        cwd=REPO, check=True, capture_output=True, text=True,
    ).stdout)
    bina = str(Path(meta["target_directory"]) / "debug" / "proof-cli")
    if not Path(bina).exists():
        raise RuntimeError(f"built binary missing: {bina}")
    CLI_BIN = [bina]
    return CLI_BIN


CMDS = []


def run(args, cwd, check=True):
    """Run proof-cli; return (exit_code, stdout, stderr)."""
    CMDS.append("proof-cli " + " ".join(args))
    p = subprocess.run(
        cli_binary() + args, cwd=cwd, capture_output=True, text=True,
        check=False,
    )
    if check and p.returncode != 0:
        raise RuntimeError(
            f"proof-cli {' '.join(args)} exited {p.returncode}:\n{p.stderr}")
    return p.returncode, p.stdout, p.stderr


def proof_id(path):
    return json.loads(Path(path).read_text())["id"]


def build_payment(w: Path):
    """Full payment lifecycle through the real CLI. Returns the data dict."""
    del CMDS[:]
    T = 1757000000
    run(["create-event", "--type", "payment.created", "--subject", "payment:p-tour",
         "--effective-at", str(T), "--payload-hex", D1,
         "--meta", "order=ord-tour-1", "--out", "evt1.json"], w)
    run(["create-event", "--type", "invoice.issued", "--subject", "invoice:i-tour",
         "--effective-at", str(T), "--payload-hex", D2, "--out", "evt2.json"], w)
    run(["attest", "--seed", "test", "--subject", "payment:p-tour",
         "--claim-type", "payment.settled", "--claim", "amount=4200,currency=EUR",
         "--issued-at", str(T + 100), "--out", "att.json"], w)
    att = proof_id(w / "att.json")
    issuer = json.loads((w / "att.json").read_text())["issuer"]
    run(["add-evidence", "--kind", "transaction_record", "--digest-hex", D3,
         "--attestation-ref", att, "--hint", "acquirer:receipt:tour",
         "--out", "evd.json"], w)
    evd = proof_id(w / "evd.json")
    e1 = proof_id(w / "evt1.json")
    e2 = proof_id(w / "evt2.json")
    run(["relate", "--from", e1, "--type", "SETTLES", "--to", e2,
         "--evidence-ref", evd, "--out", "rel.json"], w)
    _, build_out, _ = run(
        ["build", "--kind", "payment.settles-invoice", "--subject", "payment:p-tour",
         "--predicate", "settles", "--object", e2, "--at-time", str(T + 100),
         "--created-at", str(T + 200), "--events", "evt1.json,evt2.json",
         "--attestations", "att.json", "--evidence", "evd.json",
         "--relationships", "rel.json", "--out", "proof.json"], w)
    proof = json.loads((w / "proof.json").read_text())

    code, out, _ = run(
        ["verify", "--proof", "proof.json", "--clock", str(T + 300),
         "--revocations-known-at", str(T + 300),
         "--no-require-status", "--quiet"], w, check=False)
    assert code == 0, "fresh payment proof must verify"
    fresh = {"exit": code, "report": json.loads(out)}

    # Tamper: flip one hex nibble mid-CBOR, re-verify (must fail closed).
    v = dict(proof)
    cbor = v["cbor"]
    i = len(cbor) // 2
    flipped = "0" if cbor[i] != "0" else "1"
    v["cbor"] = cbor[:i] + flipped + cbor[i + 1:]
    (w / "proof-tampered.json").write_text(json.dumps(v))
    code, out, _ = run(
        ["verify", "--proof", "proof-tampered.json", "--clock", str(T + 300),
         "--revocations-known-at", str(T + 300),
         "--no-require-status", "--quiet"], w, check=False)
    assert code == 1, "tampered proof must fail"
    tampered = {
        "proof": v,
        "report": json.loads(out),
        "exit": code,
        "flip": {"offset": i, "from": cbor[i], "to": flipped},
    }

    # Expired variant: same claim, but the attestation carries expires_at
    # (with its own evidence binding so the only failure is expiry).
    run(["attest", "--seed", "test", "--subject", "payment:p-tour",
         "--claim-type", "payment.settled", "--claim", "amount=4200,currency=EUR",
         "--issued-at", str(T + 100), "--expires-at", str(T + 350),
         "--out", "att-exp.json"], w)
    att_exp = proof_id(w / "att-exp.json")
    run(["add-evidence", "--kind", "transaction_record", "--digest-hex", D3,
         "--attestation-ref", att_exp, "--hint", "acquirer:receipt:tour",
         "--out", "evd-exp.json"], w)
    evd_exp = proof_id(w / "evd-exp.json")
    run(["relate", "--from", e1, "--type", "SETTLES", "--to", e2,
         "--evidence-ref", evd_exp, "--out", "rel-exp.json"], w)
    run(["build", "--kind", "payment.settles-invoice", "--subject", "payment:p-tour",
         "--predicate", "settles", "--object", e2, "--at-time", str(T + 100),
         "--created-at", str(T + 200), "--events", "evt1.json,evt2.json",
         "--attestations", "att-exp.json", "--evidence", "evd-exp.json",
         "--relationships", "rel-exp.json", "--out", "proof-exp.json"], w)
    exp_proof = json.loads((w / "proof-exp.json").read_text())
    code, out, _ = run(
        ["verify", "--proof", "proof-exp.json", "--clock", str(T + 800),
         "--revocations-known-at", str(T + 800),
         "--no-require-status", "--quiet"], w, check=False)
    assert code == 1, "expired proof must fail"
    expired = {"proof": exp_proof, "report": json.loads(out), "exit": code}
    assert any(l["status"] == "EXPIRED"
               for l in expired["report"]["lifecycle"]), "must be EXPIRED"

    # Revoke, then re-verify with the status object.
    run(["revoke", "--seed", "test", "--target", att,
         "--reason", "tour: mislabeled", "--at", str(T + 400),
         "--out", "revoke.json"], w)
    status_id = proof_id(w / "revoke.json")
    code, out, _ = run(
        ["verify", "--proof", "proof.json", "--clock", str(T + 500),
         "--status", "revoke.json", "--revocations-known-at", str(T + 500),
         "--quiet"], w, check=False)
    assert code == 1, "revoked proof must fail"
    revoked = {"status_id": status_id, "report": json.loads(out), "exit": code}

    # Supersede to a corrected attestation; history stays valid.
    run(["attest", "--seed", "test", "--subject", "payment:p-tour",
         "--claim-type", "payment.settled", "--claim", "amount=4300",
         "--issued-at", str(T + 600), "--out", "att2.json"], w)
    att2 = proof_id(w / "att2.json")
    run(["supersede", "--seed", "test", "--old", att, "--new", att2,
         "--at", str(T + 700), "--out", "supersede.json"], w)
    sup_id = proof_id(w / "supersede.json")
    code, out, _ = run(
        ["verify", "--proof", "proof.json", "--clock", str(T + 800),
         "--status", "supersede.json", "--revocations-known-at", str(T + 800),
         "--quiet"], w, check=False)
    assert code == 0, "superseded proof keeps evidence validity"
    superseded = {"status_id": sup_id, "new_attestation": att2,
                  "report": json.loads(out), "exit": code}

    # Policy contrasts on identical bytes.
    def policy_doc(pid, reqs):
        p = {"policy_version": 1, "policy_id": pid, "requirements": reqs}
        (w / f"pol-{pid}.json").write_text(json.dumps(p))
        return f"pol-{pid}.json"

    base_reqs = [
        {"type": "signature_valid"},
        {"type": "issuer_trusted", "issuer": issuer},
        {"type": "not_expired"},
        {"type": "not_revoked"},
        {"type": "evidence_present", "kind": "transaction_record"},
    ]
    base_pf = policy_doc("tour-base", base_reqs)
    strict_pf = policy_doc("tour-strict",
                           base_reqs + [{"type": "transparency_present"}])
    combos = []
    for trusted, transp in [(True, False), (False, False),
                            (True, True), (False, True)]:
        # The requirement stays; only the verifier's trust list changes.
        # An issuer outside the trust list fails issuer_trusted.
        reqs = list(base_reqs)
        if transp:
            reqs = reqs + [{"type": "transparency_present"}]
        pf = policy_doc(f"tour-c-{int(trusted)}{int(transp)}", reqs)
        args = ["evaluate", "--proof", "proof.json", "--policy", pf,
                "--clock", str(T + 300),
                "--revocations-known-at", str(T + 300),
                "--no-require-status", "--json", "--quiet"]
        if trusted:
            args += ["--trusted", issuer]
        code, out, _ = run(args, w, check=False)
        combos.append({
            "issuer_trusted": trusted,
            "transparency_required": transp,
            "exit": code,
            "outcome": json.loads(out)["policy_outcome"],
        })
    # Base outcome + prose explanation for the narrative panel.
    code, out, _ = run(
        ["evaluate", "--proof", "proof.json", "--policy", base_pf,
         "--clock", str(T + 300), "--revocations-known-at", str(T + 300),
         "--no-require-status",
         "--trusted", issuer, "--json", "--quiet"], w, check=False)
    base = {"policy": json.loads((w / base_pf).read_text()),
            "outcome": json.loads(out)["policy_outcome"], "exit": code}
    _, explain_out, _ = run(
        ["explain", "--proof", "proof.json", "--policy", base_pf,
         "--clock", str(T + 300), "--revocations-known-at", str(T + 300),
         "--no-require-status",
         "--trusted", issuer, "--quiet"], w)

    _, inspect_out, _ = run(["inspect", "proof.json", "--json", "--quiet"], w)

    return {
        "label": "Financial transaction",
        "tagline": "Did payment:p-tour settle invoice:i-tour?",
        "commands": [c for c in CMDS if c.split()[1] in
                     ("create-event", "attest", "add-evidence", "relate", "build")],
        "proof": proof,
        "contents": json.loads(inspect_out),
        "build_log": build_out.strip().splitlines(),
        "verify_fresh": fresh,
        "expired": expired,
        "tampered": tampered,
        "revoked": revoked,
        "superseded": superseded,
        "policy_base": base,
        "policy_combos": combos,
        "explain": explain_out,
        "clock": T + 300,
    }


def build_software(w: Path):
    """Second domain: same engine, different vocabulary."""
    del CMDS[:]
    T = 1758000000
    run(["create-event", "--type", "source.committed", "--subject", "repo:svc",
         "--effective-at", str(T), "--payload-hex", D1,
         "--meta", "rev=r4242", "--out", "s-ev1.json"], w)
    run(["create-event", "--type", "build.finished", "--subject", "artifact:svc-2.1.0",
         "--effective-at", str(T), "--payload-hex", D2, "--out", "s-ev2.json"], w)
    run(["attest", "--seed", "test", "--subject", "artifact:svc-2.1.0",
         "--claim-type", "artifact.released", "--claim", "channel=stable",
         "--issued-at", str(T + 100), "--out", "s-att.json"], w)
    att = proof_id(w / "s-att.json")
    run(["add-evidence", "--kind", "receipt", "--digest-hex", D3,
         "--attestation-ref", att, "--hint", "ci:build-log:tour",
         "--out", "s-evd.json"], w)
    fin = proof_id(w / "s-ev2.json")
    evd = proof_id(w / "s-evd.json")
    run(["relate", "--from", fin, "--type", "PRODUCED", "--to", att,
         "--evidence-ref", evd, "--out", "s-rel.json"], w)
    run(["build", "--kind", "artifact.build-release",
         "--subject", "artifact:svc-2.1.0", "--predicate", "released",
         "--at-time", str(T + 100), "--created-at", str(T + 200),
         "--events", "s-ev1.json,s-ev2.json", "--attestations", "s-att.json",
         "--evidence", "s-evd.json", "--relationships", "s-rel.json",
         "--out", "s-proof.json"], w)
    proof = json.loads((w / "s-proof.json").read_text())
    code, out, _ = run(
        ["verify", "--proof", "s-proof.json", "--clock", str(T + 300),
         "--revocations-known-at", str(T + 300),
         "--no-require-status", "--quiet"], w, check=False)
    assert code == 0, "software proof must verify"
    _, inspect_out, _ = run(["inspect", "s-proof.json", "--json", "--quiet"], w)
    pol = {"policy_version": 1, "policy_id": "tour-software",
           "requirements": [{"type": "signature_valid"}]}
    (w / "s-pol.json").write_text(json.dumps(pol))
    code, out, _ = run(
        ["evaluate", "--proof", "s-proof.json", "--policy", "s-pol.json",
         "--clock", str(T + 300), "--revocations-known-at", str(T + 300),
         "--no-require-status", "--json", "--quiet"], w, check=False)
    return {
        "label": "Software artifact",
        "tagline": "Was artifact:svc-2.1.0 released by this build?",
        "commands": [c for c in CMDS if c.split()[1] in
                     ("create-event", "attest", "add-evidence", "relate", "build")],
        "proof": proof,
        "contents": json.loads(inspect_out),
        "verify_fresh": {"exit": code, "report": json.loads(out)["report"]},
        "policy_base": {"policy": pol,
                        "outcome": json.loads(out)["policy_outcome"],
                        "exit": code},
        "clock": T + 300,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", help="rendered index.html destination")
    ap.add_argument("--template", help="template.html path")
    ap.add_argument("--data-only", help="write canonical data JSON only")
    args = ap.parse_args()

    w = Path(args.work)
    w.mkdir(parents=True, exist_ok=True)
    data = {
        "generated_by": "proof-cli (V1 core; deterministic fixtures)",
        "examples": {
            "payment": build_payment(w),
            "software": build_software(w),
        },
    }
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    if args.data_only:
        Path(args.data_only).write_text(canonical)
        print(f"data: {args.data_only} ({len(canonical)} bytes)")
        return 0
    template = Path(args.template).read_text()
    page = template.replace("/*__PROOF_DATA__*/", canonical)
    if "/*__PROOF_DATA__*/" not in template:
        raise RuntimeError("template lacks the /*__PROOF_DATA__*/ marker")
    Path(args.out).write_text(page)
    print(f"page: {args.out} ({len(page)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
