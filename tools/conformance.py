#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Full-verdict conformance over the golden fixtures (Gate I extension).

`interop/differential.py` proves a second engineer can reimplement the
cryptographic core (stages 1-6 + bindings). This runner proves they can
reproduce whole *verdicts*: for every fixture carrying `proof_canonical_hex`
it replays the embedded `verify_ctx` (+ `policy`/`eval_inputs` where present)
through an engine front end and compares the recorded `expected` triple,
failure codes, and policy decisions.

Stdlib only. Third-party implementations mirror it: same fixtures, same
context mapping, same comparison rules (see INTEROPERABILITY.md
"Verdict-reproduction recipe"). Field coverage is deliberately limited to
what the fixtures record — extra report fields are ignored so conformant
implementations may extend diagnostics freely.

Usage:
  python3 tools/conformance.py --repo . --proof-cli ./target/debug/proof-cli
      --work /tmp/proof-conformance

Exit 0 = every exercised vector matches (skips listed, never failed).
Exit 1 = any mismatch, harness error, or usage error.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def fail(msg):
    print(f"conformance FAIL: {msg}")
    return False


def run_cli(proof_cli, args):
    # Verdicts ride exit 1 (FAIL/INDETERMINATE); only exit 2 is a harness
    # error. Stdout must stay machine-readable JSON either way.
    r = subprocess.run(
        [proof_cli] + args, capture_output=True, text=True, timeout=120
    )
    if r.returncode == 2:
        return None, f"engine/usage error (exit 2): {(r.stderr or '').strip()[:300]}"
    try:
        return json.loads(r.stdout), None
    except Exception as e:
        return None, f"stdout is not JSON (exit {r.returncode}): {e}"


def failing_codes(report):
    return sorted(
        c["code"] for c in report.get("checks", []) if not c.get("ok") and c.get("code")
    )


def check_verify(proof_cli, work, name, vec):
    exp = vec.get("expected", {})
    ctx = vec.get("verify_ctx", {})
    env = {"cbor": vec["proof_canonical_hex"], "kind": "proof"}
    proof_path = work / f"{name}.proof.json"
    proof_path.write_text(json.dumps(env))
    args = ["verify", "--proof", str(proof_path), "--quiet"]
    args += ["--clock", str(ctx.get("verified_at", 0))]
    args += ["--skew", str(ctx.get("skew_leeway", 300))]
    if ctx.get("revocations_known_at") is not None:
        args += ["--revocations-known-at", str(ctx["revocations_known_at"])]
    for a in ctx.get("revocation_authorities", []) or []:
        args += ["--authority", a]
    # Grandfathered fixtures predate the fail-closed empty-feed default:
    # they were recorded under caller-asserted absence. New fixtures opt
    # into the default with verify_ctx.require_status_feed=true.
    if not ctx.get("require_status_feed", False):
        args += ["--no-require-status"]
    report, err = run_cli(proof_cli, args)
    if err:
        return fail(f"{name}: {err}")
    ok = True
    for field in ("cryptographic_validity", "evidence_validity", "policy_decision"):
        if field in exp and report.get(field) != exp[field]:
            print(
                f"conformance FAIL: {name}: {field} got {report.get(field)!r}, "
                f"want {exp[field]!r}"
            )
            ok = False
    if "codes" in exp:
        got = failing_codes(report)
        for want in exp["codes"]:
            if want not in got:
                print(f"conformance FAIL: {name}: missing code {want} in {got}")
                ok = False
    if "stage" in exp and "code" in exp:
        hit = any(
            (not c.get("ok"))
            and c.get("stage") == exp["stage"]
            and c.get("code") == exp["code"]
            for c in report.get("checks", [])
        )
        if not hit:
            print(
                f"conformance FAIL: {name}: no failing check "
                f"{exp['stage']}/{exp['code']}"
            )
            ok = False
    if "proof_id" in vec and vec["proof_id"]:
        if report.get("proof_id") != vec["proof_id"]:
            print(f"conformance FAIL: {name}: proof_id mismatch")
            ok = False
    if "conflicts" in exp:
        if len(report.get("conflicts", [])) != exp["conflicts"]:
            print(
                f"conformance FAIL: {name}: conflicts got "
                f"{len(report.get('conflicts', []))}, want {exp['conflicts']}"
            )
            ok = False
    if ok:
        print(f"PASS {name} {report.get('proof_id', '?')}")
    return ok


def check_policy(proof_cli, work, name, vec):
    exp = vec.get("expected", {})
    if "decision" not in exp or "policy" not in vec:
        return None  # not a policy vector
    ctx = vec.get("verify_ctx", {})
    ei = vec.get("eval_inputs", {})
    env = {"cbor": vec["proof_canonical_hex"], "kind": "proof"}
    proof_path = work / f"{name}.proof.json"
    proof_path.write_text(json.dumps(env))
    policy_path = work / f"{name}.policy.json"
    policy_path.write_text(json.dumps(vec["policy"]))
    args = [
        "evaluate", "--proof", str(proof_path), "--policy", str(policy_path),
        "--clock", str(ctx.get("verified_at", 0)),
        "--skew", str(ctx.get("skew_leeway", 300)), "--json", "--quiet",
    ]
    if ctx.get("revocations_known_at") is not None:
        args += ["--revocations-known-at", str(ctx["revocations_known_at"])]
    for t in ei.get("trusted_issuers", []) or []:
        args += ["--trusted", t]
    if ei.get("revoked"):
        args += ["--revoked", ",".join(ei["revoked"])]
    # Same grandfather rule as check_verify (see above).
    if not ctx.get("require_status_feed", False):
        args += ["--no-require-status"]
    merged, err = run_cli(proof_cli, args)
    if err:
        return fail(f"{name} policy: {err}")
    if "policy_outcome" not in merged or "report" not in merged:
        return fail(f"{name} policy: merged document lacks policy_outcome/report")
    out = merged["policy_outcome"]
    ok = True
    if out.get("decision") != exp["decision"]:
        print(
            f"conformance FAIL: {name} policy: decision got {out.get('decision')!r}, "
            f"want {exp['decision']!r}"
        )
        ok = False
    for want_r, got_r in zip(exp.get("results", []), out.get("results", [])):
        if got_r.get("requirement") != want_r.get("requirement") or bool(
            got_r.get("passed")
        ) != bool(want_r.get("passed")):
            print(f"conformance FAIL: {name} policy: requirement mismatch {got_r} vs {want_r}")
            ok = False
            break
    if ok:
        print(f"PASS {name} policy ({out.get('decision')})")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--proof-cli", required=True)
    ap.add_argument("--work", required=True)
    args = ap.parse_args()
    repo = Path(args.repo)
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    passed, failed, skipped = 0, 0, []
    for path in sorted((repo / "fixtures").glob("golden-*.json")):
        try:
            vec = json.loads(path.read_text())
        except Exception as e:
            print(f"conformance FAIL: {path.name}: unreadable: {e}")
            failed += 1
            continue
        if "proof_canonical_hex" not in vec:
            skipped.append(f"{path.name} (no proof bytes; unit-level, see differential)")
            continue
        name = path.stem
        if check_verify(args.proof_cli, work, name, vec):
            passed += 1
        else:
            failed += 1
            continue
        pr = check_policy(args.proof_cli, work, name, vec)
        if pr is True:
            passed += 1
        elif pr is False:
            failed += 1
    print(f"CONFORMANCE: {passed} pass, {failed} fail, {len(skipped)} skipped")
    for s in skipped:
        print(f"  skip {s}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
