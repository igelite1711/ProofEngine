#!/usr/bin/env node
// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// TypeScript differential runner (third implementation).
//
// Part 1 (I2 subset): generically verify every fixture golden-NN.json whose
// recorded expectation names a stage this verifier implements (decode /
// id_verify / verify / cryptographic_validity). Vectors pinning engine-side
// verdicts (time, lifecycle, graph, policy) are counted and skipped — the
// Python differential owns them.
// Part 1b (negative differential): TS-crafted mutants over golden-11
// (unknown field in every member slot + top level, mutated proof_id,
// version bump) must all be rejected with the expected failure class.
// Part 2 (I3b): the Rust-created demo proof (make demo) verifies under TS
// (stages 1-6 + proof_id binding).
//
// Run: npm run differential (in interop/ts/). Exit 0 = all checks pass.
// Node >= 18; runtime deps: @noble/curves only.
import { readFileSync, readdirSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as cbor from "./minicbor.js";
import {
  InteropFail,
  b64uEncode,
  sha256,
  verifyProof,
  verifySign1,
} from "./pengine.js";

const PASS: string[] = [];
const FAIL: string[] = [];
function check(name: string, cond: boolean, detail = ""): void {
  (cond ? PASS : FAIL).push(name);
  console.log((cond ? "PASS " : "FAIL ") + name + (detail ? ` (${detail})` : ""));
}

const here = dirname(fileURLToPath(import.meta.url));
const fx = join(here, "..", "..", "fixtures");
const demoProof = join(here, "..", "..", "demo", "out", "proof.cbor.json");

const files = readdirSync(fx).filter((f) => /^golden-\d+\.json$/.test(f)).sort();
let exercised = 0;
let skipped = 0;
const skippedList: string[] = [];

for (const f of files) {
  const v = JSON.parse(readFileSync(join(fx, f), "utf8"));
  const exp = v.expected ?? {};
  // Locate the bytes: canonical_hex / input_hex / proof_canonical_hex /
  // cose_sign1_hex / evidence_canonical_hex. Graph vectors (golden-09/10)
  // carry JSON nodes/edges and no bytes: their verdicts are engine-side.
  const hexOf =
    v.canonical_hex ?? v.input_hex ?? v.proof_canonical_hex ??
    v.cose_sign1_hex ?? v.evidence_canonical_hex;
  const stages = Object.keys(exp);
  const inScope =
    typeof hexOf === "string" &&
    stages.some((s) =>
      ["decode", "id_verify", "verify", "cryptographic_validity"].includes(s)
    );
  if (!inScope) {
    skippedList.push(f);
    skipped += 1;
    continue;
  }
  exercised += 1;
  const tag = `I2 ${f} ${v.description ? v.description.slice(0, 40) : ""}`.trim();

  const raw = Uint8Array.from(Buffer.from(hexOf as string, "hex"));
  let ok = true;
  const detail: string[] = [];
  const code: string | undefined = exp.code;
  const mustReject =
    (exp.decode !== undefined && exp.decode !== "ok") ||
    code !== undefined ||
    exp.cryptographic_validity === "invalid";
  const engineSideOnly =
    !mustReject &&
    (exp.decision !== undefined ||
      (Array.isArray(exp.codes) && exp.codes.length > 0));

  if (mustReject) {
    // Negative differential: the engine-rejection must reproduce here.
    let msg = "";
    let rejected = false;
    try {
      runStages(raw, v);
      detail.push("accepted?! (should have been rejected)");
      ok = false;
    } catch (e) {
      if (e instanceof InteropFail) {
        rejected = true;
        msg = (e as Error).message;
        detail.push(`rejected: ${msg.slice(0, 70)}`);
      } else {
        ok = false;
        detail.push(`unexpected: ${(e as Error).message.slice(0, 60)}`);
      }
    }
    if (rejected) {
      // pin the stage where the rejection must land
      if (code === "SIGNATURE_INVALID") {
        ok = ok && /SIGNATURE_INVALID|kid does not match/.test(msg);
      } else if (code === "ID_MISMATCH") {
        ok = ok && /ID_MISMATCH/.test(msg);
      } else if (code === "SCHEMA_VIOLATION") {
        ok = ok && /unknown|malformed|referenced/.test(msg);
      } else if (exp.decode !== undefined) {
        ok = ok && /dup key|non-canonical|re-encoding/.test(msg);
      }
      // multi-code vectors (codes: [...]): TS must reproduce the binding-
      // stage code; graph-only codes (CYCLE_DETECTED) stay engine-side.
      if (Array.isArray(exp.codes)) {
        if (exp.codes.includes("ID_MISMATCH")) {
          ok = ok && /ID_MISMATCH/.test(msg);
        }
        if (exp.codes.includes("SCHEMA_VIOLATION")) {
          ok = ok && /unknown|malformed|referenced/.test(msg);
        }
      }
    }
  } else if (engineSideOnly && exp.decode !== "ok") {
    // Verdict is engine-side; TS asserts binding-level agreement only.
    try {
      runStages(raw, v);
      detail.push("binding ok (verdict engine-side)");
    } catch (e) {
      ok = false;
      detail.push(`binding disagrees: ${(e as Error).message.slice(0, 70)}`);
    }
  } else {
    // Positive vector: full stage assertions.
    try {
      runStages(raw, v);
      detail.push("ok");
    } catch (e) {
      ok = false;
      detail.push((e as Error).message.slice(0, 80));
    }
  }
  check(tag, ok, detail.join("; "));
}

// Stage dispatcher: proof binding / Sign1 verify / canonical+id.
function runStages(raw: Uint8Array, v: any): void {
  const exp = v.expected ?? {};
  if ("proof_canonical_hex" in v) {
    const rep = verifyProof(raw);
    if (exp.proof_id && rep.proof_id !== exp.proof_id) {
      throw new InteropFail("proof_id mismatch vs fixture");
    }
    return;
  }
  if ("cose_sign1_hex" in v) {
    const issuer = v.verify_ctx?.issuer;
    if (typeof issuer !== "string") {
      throw new InteropFail("no issuer in verify_ctx");
    }
    const [, kid] = verifySign1(raw, issuer);
    if (exp.alg === -19 && kid.length !== 32) {
      throw new InteropFail("ed25519 kid must be 32 bytes");
    }
    if (exp.alg === -9 && kid.length !== 64) {
      throw new InteropFail("p256 kid must be 64 bytes");
    }
    return;
  }
  // canonical/id vectors: strict decode + byte-identity + id derivation.
  cbor.decodeStrict(raw);
  const re = cbor.canonicalReencode(raw);
  if (Buffer.compare(Buffer.from(re), Buffer.from(raw)) !== 0) {
    throw new InteropFail("non-canonical re-encoding");
  }
  if (exp.id_verify === "ok" && v.object_id) {
    const id = "evt:v1:" + b64uEncode(sha256(raw));
    if (id !== v.object_id) throw new InteropFail("id mismatch");
  }
  // Artifact-id vectors (golden-08): reproducing the engine ID_MISMATCH
  // means the substituted bytes must derive to a DIFFERENT id than the
  // recorded expected_id.
  if (v.expected_id) {
    const prefix = v.expected_id.split(":")[0];
    const id = `${prefix}:v1:` + b64uEncode(sha256(raw));
    if (id !== v.expected_id) {
      throw new InteropFail("ID_MISMATCH: derived id differs from expected_id");
    }
    throw new Error("unexpected: derived id equals recorded id (no tamper?)");
  }
}

// ---- Part 1b: TS-crafted mutants must FAIL the TS verifier (closed-schema
// parity, mirrors/extends the Python runner's negative differential). ----
function mutateProof(
  raw: Uint8Array,
  fn: (outer: cbor.Map_) => void
): Uint8Array {
  const [v] = cbor.dec(raw);
  if (!(v instanceof cbor.Map_)) throw new Error("fixture not a map");
  fn(v);
  return cbor.encMap(v.pairs);
}

function firstOf(outer: cbor.Map_, key: string): cbor.Map_ {
  const arr = cbor.mapGet(outer, key) as cbor.Map_[];
  return arr[0];
}

function expectReject(name: string, raw: Uint8Array, pin?: RegExp): void {
  try {
    verifyProof(raw);
    check(name, false, "accepted?! (fail-open parity break)");
  } catch (e) {
    if (e instanceof InteropFail && (!pin || pin.test((e as Error).message))) {
      check(name, true, (e as Error).message.slice(0, 60));
    } else {
      check(name, false, `wrong failure: ${(e as Error).message.slice(0, 60)}`);
    }
  }
}

// use golden-11 (full proof) as the mutation base; every mutant must be
// rejected with the expected failure class (fail closed).
{
  const base = Uint8Array.from(
    Buffer.from(
      JSON.parse(readFileSync(join(fx, "golden-11.json"), "utf8"))
        .proof_canonical_hex,
      "hex"
    )
  );
  expectReject(
    "NEG unknown event field rejected",
    mutateProof(base, (o) => firstOf(o, "events").pairs.push(["zzz_unknown", 1])),
    /unknown event field/
  );
  expectReject(
    "NEG unknown attestation entry field rejected",
    mutateProof(base, (o) => firstOf(o, "attestations").pairs.push(["zzz_unknown", 1])),
    /unknown attestation entry field/
  );
  expectReject(
    "NEG unknown attestation content field rejected",
    mutateProof(base, (o) =>
      (cbor.mapGet(firstOf(o, "attestations"), "content") as cbor.Map_).pairs.push([
        "zzz_unknown",
        1,
      ])
    ),
    /unknown attestation field/
  );
  expectReject(
    "NEG unknown evidence field rejected",
    mutateProof(base, (o) => firstOf(o, "evidence").pairs.push(["zzz_unknown", 1])),
    /unknown evidence field/
  );
  expectReject(
    "NEG unknown relationship field rejected",
    mutateProof(base, (o) => firstOf(o, "relationships").pairs.push(["zzz_unknown", 1])),
    /unknown relationship field/
  );
  expectReject(
    "NEG unknown proposition field rejected",
    mutateProof(base, (o) =>
      (cbor.mapGet(o, "proposition") as cbor.Map_).pairs.push(["zzz_unknown", 1])
    ),
    /unknown proposition field/
  );
  expectReject(
    "NEG unknown top-level proof field rejected",
    mutateProof(base, (o) => o.pairs.push(["zzz_unknown", 1])),
    /unknown proof field/
  );
  expectReject(
    "NEG mutated proof_id rejected",
    mutateProof(base, (o) => {
      const pairs = o.pairs.map(([k, val]) =>
        k === "proof_id"
          ? [k, (val as string).replace(/.$/, (c) => (c === "A" ? "B" : "A"))]
          : [k, val]
      );
      o.pairs.length = 0;
      o.pairs.push(...(pairs as [unknown, unknown][]));
    }),
    /ID_MISMATCH/
  );
  expectReject(
    "NEG wrong proof version rejected",
    mutateProof(base, (o) => {
      const pairs = o.pairs.map(([k, val]) => (k === "v" ? [k, 2] : [k, val]));
      o.pairs.length = 0;
      o.pairs.push(...(pairs as [unknown, unknown][]));
    }),
    /version/
  );
}

// ---- Part 2: I3b — Rust-created demo proof verifies under TS ----
if (existsSync(demoProof)) {
  const v = JSON.parse(readFileSync(demoProof, "utf8"));
  try {
    const rep = verifyProof(Uint8Array.from(Buffer.from(v.cbor, "hex")));
    check("I3b rust-created demo proof verifies in TS", true, rep.proof_id.slice(0, 16));
  } catch (e) {
    check("I3b rust-created demo proof verifies in TS", false, (e as Error).message);
  }
} else {
  check("I3b rust-created demo proof verifies in TS", false, "run make demo first");
}

// ---- Part 3: I3a (TS side) — TS-creates, Rust must PASS. Mirrors the
// Python runner's Part 2: same seed (0x09*32), digest (00..1f), subjects,
// timestamps; must produce byte-identical ids to the Python leg (cross-check
// vs interop/differential.py work dir when present). ----
import { spawnSync } from "node:child_process";
import {
  makeAttestation,
  makeEvent,
  makeEvidence,
  makeProof,
  makeRelationship,
} from "./make.js";

// Resolve the CLI relative to the repo root, not the process cwd: `npm run`
// executes with cwd interop/ts, where "./target/debug/proof-cli" never
// exists — the old fallback spawned nothing (ENOENT) and reported the
// vacuous `exit=1 err=`, failing I3a on every local run while CI (which sets
// PROOF_CLI) stayed green.
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const proofCli =
  process.env.PROOF_CLI ??
  (process.env.CARGO_TARGET_DIR
    ? join(process.env.CARGO_TARGET_DIR, "debug", "proof-cli")
    : join(repoRoot, "target", "debug", "proof-cli"));
const workDir = process.env.WORK_DIR ?? "/tmp/proof-interop-ts";
mkdirSync(workDir, { recursive: true });

function runCli(...args: string[]): { code: number; err: string } {
  const p = spawnSync(proofCli, args, { encoding: "utf8" });
  // Surface spawn failures (e.g. missing binary): previously p.error was
  // dropped, so a failure to launch read as a verdict FAIL with empty err.
  const spawnErr = (p as unknown as { error?: Error }).error;
  return {
    code: p.status ?? 1,
    err:
      (spawnErr ? `spawn ${proofCli}: ${spawnErr.message}\n` : "") +
      (p.stderr || "") +
      (p.stdout || ""),
  };
}

const seed = Uint8Array.from(Buffer.alloc(32, 9));
const digest = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i));
const ev = makeEvent("payment.created", "payment:i3", 1700000000, digest);
const ev2 = makeEvent("invoice.issued", "invoice:i3", 1700000000, digest);
const att = makeAttestation(
  seed, "payment:i3", "payment.settled",
  [["amount", ["uint", 4200]]], 1700000150
);
const evd = makeEvidence("transaction_record", digest, att.id);
const rel = makeRelationship(ev.id, "SETTLES", ev2.id, evd.id);

const kinds: Record<string, string> = {
  "ev.json": "event",
  "ev2.json": "event",
  "att.json": "attestation",
  "evd.json": "evidence",
  "rel.json": "relationship",
};
const artifacts: Record<string, object> = {
  "ev.json": ev,
  "ev2.json": ev2,
  "att.json": att,
  "evd.json": evd,
  "rel.json": rel,
};
for (const [name, art] of Object.entries(artifacts)) {
  writeFileSync(
    join(workDir, name),
    JSON.stringify({ kind: kinds[name], ...art })
  );
}

const proof = makeProof(
  "payment.settles-invoice", ev.id, "settles", ev2.id, 1700000150, [],
  1700000200, [ev, ev2], [att], [evd], [rel]
);
writeFileSync(
  join(workDir, "proof.json"),
  JSON.stringify({ kind: "proof", id: proof.id, cbor: proof.cbor })
);
{
  const r = runCli(
    "verify", "--proof", join(workDir, "proof.json"),
    "--clock", "1700000300", "--revocations-known-at", "1700000300",
    "--no-require-status", "--out", join(workDir, "report.json")
  );
  let rep: any = {};
  try {
    rep = JSON.parse(readFileSync(join(workDir, "report.json"), "utf8"));
  } catch {}
  check(
    "I3a ts-created proof passes Rust verify",
    r.code === 0 && rep.cryptographic_validity === "valid" &&
      rep.evidence_validity === "valid",
    `exit=${r.code} err=${r.err.trim().slice(-120)}`
  );
}

// composition over its own proof
const proof2 = makeProof(
  "payment.settles-invoice", ev.id, "settles", ev2.id, 1700000150, [],
  1700000200, [ev, ev2], [att], [evd], [rel], [proof.id]
);
writeFileSync(
  join(workDir, "proof2.json"),
  JSON.stringify({ kind: "proof", id: proof2.id, cbor: proof2.cbor })
);
{
  const r = runCli(
    "verify", "--proof", join(workDir, "proof2.json"),
    "--clock", "1700000300", "--revocations-known-at", "1700000300",
    "--no-require-status", "--out", join(workDir, "report2.json")
  );
  let rep: any = {};
  try {
    rep = JSON.parse(readFileSync(join(workDir, "report2.json"), "utf8"));
  } catch {}
  check(
    "I3a ts-composed proof passes Rust verify",
    r.code === 0 && rep.cryptographic_validity === "valid" &&
      rep.evidence_validity === "valid" &&
      JSON.stringify(rep.referenced_proofs) === JSON.stringify([proof.id]),
    `exit=${r.code} err=${r.err.trim().slice(-120)}`
  );
}

console.log(`\nTS-DIFFERENTIAL: ${PASS.length} pass, ${FAIL.length} fail ` +
  `(${exercised} vectors exercised, ${skipped} engine-side verdicts skipped)`);
if (skippedList.length) {
  console.log("engine-side (skipped):", skippedList.join(", "));
}
if (FAIL.length) {
  console.log("FAILED:", FAIL);
  process.exit(1);
}
