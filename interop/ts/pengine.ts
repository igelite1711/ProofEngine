// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Independent ProofEngine verifier core for Node/TypeScript — third
// implementation of the cryptographic interop core (after the Rust engine
// and interop/pengine.py), written against FORMAT.md / INTEROPERABILITY.md
// / DATA-MODEL.md and the golden corpus, not against engine code.
//
// Scope mirrors interop/README.md: parse, canonicality, identifiers
// (sha256 -> b64url), Ed25519 + P-256 COSE_Sign1 verification, proof
// binding stages 1-6 (incl. composition refs + vocabularies). Time,
// lifecycle, graph, policy stay engine-side by design.
//
// Signatures: @noble/curves (audited, pure JS). Everything else: Node
// stdlib. No network access at run time.

import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import {
  Map_,
  canonicalReencode,
  concat,
  decodeStrict,
  enc,
  encAny,
  encMap,
  mapGet,
  mapOpt,
  toHex,
} from "./minicbor.js";

export class InteropFail extends Error {}

// ECDSA/P-256 verify. kid64 = X||Y (big-endian), sig64 = r||s; the message
// is digested with SHA-256 (matching interop/pengine.py p256_verify).
// @noble/curves expects an uncompressed point (0x04 || X || Y) and a
// pre-hashed message for verify with prehash.
function p256Verify(
  pub64: Uint8Array,
  msg: Uint8Array,
  sig64: Uint8Array
): boolean {
  if (pub64.length !== 64 || sig64.length !== 64) return false;
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(pub64, 1);
  try {
    return p256.verify(sig64, sha256(msg), uncompressed, {
      prehash: false,
      format: "compact",
    });
  } catch {
    return false;
  }
}

export function sha256(b: Uint8Array): Uint8Array {
  return Uint8Array.from(createHash("sha256").update(b).digest());
}

export function b64uEncode(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}
export function b64uDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new InteropFail("bad base64url");
  const b = Uint8Array.from(Buffer.from(s, "base64url"));
  if (b64uEncode(b) !== s) throw new InteropFail("non-canonical base64url");
  return b;
}

export function objId(prefix: string, canonical: Uint8Array): string {
  return `${prefix}:v1:` + b64uEncode(sha256(canonical));
}

// --- COSE_Sign1 (RFC 9052 subset; Sig_structure is a 4-array, external_aad
// = "PE1") ---
export function checkCanonical(raw: Uint8Array): unknown {
  let v: unknown;
  try {
    v = decodeStrict(raw);
  } catch (e) {
    throw new InteropFail(`parse: ${(e as Error).message}`);
  }
  if (!eqBytes(canonicalReencode(raw), raw)) {
    throw new InteropFail("non-canonical re-encoding");
  }
  return v;
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && toHex(a) === toHex(b);
}

export function verifySign1(
  sign1: Uint8Array,
  expectedKeyref: string
): [Uint8Array, Uint8Array] {
  const v = checkCanonical(sign1);
  if (!Array.isArray(v) || v.length !== 4) {
    throw new InteropFail("Sign1 must be a 4-array");
  }
  const [protRaw, unprot, payload, signature] = v;
  if (!(protRaw instanceof Uint8Array)) {
    throw new InteropFail("protected must be bstr");
  }
  if (!(unprot instanceof Map_) || unprot.pairs.length !== 0) {
    throw new InteropFail("unprotected must be empty");
  }
  if (!(payload instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
    throw new InteropFail("embedded payload/signature required");
  }
  const prot = checkCanonical(protRaw);
  if (!(prot instanceof Map_)) throw new InteropFail("protected must be map");
  if (!eqBytes(encMap(prot.pairs), protRaw)) {
    throw new InteropFail("protected not canonical");
  }
  const alg = mapGet(prot, 1);
  const kid = mapGet(prot, 4);
  if (!(kid instanceof Uint8Array)) throw new InteropFail("kid must be bstr");
  if (typeof alg !== "number") throw new InteropFail("alg must be int");
  let scheme: string, wantLen: number, op: "ed25519" | "p256";
  if (alg === -19) {
    scheme = "key:ed25519:";
    wantLen = 32;
    op = "ed25519";
  } else if (alg === -9) {
    scheme = "key:p256:";
    wantLen = 64;
    op = "p256";
  } else {
    throw new InteropFail(`unknown/deprecated alg ${alg}`);
  }
  if (!expectedKeyref.startsWith(scheme)) {
    throw new InteropFail("issuer/keyref scheme mismatch");
  }
  const expect = b64uDecode(expectedKeyref.slice(scheme.length));
  if (expect.length !== wantLen || !eqBytes(expect, kid)) {
    throw new InteropFail("kid does not match issuer key");
  }
  const tbs = Uint8Array.from([
    0x84,
    ...enc("Signature1"),
    ...enc(protRaw),
    ...enc(new Uint8Array([0x50, 0x45, 0x31])), // "PE1"
    ...enc(payload),
  ]);
  const ok =
    op === "ed25519"
      ? ed25519.verify(signature, tbs, kid)
      : p256Verify(kid, tbs, signature);
  if (!ok) throw new InteropFail("SIGNATURE_INVALID");
  return [payload, kid];
}

// --- closed schemas (mirrors proof-format check_closed: unknown member
// fields reject, fail closed) ---
const EVENT_FIELDS = new Set([
  "v",
  "type",
  "subject",
  "effective_at",
  "payload_ref",
  "metadata",
]);
const ATTESTATION_FIELDS = new Set([
  "v",
  "issuer",
  "subject",
  "claim",
  "issued_at",
  "expires_at",
  "evidence_ref",
]);
const EVIDENCE_FIELDS = new Set([
  "v",
  "kind",
  "digest",
  "attestation_ref",
  "hint",
]);
const REL_FIELDS = new Set([
  "v",
  "from",
  "type",
  "to",
  "evidence_ref",
  "attestation_ref",
]);
const PROP_FIELDS = new Set([
  "v",
  "kind",
  "subject",
  "predicate",
  "object",
  "at_time",
  "context",
]);
const PROOF_FIELDS = new Set([
  "v",
  "proof_id",
  "proposition",
  "events",
  "attestations",
  "evidence",
  "relationships",
  "referenced_proofs",
  "vocabularies",
  "created_at",
]);

function isMap(v: unknown): v is Map_ {
  return v instanceof Map_;
}
function closed(m: unknown, allowed: Set<string>, what: string): void {
  if (!isMap(m)) throw new InteropFail(`${what} must be map`);
  for (const [k] of m.pairs) {
    if (typeof k !== "string" || !allowed.has(k)) {
      throw new InteropFail(`unknown ${what} field ${String(k)}`);
    }
  }
}
function asMap(v: unknown, what: string): Map_ {
  if (!(v instanceof Map_)) throw new InteropFail(`${what} must be map`);
  return v;
}
function members(outer: Map_, key: string): unknown[] {
  const arr = mapGet(outer, key);
  if (!Array.isArray(arr)) throw new InteropFail(`${key} must be array`);
  return arr;
}

// PE-INTEROP-002: independent proof verification (stages 1-6 + binding).
export interface ProofReport {
  proof_id: string;
  created_at: unknown;
  event_ids: string[];
  attestation_ids: string[];
  evidence_ids: string[];
  relationship_ids: string[];
  referenced_proofs: string[];
  issuers: string[];
}

function checkRef(
  v: unknown,
  what: string,
  prefix: string
): void {
  // Typed-reference parity (F4/F5): wrong-typed ids reject at schema.
  if (v === null || v === undefined) return;
  if (typeof v !== "string" || !v.startsWith(prefix)) {
    throw new InteropFail(`${what} must start with ${prefix}`);
  }
}

export function verifyProof(proofRaw: Uint8Array): ProofReport {
  const outer = asMap(checkCanonical(proofRaw), "proof");
  for (const [k] of outer.pairs) {
    if (typeof k !== "string" || !PROOF_FIELDS.has(k)) {
      throw new InteropFail(`unknown proof field ${String(k)}`);
    }
  }
  if (mapGet(outer, "v") !== 1) {
    throw new InteropFail("unsupported proof version");
  }
  const prop = mapGet(outer, "proposition");
  closed(prop, PROP_FIELDS, "proposition");
  const created = mapGet(outer, "created_at");
  if (typeof created !== "number" || !Number.isInteger(created)) {
    throw new InteropFail("created_at must be a uint");
  }

  const eventIds: string[] = [];
  for (const m of members(outer, "events")) {
    closed(m, EVENT_FIELDS, "event");
    eventIds.push(objId("evt", encAny(m)));
  }
  const attIds: string[] = [];
  const issuers: string[] = [];
  for (const entry of members(outer, "attestations")) {
    const ed = asMap(entry, "attestation entry");
    for (const [k] of ed.pairs) {
      if (k !== "content" && k !== "sign1") {
        throw new InteropFail(`unknown attestation entry field ${String(k)}`);
      }
    }
    const contentRaw = encAny(mapGet(ed, "content"));
    closed(decodeStrict(contentRaw), ATTESTATION_FIELDS, "attestation");
    const payload = asMap(decodeStrict(contentRaw), "attestation content");
    checkRef(mapGet(payload, "evidence_ref"), "attestation.evidence_ref", "evd:v1:");
    const sign1 = mapGet(ed, "sign1");
    if (!(sign1 instanceof Uint8Array)) {
      throw new InteropFail("sign1 must be bstr");
    }
    attIds.push(objId("att", contentRaw));
    const issuer = mapGet(payload, "issuer");
    if (typeof issuer !== "string") {
      throw new InteropFail("issuer must be text");
    }
    const [authPayload] = verifySign1(sign1, issuer);
    if (!eqBytes(authPayload, contentRaw)) {
      throw new InteropFail(
        "envelope content differs from authenticated payload"
      );
    }
    issuers.push(issuer);
  }
  const evdIds: string[] = [];
  for (const m of members(outer, "evidence")) {
    closed(m, EVIDENCE_FIELDS, "evidence");
    const em = asMap(m, "evidence");
    checkRef(mapGet(em, "attestation_ref"), "evidence.attestation_ref", "att:v1:");
    evdIds.push(objId("evd", encAny(m)));
  }
  const relIds: string[] = [];
  for (const m of members(outer, "relationships")) {
    closed(m, REL_FIELDS, "relationship");
    const rm = asMap(m, "relationship");
    checkRef(mapGet(rm, "evidence_ref"), "relationship.evidence_ref", "evd:v1:");
    checkRef(mapGet(rm, "attestation_ref"), "relationship.attestation_ref", "att:v1:");
    relIds.push(objId("rel", encAny(m)));
  }
  return finishProofBinding(
    outer, created, eventIds, attIds, evdIds, relIds, issuers
  );
}

function finishProofBinding(
  outer: Map_,
  created: unknown,
  eventIds: string[],
  attIds: string[],
  evdIds: string[],
  relIds: string[],
  issuers: string[]
): ProofReport {
  // Composition linkage (SPEC §7): absent in V1 bytes -> empty; present ->
  // sorted well-formed `prf:v1:` ids, covered by the binding.
  const refsRaw = mapOpt(outer, "referenced_proofs");
  let refs: string[] = [];
  if (refsRaw !== null && refsRaw !== undefined) {
    if (!Array.isArray(refsRaw) || refsRaw.some((x) => typeof x !== "string")) {
      throw new InteropFail("referenced_proofs must be an array of text");
    }
    for (const x of refsRaw as string[]) {
      if (!x.startsWith("prf:v1:")) {
        throw new InteropFail("referenced proof id must start with prf:v1:");
      }
      let raw: Uint8Array;
      try {
        raw = b64uDecode(x.slice("prf:v1:".length));
      } catch {
        throw new InteropFail("referenced proof id is not base64url");
      }
      if (raw.length !== 32) {
        throw new InteropFail("referenced proof id digest must be 32 bytes");
      }
    }
    const sorted = [...(refsRaw as string[])].sort();
    if (
      JSON.stringify(sorted) !== JSON.stringify(refsRaw) ||
      new Set(refsRaw).size !== refsRaw.length
    ) {
      throw new InteropFail(
        "referenced_proofs must be sorted with no duplicates"
      );
    }
    refs = refsRaw as string[];
  }
  return bindAndReport(
    outer, created, eventIds, attIds, evdIds, relIds, issuers, refs
  );
}

function bindAndReport(
  outer: Map_,
  created: unknown,
  eventIds: string[],
  attIds: string[],
  evdIds: string[],
  relIds: string[],
  issuers: string[],
  refs: string[]
): ProofReport {
  const binding: [string, unknown][] = [
    ["attestations", [...attIds].sort()],
    ["created_at", created],
    ["events", [...eventIds].sort()],
    ["evidence", [...evdIds].sort()],
    ["relationships", [...relIds].sort()],
    ["proposition", mapGet(outer, "proposition")],
    ["v", 1],
  ];
  if (refs.length > 0) binding.push(["referenced_proofs", [...refs].sort()]);
  const vocs = mapOpt(outer, "vocabularies");
  if (vocs !== null && vocs !== undefined) {
    if (!Array.isArray(vocs)) {
      throw new InteropFail("vocabularies must be an array");
    }
    let prev: string | null = null;
    const encVocs: [string, unknown][] = [];
    for (const item of vocs) {
      const dd = asMap(item, "vocabulary");
      const keys = dd.pairs
        .map(([k]) => k)
        .sort()
        .join(",");
      if (keys !== "ns,version") {
        throw new InteropFail("vocabulary must be exactly {ns, version}");
      }
      const ns = mapGet(dd, "ns");
      const ver = mapGet(dd, "version");
      if (typeof ns !== "string" || !ns || ns.length > 128) {
        throw new InteropFail("vocabulary ns length out of bounds");
      }
      if (ns.includes(":") || /\s/.test(ns)) {
        throw new InteropFail(
          "vocabulary ns must not contain ':' or whitespace"
        );
      }
      if (typeof ver !== "number" || !Number.isInteger(ver) || ver < 0) {
        throw new InteropFail("vocabulary version must be a uint");
      }
      if (prev !== null && ns <= prev) {
        throw new InteropFail(
          "vocabularies must be sorted by ns with no duplicates"
        );
      }
      prev = ns;
      encVocs.push([ns, ver]);
    }
    binding.push([
      "vocabularies",
      encVocs.map(
        ([ns, ver]) => new Map_([["ns", ns], ["version", ver]])
      ),
    ]);
  }
  const recomputed = objId("prf", encMap(binding));
  // The engine rejects a proof referencing itself (golden-25: ID_MISMATCH +
  // CYCLE_DETECTED at graph stage). The id is computable here, so bind-time
  // rejection matches the engine without needing the graph pipeline.
  if (refs.includes(recomputed)) {
    throw new InteropFail("ID_MISMATCH: proof references itself");
  }
  if (recomputed !== mapGet(outer, "proof_id")) {
    throw new InteropFail("ID_MISMATCH on proof_id");
  }
  return {
    proof_id: recomputed,
    created_at: created,
    event_ids: eventIds,
    attestation_ids: attIds,
    evidence_ids: evdIds,
    relationship_ids: relIds,
    referenced_proofs: refs,
    issuers,
  };
}

// --- PE-INTEROP-003: independent artifact creation (I3, TS side). ---
// Ed25519-only, mirroring interop/pengine.py's creators. Every creator
// self-checks its output through this implementation's independent verifier.

export function coseSign1(
  payloadCanon: Uint8Array,
  seed32: Uint8Array
): [Uint8Array, Uint8Array] {
  const pub = ed25519.getPublicKey(seed32);
  const prot = encMap([
    [1, -19],
    [4, pub],
  ]);
  const tbs = concat(
    Uint8Array.from([0x84]),
    enc("Signature1"),
    enc(prot),
    enc(new Uint8Array([0x50, 0x45, 0x31])), // "PE1"
    enc(payloadCanon)
  );
  const sig = ed25519.sign(tbs, seed32);
  return [encAny([prot, new Map_([]), payloadCanon, sig]), pub];
}

export function keyRefEd25519(pub32: Uint8Array): string {
  return "key:ed25519:" + b64uEncode(pub32);
}

export interface Artifact {
  id: string;
  cbor: string; // hex of canonical content bytes
}

export function makeEvent(
  eventType: string,
  subject: string,
  effectiveAt: number,
  payloadDigest32: Uint8Array,
  metadata: [string, unknown][] = []
): Artifact {
  const raw = encMap([
    ["effective_at", effectiveAt],
    ["metadata", new Map_(metadata)],
    [
      "payload_ref",
      new Map_([
        ["alg", 0],
        ["digest", payloadDigest32],
        ["v", 1],
      ]),
    ],
    ["subject", subject],
    ["type", eventType],
    ["v", 1],
  ]);
  return { id: objId("evt", raw), cbor: toHex(raw) };
}

export type MetaValue =
  | { kind: "text"; value: string }
  | { kind: "uint"; value: number }
  | { kind: "bool"; value: boolean };

export interface AttestationArtifact extends Artifact {
  issuer: string;
  sign1_b64: string; // base64url of the COSE_Sign1 envelope
}

export function makeAttestation(
  seed32: Uint8Array,
  subject: string,
  claimType: string,
  fields: [string, MetaValue][],
  issuedAt: number,
  expiresAt: number | null = null,
  evidenceRef: string | null = null
): AttestationArtifact {
  const pub = ed25519.getPublicKey(seed32);
  const issuer = keyRefEd25519(pub);
  const claim: [string, unknown][] = [["type", claimType]];
  for (const [k, mv] of fields) claim.push([k, mv.value]);
  const raw = encMap([
    ["claim", new Map_(claim)],
    ["evidence_ref", evidenceRef],
    ["expires_at", expiresAt],
    ["issued_at", issuedAt],
    ["issuer", issuer],
    ["subject", subject],
    ["v", 1],
  ]);
  const [sign1] = coseSign1(raw, seed32);
  // self-check: what we just built must verify under our own verifier
  const [payload] = verifySign1(sign1, issuer);
  if (!eqBytes(payload, raw)) throw new InteropFail("creator self-check failed");
  return {
    id: objId("att", raw),
    issuer,
    cbor: toHex(raw),
    sign1_b64: b64uEncode(sign1),
  };
}

export function makeEvidence(
  kind: string,
  digest32: Uint8Array,
  attestationRef: string | null = null,
  hint: string | null = null
): Artifact {
  const raw = encMap([
    ["attestation_ref", attestationRef],
    [
      "digest",
      new Map_([
        ["alg", 0],
        ["digest", digest32],
        ["v", 1],
      ]),
    ],
    ["hint", hint],
    ["kind", kind],
    ["v", 1],
  ]);
  return { id: objId("evd", raw), cbor: toHex(raw) };
}

export function makeRelationship(
  fromId: string,
  relType: string,
  toId: string,
  evidenceRef: string | null = null,
  attestationRef: string | null = null
): Artifact {
  const raw = encMap([
    ["attestation_ref", attestationRef],
    ["evidence_ref", evidenceRef],
    ["from", fromId],
    ["to", toId],
    ["type", relType],
    ["v", 1],
  ]);
  return { id: objId("rel", raw), cbor: toHex(raw) };
}

export interface AttestationInput {
  cbor: string; // hex of attestation content
  sign1_b64: string; // base64url of COSE_Sign1
}

export interface ProofInput {
  events: Artifact[];
  attestations: AttestationInput[];
  evidence: Artifact[];
  relationships: Artifact[];
  referenced_proofs?: string[]; // must be sorted, no duplicates
  vocabularies?: [string, number][]; // sorted by ns, no duplicates
}

export function makeProof(
  kind: string,
  subject: string,
  predicate: string,
  obj: string | null,
  atTime: number | null,
  context: [string, unknown][],
  createdAt: number,
  input: ProofInput
): Artifact & { raw: string } {
  const evRaw = input.events.map((e) => bytesFromHex(e.cbor));
  const evdRaw = input.evidence.map((e) => bytesFromHex(e.cbor));
  const relRaw = input.relationships.map((e) => bytesFromHex(e.cbor));
  const attEntries = input.attestations.map((a) => [
    bytesFromHex(a.cbor),
    b64uDecode(a.sign1_b64),
  ]);
  const propRaw = encMap([
    ["at_time", atTime],
    ["context", new Map_(context)],
    ["kind", kind],
    ["object", obj],
    ["predicate", predicate],
    ["subject", subject],
    ["v", 1],
  ]);
  const ids = (prefix: string, raws: Uint8Array[]): string[] =>
    raws.map((r) => objId(prefix, r)).sort();
  const binding: [string, unknown][] = [
    ["attestations", attEntries.map(([c]) => objId("att", c as Uint8Array)).sort()],
    ["created_at", createdAt],
    ["events", ids("evt", evRaw)],
    ["evidence", ids("evd", evdRaw)],
    ["relationships", ids("rel", relRaw)],
    ["proposition", decodeStrict(propRaw)],
    ["v", 1],
  ];
  if (input.referenced_proofs && input.referenced_proofs.length > 0) {
    const refs = [...input.referenced_proofs].sort();
    if (
      JSON.stringify(refs) !== JSON.stringify(input.referenced_proofs) ||
      new Set(refs).size !== refs.length
    ) {
      throw new InteropFail("creator refs must be sorted with no duplicates");
    }
    binding.push(["referenced_proofs", refs]);
  }
  if (input.vocabularies && input.vocabularies.length > 0) {
    const vocs = [...input.vocabularies].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    if (
      JSON.stringify(vocs.map(([n]) => n)) !==
        JSON.stringify(input.vocabularies.map(([n]) => n)) ||
      new Set(input.vocabularies.map(([n]) => n)).size !==
        input.vocabularies.length
    ) {
      throw new InteropFail(
        "creator vocabularies must be sorted by ns with no duplicates"
      );
    }
    binding.push([
      "vocabularies",
      vocs.map(
        ([ns, ver]) => new Map_([["ns", ns], ["version", ver]])
      ),
    ]);
  }
  const proofId = objId("prf", encMap(binding));
  const outer: [string, unknown][] = [
    [
      "attestations",
      attEntries.map(
        ([c, s]) =>
          new Map_([
            ["content", decodeStrict(c as Uint8Array)],
            ["sign1", s],
          ])
      ),
    ],
    ["created_at", createdAt],
    ["events", evRaw.map((r) => decodeStrict(r))],
    ["evidence", evdRaw.map((r) => decodeStrict(r))],
    ["proof_id", proofId],
    ["proposition", decodeStrict(propRaw)],
    ["relationships", relRaw.map((r) => decodeStrict(r))],
    ["v", 1],
  ];
  if (input.referenced_proofs && input.referenced_proofs.length > 0) {
    outer.push(["referenced_proofs", [...input.referenced_proofs].sort()]);
  }
  if (input.vocabularies && input.vocabularies.length > 0) {
    outer.push([
      "vocabularies",
      [...input.vocabularies]
        .sort((a, b) => (a[0] < b[0] ? -1 : 1))
        .map(([ns, ver]) => new Map_([["ns", ns], ["version", ver]])),
    ]);
  }
  const proofRaw = encMap(outer);
  // self-check through this implementation's independent verifier
  const got = verifyProof(proofRaw);
  if (got.proof_id !== proofId) {
    throw new InteropFail("creator self-check: proof_id mismatch");
  }
  return { id: proofId, cbor: toHex(proofRaw), raw: toHex(proofRaw) };
}

function bytesFromHex(h: string): Uint8Array {
  if (!/^[0-9a-f]*$/.test(h) || h.length % 2 !== 0) {
    throw new InteropFail("bad hex");
  }
  return Uint8Array.from(Buffer.from(h, "hex"));
}

