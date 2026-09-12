// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Independent ProofEngine artifact creation for Node/TypeScript (I3
// equivalent of interop/pengine.py's PE-INTEROP-003 creators). Ed25519
// only; every artifact self-checks through the independent verifier before
// it is returned.
import { ed25519 } from "@noble/curves/ed25519";
import { Map_, concat, dec, enc, encAny, encMap } from "./minicbor.js";
import { InteropFail, b64uEncode, objId, verifyProof, verifySign1, } from "./pengine.js";
export function edPubkey(seed32) {
    return ed25519.getPublicKey(seed32);
}
export function edSign(seed32, msg) {
    return ed25519.sign(msg, seed32);
}
// Build a COSE_Sign1 envelope (Ed25519 only). external_aad = "PE1",
// Sig_structure is a 4-array.
export function coseSign1(payloadCanon, seed32) {
    const pub = edPubkey(seed32);
    const prot = encMap([
        [1, -19],
        [4, pub],
    ]);
    const tbs = concat(Uint8Array.from([0x84]), enc("Signature1"), enc(prot), enc(Uint8Array.from([0x50, 0x45, 0x31])), // "PE1"
    enc(payloadCanon));
    const sig = edSign(seed32, tbs);
    return [encAny([prot, new Map_([]), payloadCanon, sig]), pub];
}
export function keyRefEd25519(pub32) {
    return "key:ed25519:" + b64uEncode(pub32);
}
const hexOf = (b) => Buffer.from(b).toString("hex");
export function makeEvent(eventType, subject, effectiveAt, payloadDigest32, metadata = []) {
    const content = new Map_([
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
    const raw = encMap(content.pairs);
    return { id: objId("evt", raw), cbor: hexOf(raw) };
}
export function makeAttestation(seed32, subject, claimType, fields, issuedAt, expiresAt = null, evidenceRef = null) {
    const pub = edPubkey(seed32);
    const issuer = keyRefEd25519(pub);
    const meta = (v) => v[1];
    const claim = new Map_([
        ["type", claimType],
        ...fields.map(([k, v]) => [k, meta(v)]),
    ]);
    const content = new Map_([
        ["claim", claim],
        ["evidence_ref", evidenceRef],
        ["expires_at", expiresAt],
        ["issued_at", issuedAt],
        ["issuer", issuer],
        ["subject", subject],
        ["v", 1],
    ]);
    const raw = encMap(content.pairs);
    const [sign1] = coseSign1(raw, seed32);
    const attId = objId("att", raw);
    // creator self-check: what we just built must verify
    const [payload] = verifySign1(sign1, issuer);
    if (Buffer.compare(Buffer.from(payload), Buffer.from(raw)) !== 0) {
        throw new InteropFail("creator self-check failed");
    }
    return { id: attId, issuer, cbor: hexOf(raw), sign1_b64: b64uEncode(sign1) };
}
export function makeEvidence(kind, digest32, attestationRef = null, hint = null) {
    const content = new Map_([
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
    const raw = encMap(content.pairs);
    return { id: objId("evd", raw), cbor: hexOf(raw) };
}
export function makeRelationship(fromId, relType, toId, evidenceRef = null, attestationRef = null) {
    const content = new Map_([
        ["attestation_ref", attestationRef],
        ["evidence_ref", evidenceRef],
        ["from", fromId],
        ["to", toId],
        ["type", relType],
        ["v", 1],
    ]);
    const raw = encMap(content.pairs);
    return { id: objId("rel", raw), cbor: hexOf(raw) };
}
export function makeProof(kind, subject, predicate, obj, atTime, context = [], createdAt = 0, events = [], attestations = [], evidence = [], relationships = [], referencedProofs = []) {
    const evRaw = events.map((e) => Buffer.from(e.cbor, "hex"));
    const evdRaw = evidence.map((e) => Buffer.from(e.cbor, "hex"));
    const relRaw = relationships.map((e) => Buffer.from(e.cbor, "hex"));
    const attEntries = attestations.map((a) => ({
        content: Buffer.from(a.cbor, "hex"),
        sign1: Buffer.from(a.sign1_b64, "base64url"),
    }));
    const prop = new Map_([
        ["at_time", atTime],
        ["context", new Map_(context)],
        ["kind", kind],
        ["object", obj],
        ["predicate", predicate],
        ["subject", subject],
        ["v", 1],
    ]);
    const propRaw = encMap(prop.pairs);
    const ids = (prefix, raws) => raws.map((r) => objId(prefix, r)).sort();
    const eIds = ids("evt", evRaw);
    const aIds = attEntries.map((a) => objId("att", a.content)).sort();
    const dIds = ids("evd", evdRaw);
    const rIds = ids("rel", relRaw);
    const binding = new Map_([
        ["attestations", aIds],
        ["events", eIds],
        ["evidence", dIds],
        ["relationships", rIds],
        ["proposition", prop],
        ["v", 1],
    ]);
    if (referencedProofs.length > 0) {
        const refs = [...referencedProofs].sort();
        if (JSON.stringify(refs) !== JSON.stringify(referencedProofs) ||
            new Set(refs).size !== refs.length) {
            throw new InteropFail("creator refs must be sorted with no duplicates");
        }
        binding.pairs.push(["referenced_proofs", refs]);
    }
    const proofId = objId("prf", encMap(binding.pairs));
    const rawMap = (b) => {
        const [v, pos] = dec(b);
        if (pos !== b.length || !(v instanceof Map_)) {
            throw new InteropFail("creator: member re-decode failed");
        }
        return v;
    };
    const outer = new Map_([
        [
            "attestations",
            attEntries.map((a) => new Map_([
                ["content", rawMap(a.content)],
                ["sign1", a.sign1],
            ])),
        ],
        ["created_at", createdAt],
        ["events", evRaw.map(rawMap)],
        ["evidence", evdRaw.map(rawMap)],
        ["proof_id", proofId],
        ["proposition", rawMap(propRaw)],
        ["relationships", relRaw.map(rawMap)],
        ["v", 1],
    ]);
    if (referencedProofs.length > 0) {
        outer.pairs.push(["referenced_proofs", [...referencedProofs].sort()]);
    }
    const proofRaw = encMap(outer.pairs);
    // creator self-check through the independent verifier
    const rep = verifyProof(proofRaw);
    if (rep.proof_id !== proofId) {
        throw new InteropFail("creator self-check failed: proof_id mismatch");
    }
    return { id: proofId, cbor: hexOf(proofRaw) };
}
