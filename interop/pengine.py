# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent ProofEngine crypto + proof layer (no engine code, stdlib only).

Covers verification stages PARSE/CANONICAL(order+shortest)/IDENTIFIERS/
SIGNATURES/KEYS-shape plus proof_id binding: the cryptographic interop
core. Time/lifecycle/graph/policy are engine-side concerns (their inputs
are caller-supplied) and are NOT reimplemented here — see README scope.

Ed25519 follows RFC 8032; cross-validated during audit against
ed25519-dalek (base point, group order, Montgomery images, accept/reject).
P-256 follows SEC1 v2.0 §4.1.4 (ECDSA over secp256r1 with SHA-256);
cross-checked against golden-21/22/23 plus Rust-side negative vectors.
"""
import base64
import hashlib

from minicbor import CErr, Map, dec, decode_strict, enc, enc_any, enc_map

P = 2**255 - 19
D = -121665 * pow(121666, P - 2, P) % P
Q = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


def _xrec(y):
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    return x if x % 2 == 0 else P - x


def _pt_add(p, q):
    (x1, y1), (x2, y2) = p, q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + D * x1 * x2 * y1 * y2) % P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - D * x1 * x2 * y1 * y2) % P
    return (x3, y3)


def _pt_mul(s, p):
    r = (0, 1)
    while s:
        if s & 1:
            r = _pt_add(r, p)
        p = _pt_add(p, p)
        s >>= 1
    return r


_Gy = int.from_bytes(bytes.fromhex("58" + "66" * 31), "little")
assert _Gy < P and (_Gy >> 255) == 0
_Gx = _xrec(_Gy)
assert (-_Gx * _Gx + _Gy * _Gy - (1 + D * _Gx * _Gx * _Gy * _Gy)) % P == 0
G = (_Gx, _Gy)


def _clamp(h32):
    a = int.from_bytes(h32, "little") & ~7
    return (a & ~(1 << 255)) | (1 << 254)


def _compress(pt):
    x, y = pt
    return ((y & ~(1 << 255)) | ((x & 1) << 255)).to_bytes(32, "little")


def ed_pubkey(seed32):
    h = hashlib.sha512(seed32).digest()
    return _compress(_pt_mul(_clamp(h[:32]), G))


def _pt_from_enc(e):
    y = int.from_bytes(e, "little")
    bit = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        raise ValueError("y out of range")
    x = _xrec(y)
    if x & 1 != bit:
        x = P - x
    return (x, y)


def ed_verify(pub, msg, sig):
    if len(sig) != 64 or len(pub) != 32:
        return False
    R, S = sig[:32], int.from_bytes(sig[32:], "little")
    if S >= Q:
        return False
    try:
        A = _pt_from_enc(pub)
        Rp = _pt_from_enc(R)
    except Exception:
        return False
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % Q
    return _pt_mul(S, G) == _pt_add(Rp, _pt_mul(k, A))


def ed_sign(seed32, msg):
    """RFC 8032 pure-EdDSA signing (for I3 artifact creation)."""
    h = hashlib.sha512(seed32).digest()
    a = _clamp(h[:32])
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % Q
    R = _compress(_pt_mul(r, G))
    A = ed_pubkey(seed32)
    S = (r + int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") * a) % Q
    return R + S.to_bytes(32, "little")


# --- secp256r1 / ECDSA (SEC1 v2.0 §4.1.4, SHA-256) ---
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = (_P256_P - 3) % _P256_P
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (_P256_GX, _P256_GY)


def _p256_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        # doubling
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, _P256_P - 2, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % _P256_P, _P256_P - 2, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    return (x3, (lam * (x1 - x3) - y1) % _P256_P)


def _p256_mul(s, p):
    r = None
    while s:
        if s & 1:
            r = _p256_add(r, p)
        p = _p256_add(p, p)
        s >>= 1
    return r


def p256_verify(pub64, msg, sig64):
    """ECDSA verify over secp256r1. pub64 = X||Y big-endian, sig64 = r||s."""
    if len(sig64) != 64 or len(pub64) != 64:
        return False
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        return False
    x = int.from_bytes(pub64[:32], "big")
    y = int.from_bytes(pub64[32:], "big")
    if not (0 <= x < _P256_P and 0 <= y < _P256_P):
        return False
    if (y * y - (x * x * x + _P256_A * x + _P256_B)) % _P256_P != 0:
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, _P256_N - 2, _P256_N)
    u1, u2 = e * w % _P256_N, r * w % _P256_N
    pt = _p256_add(_p256_mul(u1, _P256_G), _p256_mul(u2, (x, y)))
    return pt is not None and pt[0] % _P256_N == r


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256(b):
    return hashlib.sha256(b).digest()


def obj_id(prefix, canonical):
    return f"{prefix}:v1:" + b64u(sha256(canonical))


class InteropFail(Exception):
    """A check the engine would reject (caller maps to codes)."""


def _map(raw):
    v, pos = dec(raw)
    if pos != len(raw):
        raise InteropFail("trailing bytes")
    if not isinstance(v, Map):
        raise InteropFail("top-level map expected")
    return v


def _req(d, key):
    for k, v in d:
        if k == key:
            return v
    raise InteropFail(f"missing field {key}")


def check_canonical(raw):
    """Stage PARSE+CANONICAL equivalent: strict decode + byte-identity."""
    try:
        v = decode_strict(raw)
    except CErr as e:
        raise InteropFail(f"parse: {e}")
    if enc_any(v) != raw:
        raise InteropFail("non-canonical re-encoding")
    return v


def verify_sign1(sign1, expected_keyref):
    """COSE_Sign1 verify. Returns (payload_bytes, kid_bytes)."""
    v = check_canonical(sign1)
    if not isinstance(v, list) or len(v) != 4:
        raise InteropFail("Sign1 must be a 4-array")
    prot_raw, unprot, payload, signature = v
    if not isinstance(prot_raw, bytes):
        raise InteropFail("protected must be bstr")
    if not isinstance(unprot, Map) or len(unprot) != 0:
        raise InteropFail("unprotected must be empty")
    if not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise InteropFail("embedded payload/signature required")
    pp = _map(prot_raw)
    if enc_map(pp) != prot_raw:
        raise InteropFail("protected not canonical")
    pd = dict(pp)
    if set(pd) != {1, 4}:
        raise InteropFail("protected must be exactly {1, 4}")
    alg = pd[1]
    kid = pd[4]
    if not isinstance(kid, bytes):
        raise InteropFail("kid must be bstr")
    if alg == -19:
        scheme, want_len, op = "key:ed25519:", 32, "ed25519"
    elif alg == -9:
        scheme, want_len, op = "key:p256:", 64, "p256"
    else:
        raise InteropFail(f"unknown/deprecated alg {alg}")
    if not expected_keyref.startswith(scheme):
        raise InteropFail("issuer/keyref scheme mismatch")
    try:
        expect = b64u_decode(expected_keyref[len(scheme):])
    except Exception:
        raise InteropFail("bad keyref base64url")
    if b64u(expect) != expected_keyref[len(scheme):]:
        raise InteropFail("keyref is not canonical base64url")
    if len(expect) != want_len or expect != kid:
        raise InteropFail("kid does not match issuer key")
    tbs = (
        b"\x84" + enc("Signature1") + enc(prot_raw) + enc(b"PE1") + enc(payload)
    )
    if op == "ed25519":
        ok = ed_verify(kid, tbs, signature)
    else:
        ok = p256_verify(kid, tbs, signature)
    if not ok:
        raise InteropFail("SIGNATURE_INVALID")
    return payload, kid


def _closed(m, allowed, what):
    """Closed-schema parity with the engine: unknown member fields reject,
    mirroring proof-format's check_closed (fail closed, never ignore)."""
    if not isinstance(m, Map):
        raise InteropFail(f"{what} must be map")
    for k, _ in m:
        if k not in allowed:
            raise InteropFail(f"unknown {what} field {k!r}")


_EVENT_FIELDS = ("v", "type", "subject", "effective_at", "payload_ref",
                 "metadata")
_ATTESTATION_FIELDS = ("v", "issuer", "subject", "claim", "issued_at",
                       "expires_at", "evidence_ref")
_EVIDENCE_FIELDS = ("v", "kind", "digest", "attestation_ref", "hint")
_REL_FIELDS = ("v", "from", "type", "to", "evidence_ref", "attestation_ref")
_PROP_FIELDS = ("v", "kind", "subject", "predicate", "object", "at_time",
                "context")


# PE-INTEROP-002: independent proof verification (stages 1-6 + binding).
def verify_proof(proof_raw):
    """Stages 1-6 + proof_id binding for a full proof.

    Returns dict with proof_id, member ids, verified issuers. Raises
    InteropFail on anything the engine would reject at these stages.
    Time/lifecycle/graph/policy are out of scope (see module docstring).
    """
    outer = check_canonical(proof_raw)
    if not isinstance(outer, Map):
        raise InteropFail("proof must be map")
    # Closed envelope: unknown top-level fields are rejected, mirroring the
    # engine's closed schema (fail closed, never ignore).
    for k, _ in outer:
        if k not in ("v", "proof_id", "proposition", "events", "attestations",
                     "evidence", "relationships", "referenced_proofs",
                     "vocabularies", "created_at"):
            raise InteropFail(f"unknown proof field {k!r}")
    d = dict(outer)
    if d.get("v") != 1:
        raise InteropFail("unsupported proof version")
    prop = _req(outer, "proposition")
    if not isinstance(prop, Map):
        raise InteropFail("proposition must be map")
    _closed(prop, _PROP_FIELDS, "proposition")
    created = d.get("created_at")
    if not isinstance(created, int) or isinstance(created, bool):
        raise InteropFail("created_at must be a uint")

    def members(key, prefix):
        arr = _req(outer, key)
        if not isinstance(arr, list):
            raise InteropFail(f"{key} must be array")
        return arr

    event_ids = []
    for m in members("events", "evt"):
        _closed(m, _EVENT_FIELDS, "event")
        event_ids.append(obj_id("evt", enc_any(m)))
    att_ids, issuers = [], []
    for entry in members("attestations", "att"):
        if not isinstance(entry, Map):
            raise InteropFail("attestation entry must be map")
        for k, _ in entry:
            if k not in ("content", "sign1"):
                raise InteropFail(f"unknown attestation entry field {k!r}")
        ed = dict(entry)
        content_raw = enc_any(_req(entry, "content"))
        _closed(_map(content_raw), _ATTESTATION_FIELDS, "attestation")
        sign1 = _req(entry, "sign1")
        if not isinstance(sign1, bytes):
            raise InteropFail("sign1 must be bstr")
        att_ids.append(obj_id("att", content_raw))
        # issuer comes from the authenticated payload, never from kid alone
        payload = _map(content_raw)
        issuer = _req(payload, "issuer")
        auth_payload, _ = verify_sign1(sign1, issuer)
        if auth_payload != content_raw:
            raise InteropFail("envelope content differs from authenticated payload")
        issuers.append(issuer)
    evd_ids = []
    for m in members("evidence", "evd"):
        _closed(m, _EVIDENCE_FIELDS, "evidence")
        evd_ids.append(obj_id("evd", enc_any(m)))
    rel_ids = []
    for m in members("relationships", "rel"):
        _closed(m, _REL_FIELDS, "relationship")
        rel_ids.append(obj_id("rel", enc_any(m)))

    # Composition linkage (SPEC §7): absent in V1 bytes → empty; present →
    # sorted list of well-formed `prf:v1:` ids, covered by the binding.
    refs_raw = d.get("referenced_proofs")
    if refs_raw is None:
        refs = []
    else:
        if not isinstance(refs_raw, list) or any(
            not isinstance(x, str) for x in refs_raw
        ):
            raise InteropFail("referenced_proofs must be an array of text")
        for x in refs_raw:
            if not x.startswith("prf:v1:"):
                raise InteropFail("referenced proof id must start with prf:v1:")
            try:
                raw = b64u_decode(x[len("prf:v1:"):])
            except Exception:
                raise InteropFail("referenced proof id is not base64url")
            if b64u(raw) != x[len("prf:v1:"):] or len(raw) != 32:
                raise InteropFail("referenced proof id digest must be 32 bytes")
        if sorted(refs_raw) != list(refs_raw) or len(set(refs_raw)) != len(refs_raw):
            raise InteropFail("referenced_proofs must be sorted with no duplicates")
        refs = list(refs_raw)

    binding = Map([
        ("attestations", sorted(att_ids)),
        ("created_at", created),
        ("events", sorted(event_ids)),
        ("evidence", sorted(evd_ids)),
        ("relationships", sorted(rel_ids)),
        ("proposition", prop),
        ("v", 1),
    ])
    if refs:
        binding.append(("referenced_proofs", sorted(refs)))
    vocs = d.get("vocabularies")
    if vocs:
        # Sorted-by-ns [{ns, version}] declarations, covered by the binding.
        if not isinstance(vocs, list):
            raise InteropFail("vocabularies must be an array")
        seen = set()
        for item in vocs:
            if not isinstance(item, Map):
                raise InteropFail("vocabulary must be a map")
            dd = dict(item)
            if set(dd) != {"ns", "version"}:
                raise InteropFail("vocabulary must be exactly {ns, version}")
            ns, ver = dd["ns"], dd["version"]
            if not isinstance(ns, str) or not ns or len(ns) > 128:
                raise InteropFail("vocabulary ns length out of bounds")
            if ":" in ns or any(ch.isspace() for ch in ns):
                raise InteropFail("vocabulary ns must not contain ':' or whitespace")
            if not isinstance(ver, int) or isinstance(ver, bool) or ver < 0:
                raise InteropFail("vocabulary version must be a uint")
            if ns in seen:
                raise InteropFail("vocabularies must be sorted by ns with no duplicates")
            seen.add(ns)
        if [dict(x)["ns"] for x in vocs] != sorted(seen):
            raise InteropFail("vocabularies must be sorted by ns with no duplicates")
        binding.append(("vocabularies", [
            Map([("ns", dict(item)["ns"]), ("version", dict(item)["version"])])
            for item in vocs
        ]))
    recomputed = obj_id("prf", enc_map(binding))
    if recomputed != d.get("proof_id"):
        raise InteropFail("ID_MISMATCH on proof_id")
    return {
        "proof_id": recomputed,
        "created_at": created,
        "event_ids": event_ids,
        "attestation_ids": att_ids,
        "evidence_ids": evd_ids,
        "relationship_ids": rel_ids,
        "referenced_proofs": refs,
        "issuers": issuers,
    }


def sign1_payload(sign1):
    v, pos = dec(sign1)
    if pos != len(sign1) or not isinstance(v, list) or len(v) != 4:
        raise InteropFail("Sign1 shape")
    return v[2]


# PE-INTEROP-003: independent artifact creation (I3).
def cose_sign1(payload_canon, seed32, alg=-19):
    """Build a COSE_Sign1 envelope (for I3 creation). Ed25519 only."""
    if alg != -19:
        raise InteropFail("interop creator supports Ed25519 only")
    pub = ed_pubkey(seed32)
    prot = enc_map(Map([(1, -19), (4, pub)]))
    tbs = b"\x84" + enc("Signature1") + enc(prot) + enc(b"PE1") + enc(payload_canon)
    sig = ed_sign(seed32, tbs)
    return enc_any([prot, Map([]), payload_canon, sig]), pub


def key_ref_ed25519(pub32):
    return "key:ed25519:" + b64u(pub32)


def make_event(event_type, subject, effective_at, payload_digest32, metadata=()):
    content = Map([
        ("effective_at", effective_at),
        ("metadata", Map(list(metadata))),
        ("payload_ref", Map([("alg", 0), ("digest", payload_digest32), ("v", 1)])),
        ("subject", subject),
        ("type", event_type),
        ("v", 1),
    ])
    raw = enc_map(content)
    return {"id": obj_id("evt", raw), "cbor": raw.hex()}


def make_attestation(seed32, subject, claim_type, fields, issued_at, expires_at=None,
                     evidence_ref=None):
    """fields: list of (key, MetaValue) with MetaValue as
    ("text", s) | ("uint", n) | ("bool", b). Absent optionals encode Null."""
    pub = ed_pubkey(seed32)
    issuer = key_ref_ed25519(pub)

    def meta(v):
        kind, val = v
        return {"text": val, "uint": val, "bool": val}[kind]

    claim = Map([("type", claim_type)] + [(k, meta(v)) for k, v in fields])
    content = Map([
        ("claim", claim),
        ("evidence_ref", evidence_ref),
        ("expires_at", expires_at),
        ("issued_at", issued_at),
        ("issuer", issuer),
        ("subject", subject),
        ("v", 1),
    ])
    raw = enc_map(content)
    sign1, _ = cose_sign1(raw, seed32)
    att_id = obj_id("att", raw)
    # self-check: what we just built must verify
    payload, _ = verify_sign1(sign1, issuer)
    assert payload == raw, "creator self-check failed"
    return {"id": att_id, "issuer": issuer, "cbor": raw.hex(),
            "sign1_b64": b64u(sign1)}


def make_evidence(kind, digest32, attestation_ref=None, hint=None):
    content = Map([
        ("attestation_ref", attestation_ref),
        ("digest", Map([("alg", 0), ("digest", digest32), ("v", 1)])),
        ("hint", hint),
        ("kind", kind),
        ("v", 1),
    ])
    raw = enc_map(content)
    return {"id": obj_id("evd", raw), "cbor": raw.hex()}


def make_relationship(from_id, rel_type, to_id, evidence_ref=None,
                      attestation_ref=None):
    content = Map([
        ("attestation_ref", attestation_ref),
        ("evidence_ref", evidence_ref),
        ("from", from_id),
        ("to", to_id),
        ("type", rel_type),
        ("v", 1),
    ])
    raw = enc_map(content)
    return {"id": obj_id("rel", raw), "cbor": raw.hex()}


def make_proof(kind, subject, predicate, obj=None, at_time=None, context=(),
               created_at=0, events=(), attestations=(), evidence=(),
               relationships=(), referenced_proofs=(), vocabularies=()):
    """attestations: list of {"content_cbor_hex", "sign1_b64"} artifacts.
    vocabularies: list of (ns, version) declarations, sorted by ns.
    Returns the proof artifact dict {"id", "cbor"} plus full canonical bytes.
    """
    ev_raw = [bytes.fromhex(e["cbor"]) for e in events]
    evd_raw = [bytes.fromhex(e["cbor"]) for e in evidence]
    rel_raw = [bytes.fromhex(e["cbor"]) for e in relationships]
    att_entries = []
    for a in attestations:
        c = bytes.fromhex(a["cbor"])
        s = b64u_decode(a["sign1_b64"])
        att_entries.append((c, s))
    prop = Map([
        ("at_time", at_time),
        ("context", Map(list(context))),
        ("kind", kind),
        ("object", obj),
        ("predicate", predicate),
        ("subject", subject),
        ("v", 1),
    ])
    prop_raw = enc_map(prop)

    def ids(prefix, raws):
        return sorted(obj_id(prefix, r) for r in raws)

    e_ids = ids("evt", ev_raw)
    a_ids = sorted(obj_id("att", c) for c, _ in att_entries)
    d_ids = ids("evd", evd_raw)
    r_ids = ids("rel", rel_raw)
    binding = Map([
        ("attestations", a_ids),
        ("created_at", created_at),
        ("events", e_ids),
        ("evidence", d_ids),
        ("relationships", r_ids),
        ("proposition", _map(prop_raw)),
        ("v", 1),
    ])
    if referenced_proofs:
        refs = sorted(referenced_proofs)
        assert refs == list(referenced_proofs) and len(set(refs)) == len(refs), \
            "creator refs must be sorted with no duplicates"
        binding.append(("referenced_proofs", refs))
    if vocabularies:
        vocs = sorted(vocabularies)
        assert ([n for n, _ in vocs] == sorted(n for n, _ in vocs)
                and len({n for n, _ in vocs}) == len(vocs)), \
            "creator vocabularies must be sorted by ns with no duplicates"
        binding.append(("vocabularies", [Map([("ns", n), ("version", v)])
                                         for n, v in vocs]))
    proof_id = obj_id("prf", enc_map(binding))

    def raw_map(b):
        v, pos = dec(b)
        assert pos == len(b) and isinstance(v, Map)
        return v

    outer = Map([
        ("attestations", [Map([("content", raw_map(c)), ("sign1", s)])
                          for c, s in att_entries]),
        ("created_at", created_at),
        ("events", [raw_map(r) for r in ev_raw]),
        ("evidence", [raw_map(r) for r in evd_raw]),
        ("proof_id", proof_id),
        ("proposition", raw_map(prop_raw)),
        ("relationships", [raw_map(r) for r in rel_raw]),
        ("v", 1),
    ])
    if referenced_proofs:
        outer.append(("referenced_proofs", sorted(referenced_proofs)))
    if vocabularies:
        outer.append(("vocabularies", [Map([("ns", n), ("version", v)])
                                       for n, v in sorted(vocabularies)]))
    proof_raw = enc_map(outer)
    # self-check through the independent verifier
    got = verify_proof(proof_raw)
    assert got["proof_id"] == proof_id, "creator self-check failed"
    return {"id": proof_id, "cbor": proof_raw.hex()}