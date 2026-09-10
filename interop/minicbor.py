# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Minimal strict CBOR codec for the ProofEngine V0.1 subset (independent code).

Scope: uint/nint/text/bytes/array/map/bool/null. Rejects floats, tags,
indefinite lengths, bignums, simple values, non-shortest ints, duplicate
map keys, unordered maps, trailing bytes, bad UTF-8. Depth capped at 16 to
match the engine default (proof-core Limits::default max_depth).
Stdlib only.
"""

# PE-INTEROP-002: strict subset shared by verifier and creator.
MAX_DEPTH = 16


class CErr(Exception):
    """Any strictness violation (maps to engine PARSE failures)."""


class Map(list):
    """A CBOR map: list of (key, value) preserving map-ness."""


def dec(buf, pos=0, depth=0):
    if depth > MAX_DEPTH:
        raise CErr("depth")
    if pos >= len(buf):
        raise CErr("truncated")
    ib = buf[pos]
    pos += 1
    maj, ai = ib >> 5, ib & 0x1F

    def arg():
        nonlocal pos
        if ai <= 23:
            return ai
        n = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
        if pos + n > len(buf):
            raise CErr("truncated")
        v = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
        return v

    if maj in (0, 1):
        v = arg()
        lo = 0 if ai <= 23 else {24: 24, 25: 256, 26: 65536, 27: 2**32}[ai]
        if v < lo:
            raise CErr("non-shortest int")
        return (-1 - v if maj == 1 else v), pos
    if maj in (2, 3):
        ln = arg()
        if pos + ln > len(buf):
            raise CErr("truncated")
        b = bytes(buf[pos:pos + ln])
        pos += ln
        if maj == 3:
            try:
                return b.decode("utf-8"), pos
            except UnicodeDecodeError:
                raise CErr("bad utf-8")
        return b, pos
    if maj == 4:
        ln = arg()
        out = []
        for _ in range(ln):
            v, pos = dec(buf, pos, depth + 1)
            out.append(v)
        return out, pos
    if maj == 5:
        # NOTE: enc is defined below; resolved from module globals at call time.
        ln = arg()
        items = Map()
        prev = None
        for _ in range(ln):
            k, pos = dec(buf, pos, depth + 1)
            v, pos = dec(buf, pos, depth + 1)
            kb = enc(k)
            if prev is not None:
                if kb == prev:
                    raise CErr("dup key")
                if kb < prev:
                    raise CErr("misordered key")
            prev = kb
            items.append((k, v))
        return items, pos
    if maj == 7 and ai in (20, 21, 22):
        return ({20: False, 21: True, 22: None})[ai], pos
    raise CErr(f"forbidden major={maj} ai={ai}")


def _head(maj, ln):
    for ai, lo in ((None, 24), (24, 256), (25, 65536), (26, 2**32), (27, None)):
        if lo is None or ln < lo:
            if ai is None:
                return bytes([(maj << 5) | ln])
            return bytes([(maj << 5) | ai]) + ln.to_bytes(
                {24: 1, 25: 2, 26: 4, 27: 8}[ai], "big")
    raise CErr("too long")


def enc(v):
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        if v >= 0:
            n, maj = v, 0
        else:
            if v < -(2**63):
                raise CErr("nint out of V0.1 range")
            n, maj = -1 - v, 1
        return _head(maj, n)
    if isinstance(v, bytes):
        h = 0x40
    else:
        v = v.encode()
        h = 0x60
    ln = len(v)
    for ai, lo in ((None, 24), (24, 256), (25, 65536), (26, 2**32), (27, None)):
        if lo is None or ln < lo:
            pre = (bytes([h | ln]) if ai is None
                   else bytes([h | ai]) + ln.to_bytes(
                       {24: 1, 25: 2, 26: 4, 27: 8}[ai], "big"))
            return pre + v
    raise CErr("too long")


def enc_map(pairs):
    ek = sorted(((enc(k), k, v) for k, v in pairs))
    for i in range(1, len(ek)):
        if ek[i][0] == ek[i - 1][0]:
            raise CErr("dup key")
        if ek[i][0] < ek[i - 1][0]:
            raise CErr("order")
    out = _head(5, len(pairs))
    for kb, _, v in ek:
        out += kb + enc_any(v)
    return out


def enc_any(v):
    if isinstance(v, Map):
        return enc_map(v)
    if isinstance(v, list):
        out = _head(4, len(v))
        for x in v:
            out += enc_any(x)
        return out
    return enc(v)


def decode_strict(raw):
    """Decode exactly one item; reject trailing bytes. Returns the value."""
    v, pos = dec(raw)
    if pos != len(raw):
        raise CErr("trailing bytes")
    return v


def canonical_reencode(raw):
    """Decode then re-encode; the round trip must be byte-identical."""
    return enc_any(decode_strict(raw))