// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Strict CBOR codec for the ProofEngine V1 subset (third implementation).
// Scope: uint/nint/text/bytes/array/map/bool/null. Rejects floats, tags,
// indefinite lengths, bignums, simple values, non-shortest ints, duplicate
// map keys, unordered maps, trailing bytes, bad UTF-8. Depth capped at 16
// (engine default proof-core Limits::default max_depth).

export const MAX_DEPTH = 16;

export class CErr extends Error {}
export class Map_ {
  constructor(public pairs: [unknown, unknown][]) {}
}

type Val = number | Uint8Array | string | boolean | null | Val[] | Map_;

function u8(...xs: number[]): Uint8Array {
  return Uint8Array.from(xs);
}
function cat(...xs: Uint8Array[]): Uint8Array {
  const n = xs.reduce((s, x) => s + x.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const x of xs) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}
export function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

// deterministic decode: returns [value, nextPos]
export function dec(buf: Uint8Array, pos = 0, depth = 0): [Val, number] {
  if (depth > MAX_DEPTH) throw new CErr("depth");
  if (pos >= buf.length) throw new CErr("truncated");
  const ib = buf[pos];
  pos += 1;
  const maj = ib >> 5;
  const ai = ib & 0x1f;

  const arg = (): number => {
    if (ai <= 23) return ai;
    const n = ({ 24: 1, 25: 2, 26: 4, 27: 8 } as Record<number, number>)[ai];
    if (n === undefined) throw new CErr("forbidden major");
    if (pos + n > buf.length) throw new CErr("truncated");
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + buf[pos + i];
    pos += n;
    return v;
  };

  if (maj === 0 || maj === 1) {
    const v = arg();
    const lo: number =
      ai <= 23 ? 0 : ({ 24: 24, 25: 256, 26: 65536, 27: 2 ** 32 } as Record<number, number>)[ai];
    if (lo === undefined) throw new CErr("forbidden major");
    if (v < lo) throw new CErr("non-shortest int");
    return [maj === 1 ? -1 - v : v, pos];
  }
  if (maj === 2 || maj === 3) {
    const ln = arg();
    if (pos + ln > buf.length) throw new CErr("truncated");
    const b = buf.slice(pos, pos + ln);
    pos += ln;
    if (maj === 3) {
      try {
        return [new TextDecoder("utf-8", { fatal: true }).decode(b), pos];
      } catch {
        throw new CErr("bad utf-8");
      }
    }
    return [b, pos];
  }
  if (maj === 4) {
    const ln = arg();
    const out: Val[] = [];
    for (let i = 0; i < ln; i++) {
      const [v, np] = dec(buf, pos, depth + 1);
      pos = np;
      out.push(v);
    }
    return [out, pos];
  }
  if (maj === 5) {
    const ln = arg();
    const items: [unknown, unknown][] = [];
    let prev: string | null = null;
    for (let i = 0; i < ln; i++) {
      const k0 = pos;
      const [k, p1] = dec(buf, pos, depth + 1);
      const [v, p2] = dec(buf, p1, depth + 1);
      pos = p2;
      const kb = toHex(buf.slice(k0, p1));
      if (prev !== null) {
        if (kb === prev) throw new CErr("dup key");
        if (kb < prev) throw new CErr("misordered key");
      }
      prev = kb;
      items.push([k, v]);
    }
    return [new Map_(items), pos];
  }
  if (maj === 7 && ai === 20) return [false, pos];
  if (maj === 7 && ai === 21) return [true, pos];
  if (maj === 7 && ai === 22) return [null, pos];
  throw new CErr(`forbidden major=${maj} ai=${ai}`);
}
export function decodeStrict(raw: Uint8Array): unknown {
  const [v, pos] = dec(raw, 0, 0);
  if (pos !== raw.length) throw new CErr("trailing bytes");
  return v;
}

function head(maj: number, ln: number): Uint8Array {
  for (const [ai, lo] of [
    [null, 24],
    [24, 256],
    [25, 65536],
    [26, 2 ** 32],
    [27, null],
  ] as [number | null, number][]) {
    if (lo === null || ln < lo) {
      if (ai === null) return u8((maj << 5) | ln);
      const n = ({ 24: 1, 25: 2, 26: 4, 27: 8 } as Record<number, number>)[ai];
      if (n === undefined) throw new CErr("forbidden major");
      const bytes: number[] = [];
      let v = ln;
      for (let i = 0; i < n; i++) {
        bytes.unshift(v % 256);
        v = Math.floor(v / 256);
      }
      return cat(u8((maj << 5) | ai), Uint8Array.from(bytes));
    }
  }
  throw new CErr("too long");
}

export function enc(v: unknown): Uint8Array {
  if (v === true) return u8(0xf5);
  if (v === false) return u8(0xf4);
  if (v === null) return u8(0xf6);
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new CErr("float forbidden");
    const maj = v >= 0 ? 0 : 1;
    const n = v >= 0 ? v : -1 - v;
    return head(maj, n);
  }
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (typeof v === "string") {
    const b = Buffer.from(v, "utf8");
    return cat(head(3, b.length), b);
  }
  throw new CErr("enc: unexpected value");
}

export function encAny(v: unknown): Uint8Array {
  if (v instanceof Map_) return encMap(v.pairs);
  if (Array.isArray(v)) {
    const parts: Uint8Array[] = [head(4, v.length)];
    for (const x of v) parts.push(encAny(x));
    return cat(...parts);
  }
  return enc(v);
}

export function encMap(pairs: [unknown, unknown][]): Uint8Array {
  const ek = pairs.map(([k, v]) => [toHex(enc(k)), k, v] as const);
  ek.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (let i = 1; i < ek.length; i++) {
    if (ek[i][0] === ek[i - 1][0]) throw new CErr("dup key");
  }
  const parts: Uint8Array[] = [head(5, pairs.length)];
  for (const [kb, k, v] of ek) parts.push(cat(enc(k), encAny(v)));
  return cat(...parts);
}

// CBOR map keys: integers (COSE) or text (artifacts). Helpers handle both.
export function mapGet(m: Map_, key: string | number): unknown {
  for (const [k, v] of m.pairs) if (k === key) return v;
  throw new CErr(`missing field ${key}`);
}
export function mapOpt(m: Map_, key: string): unknown {
  for (const [k, v] of m.pairs) if (k === key) return v;
  return undefined;
}
export function mapEntries(m: Map_): [unknown, unknown][] {
  return m.pairs;
}
export function canonicalReencode(raw: Uint8Array): Uint8Array {
  return encAny(decodeStrict(raw));
}
export { cat as concat, u8 as bytes };

