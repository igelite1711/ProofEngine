# Proof Engine Core — Plain-English Guide

> What the core is, what it holds, what it can do, and what it will not do.
> No jargon without an explanation. If a sentence here disagrees with the
> protocol spec, the spec wins — this is the friendly version, not the law.

---

## 1. The core in one paragraph

The Proof Engine core is a small, offline, dependency-light library that
lets any software make **portable, tamper-evident, independently checkable
claims about the world**. You put in a claim ("payment P settled invoice
I"), attach supporting material, sign it, and get back a sealed package
called a **proof**. Anyone else — using our code, their own code, or a
second implementation written from the spec alone — can check that package
and get the same answer, without trusting you, your servers, or your
database.

---

## 2. The problem it solves

Computers constantly assert things: a payment settled, a part was
installed, a document was signed, a sensor recorded a value, a license was
granted. Those assertions usually live inside somebody's database, so a
stranger asking *"why should I believe this?"* gets no machine-checkable
answer. The core fixes exactly that: every important assertion travels
with its own evidence, signatures, history, and relationships, sealed so
any change is detectable, in a format that outlives any single vendor.

---

## 3. What the core contains (six small crates)

| Crate | Plain meaning | Size |
|---|---|---|
| `proof-core` | The shared dictionary: the five building blocks, the list of error codes, and the safety limits. | ~1k lines |
| `proof-format` | The handwriting rules: one exact way to write every object as bytes, so the same object always produces the same bytes everywhere. | ~2.6k lines |
| `proof-crypto` | The wax seals: hashing, signing, signature checking, and identity labels for keys. No invented cryptography — standard algorithms only. | ~3.2k lines |
| `proof-graph` | The family-tree checker: makes sure relationship arrows between objects form a sane graph with no impossible loops. | ~0.7k lines |
| `proof-verify` | The inspector: runs every check in order and writes a full report card. | ~2.9k lines |
| `proof-policy` | The judge's rulebook reader: takes *your* rules and decides PASS or FAIL against a checked proof. | ~2.9k lines |

Total: about thirteen thousand lines, each crate with one job.

---

## 4. The five building blocks

1. **Event** — "Something happened." A payment was created, a part was
   installed, a reading was taken. Unsigned by itself; it is the raw
   record, with a timestamp and a fingerprint (hash) of the data behind it.
2. **Attestation** — "Somebody signed a statement about it." An issuer
   (identified only by their key, never by an account in our system) signs
   a typed claim such as `payment.settled {amount: 4200}`. The signature
   proves *who signed* and *that the words didn't change* — it does not
   prove the words are true or the signer is trustworthy.
3. **Evidence** — "Here is the supporting material." A fingerprint of a
   document, log, photo, or record, optionally pointing at the attestation
   that vouches for it. The core stores fingerprints, never bulky files,
   and never fetches anything over the network.
4. **Relationship** — "These things connect like this." A labeled arrow
   between two objects: A *settles* B, B *derives from* A, C *supersedes*
   D. Labels are open — your industry invents its own vocabulary; the core
   carries the arrows without pretending to understand your business.
5. **Proof** — "The sealed package." A proposition (what this proof is
   *about*: subject, predicate, object) plus exact lists of the events,
   attestations, evidence, and relationships above, all bound together by
   one fingerprint. Change one byte anywhere and the seal breaks.

Two helper notions ride along: a **claim** (the typed statement inside an
attestation) and a **proposition** (the "about" line on the package).

---

## 5. What the core can do

- **Build proofs.** Assemble the five blocks into a sealed package with a
  single fingerprint. Rebuilding the same inputs always yields the same
  bytes — byte-for-byte reproducible.
- **Check proofs in fixed stages.** Parsing, shape, handwriting
  (canonical form), fingerprints, signatures, key shapes, timeliness,
  lifecycle, evidence linkage, graph sanity, feed health, then policy
  handoff, then the final report. Same inputs always give the same report.
- **Tell history apart from "safe right now."** A proof can be *historically
  valid* (it checked out at the time) without being *acceptable now* (it
  has since expired, been revoked, superseded, or its issuer compromised).
  Both answers are reported separately, never blurred.
- **Track a full lifecycle.** Expiry dates, revocations, supersessions
  (replaced by a newer statement), withdrawals of reliance, and compromise
  markings — all as signed objects, all verified before they count. Forged
  or future-dated lifecycle notes are flagged as feed problems without
  flipping the proof's own verdict.
- **Represent disagreement honestly.** If two signers assert opposite
  values for the same thing, the core records the conflict and stays
  neutral — it never picks a winner. Your rules decide.
- **Represent chains of trust without becoming an identity company.**
  Organizations delegate to people, people to systems, systems to devices —
  as signed delegation notes over bare key labels. The core never owns
  identities, runs no registry, and phones nobody.
- **Represent provenance chains.** A derives from B derives from C, with
  impossible loops rejected automatically and dangling arrows (pointing at
  nothing) rejected at check time.
- **Combine proofs.** Merge several proofs into one bigger verifiable
  package, with the sources recorded tamper-evidently inside.
- **Judge against your rules.** You supply a small rule set (signatures
  valid, issuer trusted, not expired, not revoked, required relationship
  present, required evidence present — plus richer version-2 rules with
  and/or/not logic, delegation chains, thresholds, and field comparisons).
  The same proof can PASS under one party's rules and FAIL under another's
  without changing a byte.
- **Explain itself.** Every verdict ships a per-stage report card with
  stable machine-readable codes plus human sentences — no silent trust.
- **Fail closed.** Anything missing, stale, malformed, oversized, unknown,
  or unverifiable comes back INVALID/UNKNOWN, never a quiet PASS. In
  particular: no revocation feed, no trust — an empty feed fails closed
  unless you explicitly assert the absence (for brand-new proofs where no
  revocations can exist yet).
- **Hide secrets while proving facts.** A claim can carry a salted hash of
  a sensitive value instead of the value; your rules check the hash. The
  value itself never goes on the wire. (Equality checks only — fancy
  zero-knowledge math belongs in extensions, not this core.)
- **Stay offline and portable.** Zero network calls anywhere in checking.
  Proofs are bytes; they travel by file, message, or QR code and check the
  same everywhere, years later.

---

## 6. What the core guarantees

- **Same bytes in, same answer out** — deterministic, reproducible, with
  34 golden reference vectors and three independent implementations (Rust,
  Python with only the standard library, TypeScript) agreeing both
  directions.
- **Any tampering is caught** — flipped bytes, swapped identities,
  truncated packages, substituted contents, expired or revoked material
  all fail with named reasons (2,000-flip soak test green).
- **No guesswork** — 24 stable error codes, append-only; unknown versions,
  unknown algorithms, and deprecated algorithms are rejected, never
  silently accepted.
- **No resource ambushes** — hard caps on size, depth, and counts at every
  boundary; fuzz-tested parsers; no panics in production paths.
- **No vendor lock-in** — open label vocabularies, versioned formats, an
  algorithm registry (Ed25519 standard today, P-256 opt-in, path reserved
  for future algorithms), and a written longevity plan.

---

## 7. What the core will NOT do (on purpose)

- No blockchain, tokens, money, or payments.
- No identity accounts, logins, registries, or trust scores.
- No central servers, phone-home calls, or mandatory network.
- No databases, storage, or fetching of evidence content.
- No key custody (key management is the operator's job; demo keys are
  clearly marked never-for-production).
- No encryption or fancy privacy math in the core.
- No deciding what is *true* — it checks packages against rules; truth
  about the world remains the signers' and the judges' business.

---

## 8. A proof's life, in plain steps

1. **Record** events (what happened, when, fingerprint of the data).
2. **Sign** attestations over claims (who says what, valid from/until).
3. **Attach** evidence fingerprints to back the claims.
4. **Draw** relationship arrows between the objects.
5. **Seal** everything into a proof (one fingerprint covers the lot).
6. **Check** it anywhere: feed the bytes plus the checker's context (what
   time is it, which issuers do you trust, how fresh is your revocation
   feed) into the inspector; read the report card.
7. **Judge** it: run your rule set over the checked proof; PASS, FAIL, or
   "cannot tell" — your decision, your responsibility.
8. **Maintain** it: publish signed revocations, replacements, or
   compromise notices as facts change; old proofs keep their history while
   new checks reflect the present.

---

## 9. The one rule that keeps everyone safe

> A cryptographically valid package is not automatically a trusted one.
> A trusted one is not automatically acceptable under your rules. A valid
> historical record is not automatically safe to rely on right now.

The core keeps these four ideas — *valid, supported, trusted, acceptable
now* — in separate boxes with separate labels, and refuses to collapse
them. That separation is the whole point of the design.

---

## 10. Scorecard (where this stands)

- Input safety, format strictness, tamper resistance: best in class for
  its size.
- Lifecycle honesty (history vs now, conflicts without winners,
  feed-problem vs revoked distinction): genuinely careful.
- Independence: three implementations, reproducible bytes, offline by
  construction.
- Remaining work lives *outside* this core by design: running a revocation
  feed, storing evidence bytes, guarding keys, and writing your industry's
  vocabulary and rules.

*Proof Engine core — make digital claims independently verifiable.*
