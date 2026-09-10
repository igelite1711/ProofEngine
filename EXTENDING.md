# EXTENDING.md — Adding a domain without touching the core (V1)

The core answers *how* claims are represented, bound, and verified. Your
domain answers *what they mean*. If you find yourself editing `crates/` to
express domain meaning, stop — this page describes the intended path. The
machinery below is exercised by real tests (`PE-NEUT-001..005` in
`docs/requirements-matrix.md`) and by four example domains in `docs/domains/`
(payment, credential, media, AI) plus the differential suite in
`domains/proof-domains/tests/differential.rs`.

## The four extension points

1. **Vocabulary strings (open).** `EventType`, `EvidenceKind`, `RelType` are
   newtype strings transported verbatim through the closed structural schemas
   (PE-FMT-008). Name yours namespaced: `acme.payments.settled`,
   `lab.example.measurement`. Unknown *fields* and *versions* are rejected;
   unknown *vocabulary* is not — judgment over vocabulary belongs to your
   policy, never the core.
2. **Metadata (open key/value).** `MetaValue` (text/uint/bool) on events and
   claims; the CLI exposes `--meta k=v,...` and `--context k=v,...`. Keep
   domain semantics in these values and in your own schema documentation.
3. **Policy (closed set, explicit inputs).** The V1 requirement set
   (`POLICY.md`) is deliberately closed — pure conjunction over proof state.
   Extend by *choosing requirements and supplying inputs*: trusted issuers
   (constrained by evaluation time, TRUST.md), revocation data, clock. New
   requirement *semantics* (OR/quorum/freshness) arrive only via a new
   `policy_version` with a `docs/capability-map.md` row — never a core hack.
4. **Evidence abstraction.** `EvidenceKind` + digest binding + optional
   attestation reference + hint cover arbitrary external material. Attach
   your real-world artifacts by digest; the core needs nothing more.

## Recipe

1. Define your vocabulary and document it (`docs/domains/<domain>.md`).
2. Create events/attestations/evidence/relationships with the existing CLI
   commands or the library builders — zero core changes.
3. Write your policy as data (JSON) over the closed requirement set.
4. Add a differential test in `domains/proof-domains/` proving your domain
   traverses the same pipeline and produces the same verdict shapes as the
   other domains.
5. Run `make neutrality`: your vocabulary must live in tests/fixtures/docs/
   demos, never in mechanism sources (`crates/`).

## What does NOT extend

Closed enums exist only for universal states (validity, lifecycle, decisions,
error codes). Domain taxonomies never become engine enums. If a domain needs a
state the engine lacks, that is a versioned specification change with a
capability-map row — not an enum addition on a Friday.
