# Confidentiality — what Proof Engine does and does not do

> Scope: V1.1. The core is a plaintext, digest-bound claim/evidence engine.
> There is no encryption, redaction, or zero-knowledge mechanism in the core
> (see `ARCHITECTURE-FREEZE.md` §3: privacy arrives via adapters).

## 1. The rule

- Canonical bytes are **plaintext**: event subjects, claim fields, metadata,
  hints, and relationship endpoints travel verbatim and are hashed into ids.
  Do NOT place PII, secrets, or regulated data in these fields unless the
  proof's distribution already permits it.
- Evidence binds a **digest**, not content. External bytes never enter the
  core (`no fetch in V1`); availability is the operator's content-store job.

## 2. Application-layer patterns (recommended)

- **Digest-only sensitive evidence:** store sensitive bytes off-proof (access-
  controlled store), place only `SHA-256` + `kind` + `attestation_ref` in the
  proof. Verifiers check digest presence/binding; readers need store access
  for content. `evidence_present` vs `evidence_usable` (v2) express the two
  levels.
- **Coarse claims:** attest `cohort:eligible=true` instead of
  `diagnosis:<code>`; keep fine-grained facts in the gated store behind the
  same digest.
- **Member subsets + linkage:** ship minimal proofs; link related proofs via
  `referenced_proofs` (tamper-evident, content-withheld) and resolve bundles
  only among authorized parties.
- **Key hygiene:** `--seed` is demo-only (visible in `ps`/history); use
  `--seed-file` and HSM/KMS-backed signers in production. Keyrefs are
  public identifiers — rotation via `delegate` chains + `revocation_authorities`.

## 3. Non-goals (will not be added to the core)

Per-request selective disclosure, field-level redaction proofs, and ZK
predicates belong in adapters/profiles above the frozen core, never as
mechanism branches. Proposals MUST follow `ARCHITECTURE-FREEZE.md` §5
(reopen procedure) and prove extension insufficiency first.
