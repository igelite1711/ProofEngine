# proof-api — thin reference HTTP API (P9)

Stateless loopback interface over the core. Never a trust root: every
decision comes from caller-supplied policy + verification context.

Endpoints: `GET /v1/health|version|metrics`, `POST /v1/verify|evaluate|explain|ingest`.

```bash
cargo run -p proof-api          # serve on 127.0.0.1:8910
cargo test -p proof-api         # 10 integration tests over the serve path
```

Boundaries: std-only HTTP (no framework), zero network inside
`verify_proof`, allow_remote always false. Production auth/TLS/fronting
is the deployer's job.

Verifier-policy scope: the HTTP context carries the full `VerifyCtx`
surface — `clock`/`skew`/`trusted`/`status`/`authority`/
`revocations_known_at` plus `esp256`, `historical`/`allow_deprecated`,
`report_all`, `accepted_vocab` (`["ns:max"]`), `extra_grounded`,
`require_acyclic`, `require_status`/`no_require_status`, and `production`
(strict profile: implies full-DAG + feed gate + currency overlay) with
`strict_current` for currency-only overlay. Wire strings match the CLI
(lowercase validities/policy, UPPER lifecycle/status) plus
`currently_acceptable` (verify) and `currently_acceptable`/`currency_fail`
(evaluate/explain); verdicts ride 200 (FAIL is data, not an error).
