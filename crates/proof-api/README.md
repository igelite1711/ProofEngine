# proof-api — thin reference HTTP API (P9)

Stateless loopback interface over the core. Never a trust root: every
decision comes from caller-supplied policy + verification context.

Endpoints: `GET /v1/health|version|metrics`, `POST /v1/verify|evaluate|explain|ingest`.

```bash
cargo run -p proof-api          # serve on 127.0.0.1:8910
cargo test -p proof-api         # 8 integration tests over the serve path
```

Boundaries: std-only HTTP (no framework), zero network inside
`verify_proof`, allow_remote always false. Production auth/TLS/fronting
is the deployer's job.
