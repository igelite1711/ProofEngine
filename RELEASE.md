# Proof Engine — Release Checklist (V1)

First signed cut: `v1.0.0` (single-commit history; record in
`dist/RELEASE-NOTES.txt`; signed `dist/` + `docs/allowed_signers`).
Later cuts re-run `make release-meta` and re-sign on their tagged commit.
When V1 is ready, this file gates the cut.

## Gate

- [ ] `cargo test --locked` green on a clean checkout.
- [ ] `cargo fmt --check` and `cargo clippy --locked --workspace --all-targets` (zero warnings) green.
- [ ] `make demo` reproduces `demo/out/` byte-for-byte.
- [ ] `make trace`, `make neutrality`, `make web-check`, `make cddl-validate` green.
- [ ] `make domain-tests` green.
- [ ] `make interop` (Python + TypeScript differentials) and `make conformance`
  (full-verdict golden replay, 22+ checks) green — no release ships without
  independent-verifier and verdict-agreement evidence.
- [ ] `make freeze-guard` green (covers tracked AND untracked frozen-path
  files); every CORE-class change since the pin names its
  `docs/ARCHITECTURE-CHANGE-PROPOSAL-*.md` decision in
  `docs/freeze-manifest.json`.
- [ ] Record the release commit, `Cargo.lock` hash, and test counts in the
  release notes; tag the commit.

## Supply-chain artifacts (PE-OPS-006)

Every release ships three machine-readable files beside the binaries,
produced by `make release-meta OUT=dist/`:

1. `sbom.cdx.json` — CycloneDX 1.5 bill of materials projected from
   `Cargo.lock` (`tools/gen_sbom.py`; stdlib only, offline, deterministic:
   same lockfile ⇒ byte-identical SBOM). Answers "exactly which third-party
   code is inside this release".
2. `provenance.json` — build provenance (`tools/gen_provenance.py`):
   commit, tag, `Cargo.lock` sha256, SBOM sha256, rustc/cargo versions,
   target triple, and sha256 of every released artifact.
3. `sha256sums.txt` — plain hashes of every file in `dist/` for one-glance
   verification.

## Signing (no new tooling)

Releases are signed with OpenSSH signatures (maintainers already hold SSH
keys; nothing to install beyond `ssh-keygen`, `ssh-keygen -Y verify`):

```console
# Release manager signs each artifact (allowed signers published in-repo).
ssh-keygen -Y sign -f ~/.ssh/release_key -n proof-engine-release dist/proof-cli
ssh-keygen -Y sign -f ~/.ssh/release_key -n proof-engine-release dist/sbom.cdx.json
# Downloader verifies (allowed_signers lists the release principals).
ssh-keygen -Y verify -f allowed_signers -I release@proof-engine \
  -n proof-engine-release -s dist/proof-cli.sig < dist/proof-cli
```

The `allowed_signers` principal list lives in `docs/allowed_signers` from
the first signed release onward. Key rotation = a PR updating that file
plus a CHANGELOG entry; old signatures stay verifiable against history.
GPG works too, but SSH signatures are the documented default (simpler
key story, same properties for file signing).
