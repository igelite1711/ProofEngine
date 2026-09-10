# Domain: Media Provenance (J-C')

> Licensing + deepfake-response + transcode chaining as one engine, no core change.
> Journey: `domains/proof-domains/tests/media.rs`.

## Vocabulary mapping
| Media noun | Core mapping |
|------------|--------------|
| master asset | `Event` (`document.signed`) |
| transcode outputs | `Event`s + `PRODUCED` relationships (master -> h264 -> hls) |
| license grant | `Attestation` (`license.granted`) + `ISSUED` edge |
| media manifest | `Evidence` (`signed_document`) |
| deepfake takedown | signed `revoke` status -> lifecycle `REVOKED` |

## Journey

1. License: rights-holder attests `license.granted` over the master asset.
2. Transcode chain: three events linked by `PRODUCED` edges (provenance).
3. Verify bundle under `license_required` policy (PASS).
4. Deepfake response: rights-holder signs a `revoke` over the PSA attestation;
   re-verification fails closed with `REVOKED` (media takedown = engine revocation).

No media semantics in the engine: `license.granted` and `PRODUCED` are just
strings and a generic edge (docs/domains/README.md tables).
