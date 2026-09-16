# Domain: Credential Lifecycle (identity instantiation)

> Exercises the lifecycle machinery (expiry, supersession) and the deny-list
> requirement in an identity domain. Journey:
> `domains/proof-domains/tests/credential.rs`.

## Vocabulary mapping
| Credential noun | Core mapping |
|-----------------|--------------|
| issuance | `Event` (`document.signed`) + `Attestation` (`credential.active`) |
| the credential blob | `Evidence` (`credential`) |
| authority grants | `Relationship` (`ISSUED`) |
| validity window | `issued_at` / `expires_at` |
| replacement | second attestation + `SUPERSEDES` |
| blocked authority | `issuer_excluded` policy requirement |

## Journey (J-A')

1. Authority attests a credential over the holder's identity event.
2. Verify at time T (PASS).
3. Pass the expiry bound: same proof verifies `EXPIRED` -> policy FAIL (not_expired).
4. Reissue + supersede: old credential stays historically valid; a policy requiring
   `not_superseded` fails; golden-19 parallel.
5. Deny-list (J-B): a proof whose chain touches a listed issuer fails closed even
   when every signature is valid and the trust list contains the issuer.

Identity domain is *not* the engine's identity: the engine stores keyrefs and
references supplied by the caller (CAP-033).
