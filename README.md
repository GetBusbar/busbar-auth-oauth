<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-oauth

First-party signed kind:auth plugin cdylib: the oauth auth, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `oauth` | `busbar-auth-oauth-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

<!-- fleet:header:end -->

## What it is for

`busbar-auth-oauth` provides three outbound OAuth styles through the `oauth` auth module. It mints from the operator's credential and presents the resulting bearer; it does not forward a caller's credential.

## Config

| Style | Credential | Settings |
|---|---|---|
| `jwt-bearer` | Service-account JSON containing `client_email` and a PKCS#8 RSA `private_key` | `token_uri?`, `scope?`, `subject?`, `max_response_bytes?` |
| `oauth-client-credentials` | `client_id:client_secret` | `token_url`, `scope?`, `max_response_bytes?` |
| `oauth-token-exchange` | Busbar's subject token | `token_url`, `resource`, `subject_token_type?`, `max_response_bytes?` |

`jwt-bearer` uses the Google service-account profile of RFC 7523: RS256 with `iss`, `aud`, `iat`, `exp` and a `scope` claim. The default scope is `https://www.googleapis.com/auth/cloud-platform`. It includes `sub` only when `subject` is configured. The host resolves key files through `api_key: {file: <path>}`; the plugin receives JSON and opens no file. A host-judged `token_uri` selects the dial target; the credential's own `token_uri` remains the assertion audience.

Client credentials use RFC 6749 section 4.4. An omitted scope leaves the request unscoped. Token exchange uses RFC 8693, binds the result to `resource`, and caches each request's scope separately. `subject_token_type` defaults to `urn:ietf:params:oauth:token-type:access_token`.

`max_response_bytes` defaults to 256 KiB and accepts 1024 through 1048576 bytes. Blank or mistyped settings are refused by name. Unknown keys are refused; forwarded provider keys (`token_url`, `token_uri`, `scope`, `subject`) that a style does not read are ignored with a warning when that style opens.

Scheduled styles refuse a request before the first token is available and refresh ahead of expiry, with a maximum refresh interval of 24 hours and a minimum of 5 seconds between mints. A token is never presented at or past its expiry: a request that finds it expired waits for the refresh, which is brought forward (after a host suspend, for example), or fails at once when the refresh has failed and is backing off. Token exchange mints on demand and backs off after a failed exchange (30 seconds, or the endpoint's `Retry-After` up to 300 seconds); while one scope backs off an outage of the token endpoint, a request for a scope not yet exchanged fails at once instead of reaching the endpoint. Minted bearer fields retain their sensitive flag and secure-connection requirement through the host.

## Token endpoint egress

Both token endpoint needs are in the `provider` egress class. A token endpoint on a private, loopback, link-local or other non-public address is refused by the host connector unless `advanced.allow_destinations` names it (an in-cluster identity provider, for example); once named, it mints, over `http` as well as `https`. A public endpoint needs no entry.

## Differences from 1.5.5

- A scheduled style (`jwt-bearer`, `oauth-client-credentials`) never presents a token at or past its expiry (RFC 6750 §3.1). 1.5.5 presented the cached bearer whatever its expiry until a refresh landed, so after a host suspend, or while refreshes failed past expiry, it sent an expired token and the upstream answered 401. Now a request that finds the token expired waits while the refresh is brought forward (no sooner than 5 seconds after the last mint), and fails closed at once, naming the expired token, when that refresh has failed; the 30-second retry after a failed mint is unchanged.
- A scheduled style re-mints no more often than once every 5 seconds. 1.5.5 re-minted a token of `expires_in` 1 or 2 about once a second (half its life, at least 1 second), so a provider issuing very short tokens drove a tight mint loop. Such a provider still mints and its token is presented while it lives; a request after it expires waits for the next mint. A token living 10 seconds or more keeps 1.5.5's schedule exactly.

## Build

```bash
cargo build --release -p busbar-auth-oauth-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
