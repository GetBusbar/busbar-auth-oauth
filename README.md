<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-oauth

First-party signed kind:auth plugin cdylib: the oauth auth, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `oauth` | `busbar-auth-oauth-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-oauth/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-oauth/actions/workflows/ci.yml)
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

Scheduled styles refuse a request before the first token is available and refresh ahead of expiry, with a maximum refresh interval of 24 hours. Token exchange mints on demand and backs off after a failed exchange (30 seconds, or the endpoint's `Retry-After` up to 300 seconds); while one scope backs off an outage of the token endpoint, a request for a scope not yet exchanged fails at once instead of reaching the endpoint. Minted bearer fields retain their sensitive flag and secure-connection requirement through the host.

## Token endpoint egress

Both token endpoint needs are in the `provider` egress class. A token endpoint on a private, loopback, link-local or other non-public address is refused by the host connector unless `advanced.allow_destinations` names it (an in-cluster identity provider, for example); once named, it mints, over `http` as well as `https`. A public endpoint needs no entry.

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
