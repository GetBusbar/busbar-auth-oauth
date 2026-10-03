<!-- fleet:header:begin (rendered by `busbar-release plugin sync` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-oauth

First-party signed kind:auth plugin cdylib: the oauth auth, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `oauth` | `busbar-auth-oauth-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-oauth/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-oauth/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-oauth` is a `kind: auth` busbar plugin.

## Config

Configured under the `oauth` module name.

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
