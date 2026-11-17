# status-list-server test material

`dev.key` is the status-list-server's own development signing key, copied verbatim from upstream
([status-list-server](https://github.com/adorsys/status-list-server), `develop` revision `5ab1855`,
`test_data/certs/dev.key`); upstream documents it as public test material for local development
only.

| File         | Origin                                                                            |
| ------------ | --------------------------------------------------------------------------------- |
| `dev.key`    | upstream `test_data/certs/dev.key`, unmodified                                    |
| `dev.crt`    | self-signed certificate for `dev.key`, SAN `status-list-server-tls` + `localhost` |
| `nginx.conf` | written for this stack                                                            |

`dev.crt` is not upstream's (theirs covers `DNS:localhost` only, but the token-status plugin
enforces hostname verification and this stack addresses the server as `status-list-server-tls`). It
is a `CA:FALSE` leaf, which is fine: the plugins treat a configured trust anchor as a root either
way.

In the e2e stack the material is used twice:

- the status-list-server signs status list JWTs with `dev.key`, and the token's `x5c` chain is just
  this self-signed certificate;
- the nginx TLS proxy presents the same certificate, so Keycloak reaches the server with HTTPS at
  `https://status-list-server-tls`.

Plugins need to trust `dev.crt`, but through two independent mechanisms: it is mounted into Keycloak
and merged into the global truststore with `--truststore-paths` (used by the OpenID4VP plugin's
x5c-chain validation), and the token-status plugin trusts the same file through the realm's
`status-list-tls-ca-cert-path`.
