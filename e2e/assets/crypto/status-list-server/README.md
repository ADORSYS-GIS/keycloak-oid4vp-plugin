# status-list-server test material

The key is the status-list-server's own development signing key, copied verbatim from the upstream
repository ([status-list-server](https://github.com/adorsys/status-list-server), `develop`, revision
`5ab1855`, `test_data/certs/dev.key`). The upstream README documents it as public test material for
local development only.

| File         | Origin                                                        |
| ------------ | ------------------------------------------------------------- |
| `dev.key`    | upstream `test_data/certs/dev.key`, unmodified                |
| `dev.crt`    | self-signed certificate for `dev.key` (see the command below) |
| `nginx.conf` | written for this stack                                        |

`dev.crt` is not upstream's file: upstream issues its certificate for `DNS:localhost` only, while
this stack reaches the server through the TLS proxy at `https://status-list:8443`, and the
token-status plugin enforces hostname verification. The certificate is therefore self-signed for
both names, using the same key:

```bash
openssl req -x509 -new -key dev.key -subj "/CN=localhost" -days 3650 -sha256 \
  -addext "subjectAltName=DNS:localhost,DNS:status-list" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -out dev.crt
```

It is a `CA:FALSE` leaf; that is fine because the plugins treat the certificate configured as a
trust anchor as a root regardless of the CA flag.

In the e2e stack the material is used twice:

- the status-list-server signs status list JWTs with `dev.key`, and the token's `x5c` chain is just
  this self-signed certificate;
- the nginx TLS proxy presents the same certificate, so Keycloak reaches the server at
  `https://status-list:8443`.

One PEM trust entry for `dev.crt` covers both: it is mounted into Keycloak and merged into the
global truststore with `--truststore-paths` (used by the OpenID4VP plugin's x5c-chain validation),
and the token-status plugin trusts the same file through the realm's `status-list-tls-ca-cert-path`.
No JKS conversion is needed.
