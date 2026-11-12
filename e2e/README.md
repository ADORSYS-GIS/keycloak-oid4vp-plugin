# End-to-End Test Suite

This suite plays the entire user journey of the
[credential revocation demo](https://github.com/ADORSYS-GIS/token-status-link/blob/main/docs/credential-revocation-demo/setup.md)
against real spun-up components.

## The main journey (tests/journey.spec.ts)

1. Alice logs in to the mock app with username + password.
2. She obtains an Identity VC into her wallet.
3. She logs out.
4. She logs back in **by presenting the VC** — the headless wallet plays the whole OpenID4VP
   protocol; the browser auto-completes its Keycloak flow.
5. She revokes the credential from the app.
6. She logs out again.
7. The revoked VC no longer logs her in — she stays in front of Keycloak.

## The components

| Component               | Where it comes from                                                       |
| ----------------------- | ------------------------------------------------------------------------- |
| Keycloak                | `quay.io/keycloak/keycloak:26.8.2` with both plugins mounted as JARs      |
| Plugin: OpenID4VP login | latest release of this very repo                                          |
| Plugin: token status    | latest release of `ADORSYS-GIS/token-status-link`                         |
| Mock FE                 | latest `ghcr.io/adorsys-gis/keycloak-oid4vc-mock-fe`                      |
| Test wallet             | latest `ghcr.io/eudi-dev/eudi-dev` (headless, auto-accepting)             |
| Status server           | `ghcr.io/adorsys/status-list-server:latest-fscert`, local, no DB          |
| TLS proxy for it        | stock `nginx:1.27-alpine` (`assets/crypto/status-list-server/nginx.conf`) |

The status list server runs as part of the stack, so the journey never talks to a remote status-list
service. It uses in-memory storage (`APP_DATABASE__BACKEND=memory`), so the stack needs no database,
even though the published image is built with the Postgres driver. Its image serves plain HTTP only
while the plugins require an HTTPS base URL, so a small nginx container terminates TLS in front of
it (`https://status-list:8443` inside the compose network).

The signing key is the status list server's own development fixture (`dev.key` from
`test_data/certs/` in its repository), and the certificate is a self-signed certificate for that key
covering `status-list` — see `assets/crypto/status-list-server/README.md` for the one `openssl`
command that produces it. A single PEM trust entry for that certificate is enough: Keycloak merges
it into its global truststore with `--truststore-paths` (which the OpenID4VP plugin's x5c-chain
validation uses), and the token-status plugin trusts the same file through
`status-list-tls-ca-cert-path`. No JKS conversion is needed. These are public test fixtures; never
reuse them outside this folder.

## Running

The `pnpm` scripts in `package.json` are the front face (thin wrappers; the logic lives in
`scripts/*.sh`). Before the first run, install the dependencies and the Playwright browser:

```bash
pnpm install
pnpm exec playwright install chromium
```

Then run journeys:

```bash
pnpm play                           # bring the stack up, run the journey, tear it down
pnpm play --keep-stack-alive        # keep the stack up afterwards (logs under build/)
pnpm clean:play                     # wipe generated artifacts first, then run
pnpm clean:play --keep-stack-alive  # wipe generated artifacts first, keep the stack up afterwards
pnpm clean                          # only wipe generated artifacts
pnpm stop                           # tear a kept-alive stack down
```

Re-runs are cheap: `setup.sh` is idempotent (it only re-downloads the plugin JARs when a newer
upstream release exists) and `play.sh` calls it before every journey. To keep the stack up for
inspection afterwards, the compose logs land in `build/docker-compose.log`.

On failure, Playwright writes traces, screenshots and videos to `playwright-report/`.

## CI run

`.github/workflows/e2e.yml` schedules the suite at 01:00 UTC and resolves the latest plugin releases
and pulls the mock FE container, and sends the existing `DISCORD_WEBHOOK_URL` alert on failure —
same pattern as the perf workflow.

## Configuration

There is little to configure: the container images, ports and the status-list server URL come from
`.env` (copy `.env.example` if you want any non-default — the file itself explains everything). The
realm rendered from `assets/realm/` is intentionally fixed so the tests, the import file name and
the mounts always agree.

The status-list server is part of the stack and reachable only from it (`https://status-list:8443`).
The tests read the same URL through `STATUS_LIST_SERVER_URL`, so they compare the issued
credential's status-list claim against the local instance, not a remote one.

One thing worth knowing: the signing keystore in `assets/crypto/keystore.p12` uses the test-only
password `password` for both entries (`oid4vci-ec-issuer` for ES256 key and `oid4vci-issuer` for
RS256). Never use it outside this folder.
