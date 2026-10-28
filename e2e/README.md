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

| Component               | Where it comes from                                                  |
| ----------------------- | -------------------------------------------------------------------- |
| Keycloak                | `quay.io/keycloak/keycloak:26.8.0` with both plugins mounted as JARs |
| Plugin: OpenID4VP login | latest release of this very repo                                     |
| Plugin: token status    | latest release of `ADORSYS-GIS/token-status-link`                    |
| Mock FE                 | latest `ghcr.io/adorsys-gis/keycloak-oid4vc-mock-fe`                 |
| Test wallet             | latest `ghcr.io/eudi-dev/eudi-dev` (headless, auto-accepting)        |
| Status server           | public instance `https://statuslist.eudi-adorsys.com`                |

## Running

The `pnpm` scripts in `package.json` are the front face (thin wrappers; the logic lives in
`scripts/*.sh`):

```bash
pnpm play                        # bring the stack up, run the journey, tear it down
pnpm play -- --keep-stack-alive  # keep the stack up afterwards (logs under build/)
pnpm clean:play                  # wipe generated artifacts first, then run
pnpm clean:play -- --keep-stack-alive
pnpm clean                       # only wipe generated artifacts
pnpm stop                        # tear a kept-alive stack down
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

One thing worth knowing: the signing keystore in `assets/crypto/keystore.p12` uses the test-only
password `password` for both entries (`oid4vci-ec-issuer` for ES256 key and `oid4vci-issuer` for
RS256). Never use it outside this folder.
