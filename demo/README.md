# OID4VP Local Demo (Walletless)

This demo spins up Keycloak with the OID4VP plugin, creates a demo realm + user, and runs a Java flow that **acts like a wallet**. You get a full end-to-end OpenID4VP authentication without any external wallet app.

## Prerequisites

- Docker (Compose v2 recommended)
- Java 21 (for building and running the demo flow)
- `bash`
- Optional: `just` for convenient commands

## What This Demo Does

1. Starts Keycloak with the OID4VP plugin (`demo/docker-compose.yml`)
2. Imports a demo realm (`demo/realm.json`)
3. Creates a test user (`demo/create-test-user.sh`)
4. Runs a Java flow (`demo/sample-flow.java`) that:
   - Calls `/oid4vp-auth/request`
   - Resolves the signed request object
   - Builds an SD-JWT credential + VP token (wallet replacement)
   - Posts `/oid4vp-auth/response`
   - Polls `/oid4vp-auth/status/{transactionId}`
   - Exchanges the authorization code for an access token

## Quick Start

From the repo root:

```bash
just -f demo/Justfile demo
```

Or without `just`:

```bash
./demo/run-demo.sh
```

First run may take a few minutes while Maven downloads dependencies and builds the plugin.

## Scripts

- `demo/setup-realm.sh`
  - Builds the plugin if needed
  - Starts Keycloak (Docker Compose)
  - Imports the demo realm

- `demo/create-test-user.sh`
  - Creates or updates the demo user and password

- `demo/run-demo.sh`
  - Runs `setup-realm.sh`
  - Runs `create-test-user.sh`
  - Compiles and executes `sample-flow.java`

## Expected Output

You should see log lines like:

- `Received authorization_request and transaction_id`
- `Prepared SD-JWT VP token`
- `Authentication succeeded. Received authorization_code`
- `Access token issued for user: test-user@localhost`

## Configuration

All scripts read the following environment variables (defaults shown):

- `KC_HTTP_PORT=8080`
- `KC_ADMIN_USER=admin`
- `KC_ADMIN_PASS=admin`
- `DEMO_REALM=oid4vp-demo`
- `DEMO_CLIENT_ID=test-app`
- `DEMO_CLIENT_SECRET=password`
- `DEMO_REDIRECT_URI=http://localhost:4200/callback`
- `DEMO_USERNAME=test-user@localhost`
- `DEMO_PASSWORD=password`
- `DEMO_VCT=https://credentials.example.com/identity_credential`
- `DEMO_ISSUER_JWK=demo/keys/keycloak.json`
- `DEMO_HOLDER_JWK=demo/keys/user-wallet-key.json`

If you want to change the realm name or client IDs, update `demo/realm.json` and the variables above together.

## Notes

- The demo disables token-status enforcement to avoid external HTTP calls during local development.
- The SD-JWT issuer key in `demo/keys/keycloak.json` matches the realm key provider in `demo/realm.json`, so verification succeeds locally.
- The demo uses HTTP (`start-dev`) and is **not** production-ready.

## Tear Down

```bash
just -f demo/Justfile stop
```

or

```bash
docker compose -f demo/docker-compose.yml -p oid4vp-demo down -v
```
