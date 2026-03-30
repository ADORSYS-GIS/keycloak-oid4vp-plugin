# OID4VP Local Demo

This demo is designed as a teaching tool for the OID4VP authentication flow implemented by the plugin.

It splits the flow into two CLI actors:

- an **app** that starts authentication, displays the `openid4vp` offer link, polls transaction status, and can retrieve an access token;
- a **wallet** that accepts an offer link, lets you choose a credential scenario, and submits the presentation.

There is also a retained one-shot **smoke** flow for quick automation.

## Prerequisites

- Docker (Compose v2 recommended)
- Java 21
- `bash`
- Optional: `just`

## Demo Layout

- `app/`
  - interactive verifier/app CLI
- `wallet/`
  - interactive wallet CLI
- `lib/`
  - shared Java helpers for HTTP, SD-JWT, and OID4VP protocol handling
- `smoke/`
  - one-shot end-to-end automation built on the same shared helpers
- `realm.json`
  - demo realm, client, auth flow, and demo users
- `docker-compose.yml`
  - local Keycloak runtime for the demo

## Interactive Flow

Open two terminals.

Terminal 1:

```bash
cd demo
just start app
```

Terminal 2:

```bash
cd demo
just start wallet
```

Then:

1. In the app terminal, choose to start an authentication flow.
2. The app prints an `openid4vp://...` offer link and starts polling in the background.
3. Copy that link into the wallet terminal.
4. In the wallet terminal, choose one of the credential scenarios.
5. The wallet sends the presentation and returns to its prompt.
6. The app reports success or failure.
7. On success, the app can optionally exchange the authorization code for an access token and print the authenticated user details.

The wallet currently supports these scenarios:

- valid credential issued to Alice
- valid credential issued to Bob
- valid credential issued to an unknown user
- invalid credential issued to Alice (expired)

## One-Shot Smoke Flow

For automation or a quick end-to-end check:

```bash
cd demo
just smoke
```

or from the repo root:

```bash
just -f demo/Justfile smoke
```

This keeps the old “do everything in one stroke” behavior, but it now sits beside the interactive demo instead of replacing it.

## Scripts

- `just start app`
  - starts Keycloak if needed
  - imports the demo realm if needed
  - runs the interactive app CLI
- `just start wallet`
  - runs the interactive wallet CLI
- `just smoke`
  - runs the non-interactive end-to-end smoke demo
- `just stop`
  - tears down the local Keycloak demo stack
- `just logs`
  - tails Keycloak logs

## Demo Users

The realm imports these demo users directly:

- `alice@localhost`
- `bob@localhost`

## Configuration

Most users do not need to configure anything.

If you need to override the default host port, create a `demo/.env` file:

```bash
cp demo/.env.example demo/.env
```

Then edit:

```bash
KC_HTTP_PORT=8080
```

The demo scripts load `demo/.env` automatically, so you do not need to export variables into your shell.

If you need deeper overrides for local debugging, the scripts still honor environment variables from `.env`, but the common case is just changing `KC_HTTP_PORT`.

## Notes

- The demo disables token-status enforcement to avoid external HTTP calls during local development.
- The issuer key in `keys/keycloak.json` matches the realm key provider in `realm.json`, so local verification succeeds.
- The wallet CLI accepts a raw `openid4vp` offer link. That keeps it reusable for future browser-assisted flows too.
- The demo uses HTTP and `start-dev`. It is not production-ready.
- If you previously ran the older one-shot demo, use `just stop` before your first interactive run so the realm is recreated cleanly.

## Tear Down

```bash
cd demo
just stop
```

The app script also tears the stack down automatically when you choose to stop the app.
