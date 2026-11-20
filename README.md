# keycloak-oid4vp-plugin

This plugin adds OpenID4VP authentication to Keycloak.

## Contents

- [Compatibility](#compatibility)
  - [Supported features](#supported-features)
  - [Tested wallets](#tested-wallets)
- [Build the Plugin](#build-the-plugin)
- [Deploying the Plugin](#deploying-the-plugin)
- [Running Keycloak for Testing (Docker Compose)](#running-keycloak-for-testing-docker-compose)
- [Configuration](#configuration)
  - [OID4VP authenticator configuration](#oid4vp-authenticator-configuration)
- [Documentation site (Antora)](#documentation-site-antora)
- [Releasing to Maven Central](#releasing-to-maven-central)
- [License](#license)

## Compatibility

The plugin has been tested with:

| **Requirement** | **Version** |
| --------------- | ----------- |
| **Java**        | 21          |
| **Keycloak**    | 26.8.2      |

While it may work with other versions, compatibility is not guaranteed. Ensure your environment matches the tested
versions for best results.

### Supported features

The plugin implements the verifier side of
[OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
(OpenID4VP 1.0, finalized in July 2025). The following features are supported:

- **Authorization request.** Signed request object (JAR) delivered through `request_uri`, with
  `request_uri_method` `get` (default) or `post` and a custom wallet invocation URL scheme.
- **Client identifier prefixes.** `x509_san_dns` (default) and `x509_hash`.
- **Client authentication.** Request object signed with the realm key, `x5c` header carrying the access
  certificate, and registration certificate or extra attestations advertised through `verifier_info`.
- **Query language.** DCQL (`dcql_query`) with credential sets, Claims Path Pointers for JSON-based
  credentials and ISO mDoc, and per-format `meta` parameters. Support for DIF Presentation Exchange was
  removed in line with the evolution of the spec.
- **Credential formats.** SD-JWT VC (`dc+sd-jwt`) and ISO/IEC 18013-5 mDoc (`mso_mdoc`), alone or
  combined in one profile.
- **Response.** Response type `vp_token`, with response modes `direct_post` and encrypted
  `direct_post.jwt` (JWE, ECDH-ES, A128GCM/A256GCM), plus error responses from the wallet in both
  plaintext and encrypted form. The interactive authorization flow of presentation during issuance
  uses `ia_post` or `ia_post.jwt` instead.
- **Holder binding.** Key Binding JWT for SD-JWT VC with proof age limit, non-cryptographic
  presentations with state binding (OpenID4VP §5.3), and mDoc device authentication.
- **Transaction data.** `transaction_data` (OpenID4VP §5.1) with `sha-256` hashes.
- **Credential verification.** SD-JWT VC issuer signature with `nbf`/`exp`/`iss` checks, and mDoc
  issuer and device authentication with ISO-spec session transcript fallback.
- **Issuer trust.** Self-trust for credentials issued by the same realm, X.509 trust anchors (`x5c`),
  and EUDI PID trust lists (ETSI TS 119 602 LoTE).
- **Revocation.** Optional Token Status List revocation checks (disabled by default), with
  configurable trust in the Status List signer.
- **Verifier policy.** JSON authentication profiles with primary and supporting credentials,
  credential groups, per-profile registration certificates, client filters, and claim-binding rules.
- **Login integration.** OIDC login through the plugin's login themes, and API-driven flows with
  status polling and PKCE S256 code exchange.
- **Presentation during issuance.** [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
  issuance gated on a verified presentation, through the
  [Interactive Authorization Endpoint](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-1_1-wg-draft.html#name-interactive-authorization)
  of the OpenID4VCI 1.1 working-group draft or through a [nested OpenID4VP flow](https://bmi.usercontent.opencode.de/eudi-wallet/wallet-development-documentation-public/latest/architecture-concept/03-data-flows/31-eaa-issuance.html#presentation-during-issuance)
  in the OpenID4VCI 1.0 authorization code flow.

Conversely, the following features are notably **not** supported:

- W3C Verifiable Credentials (VCDM) formats (`jwt_vc_json`, `ldp_vc`)
- OpenID4VP over the Digital Credentials API
- DCQL Trusted Authorities Queries

### Tested wallets

The plugin has been tested successfully against the following real wallets:

- The [d-you](https://d-you.gov.de/en) Sandbox wallet (on Android and iOS) – Germany's official EUDI Wallet to be 
  launched in January 2027.
- The [Valera](https://github.com/a-sit-plus/valera) wallet (on Android) – an open-source EUDI Wallet implementation.

Additionally, the plugin's end-to-end suite covers the [eudi-dev](https://github.com/eudi-dev/eudi-dev) headless test
wallet, an OpenID-certified wallet for testing EUDI issuers and verifiers; see [`e2e/`](./e2e/README.md).

## Build the Plugin

To compile the plugin without running tests, run:

```sh
./mvnw clean package -DskipTests
```

The built JAR will be located at `target/keycloak-oid4vp-plugin-{version}.jar`.

If you want to run the tests, make sure **Docker is installed and running** because the test suite uses
[Testcontainers](https://testcontainers.com/) and a Keycloak container. Then use:

```sh
./mvnw clean verify
```

Running the tests from an IDE such as IntelliJ may fail if the JAR has not been built first. By default,
the IDE does not delegate the build to Maven and therefore does not produce the JAR that the tests deploy
into the Keycloak container. Build the JAR explicitly (as described above) before running the tests from
the IDE.

Additionally, Gatling load tests are provided in the codebase to monitor the plugin's performance and
behavior under heavy load. Run them with (as they are run in the CI/CD pipeline):

```sh
./mvnw gatling:test
```

For the full options on how to run Gatling simulations (e.g. running a single simulation
non-interactively), refer to the [Gatling Maven plugin documentation](https://docs.gatling.io/integrations/build-tools/maven-plugin/#running-your-simulations).

For end-to-end testing of the full credential lifecycle (issued credential → presentation
login → revocation → rejected presentation), see the [`e2e/`](./e2e/README.md) suite.

## Deploying the Plugin

Copy the JAR file to the `providers` directory of your Keycloak installation. For example:

```sh
cp target/keycloak-oid4vp-plugin-{version}.jar /path/to/keycloak/providers/
```

For more information about loading and managing Keycloak plugins, refer to the
[Keycloak documentation on deploying custom providers](https://www.keycloak.org/docs/latest/server_development/#_deploying).

## Running Keycloak for Testing (Docker Compose)

A `docker-compose.yml` is provided in this project for testing purposes. To start Keycloak with the plugin:

```sh
docker compose up
```

This will mount the plugin JAR into the Keycloak container as configured in the compose file.

By default the compose file mounts `keycloak-oid4vp-plugin-999.0.0-SNAPSHOT.jar`. If you built a different version,
set `VERSION` when starting compose:

```sh
VERSION=1.0.0-SNAPSHOT docker compose up
```

Once the container is up, you can access the Keycloak Admin Console at:

- URL:`http://localhost:8080/admin/master/console/`
- Username: `admin`
- Password: `admin`

For more information about using the Keycloak Admin Console and managing realms, clients, and users, see the
[Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/).

If you need to make specific changes (e.g., environment variables, ports, or database settings),
you are encouraged to create a `docker-compose.override.yml` based on the provided `docker-compose.yml`.

## Configuration

The plugin can be configured via the `oid4vp-auth` realm resource provider's standard Keycloak SPI
properties. These can be set in `keycloak.conf`, via CLI flags, or via `KC_*` environment variables.

To automatically create the supplied `oid4vp auth` authentication flow during startup, configure the
realms for which the flow should be created as a comma-separated list:

```bash
bin/kc.sh start --spi-realm-restapi-extension-oid4vp-auth-managed-realms='test,dev'
```

This plugin equally supports a `verbose-errors` setting to control whether detailed verification errors
are returned to clients. By default, verbose errors are disabled (safe-by-default).

For complete configuration examples (including examples for `keycloak.conf`, `KC_*` environment variables, and CLI
flags), see:

- Authentication flow and provider configuration:
  [`docs/modules/ROOT/pages/oid4vp-user-authentication.adoc`](./docs/modules/ROOT/pages/oid4vp-user-authentication.adoc)
- German wallet PID verification configuration:
  [`docs/modules/ROOT/pages/german-wallet-pid-verification-configuration.adoc`](./docs/modules/ROOT/pages/german-wallet-pid-verification-configuration.adoc)
- Presentation during credential issuance:
  [`docs/modules/ROOT/pages/presentation-during-issuance-configuration.adoc`](./docs/modules/ROOT/pages/presentation-during-issuance-configuration.adoc)
- Technical performance/security tuning:
  [`docs/modules/ROOT/pages/non-functional-requirements.adoc`](./docs/modules/ROOT/pages/non-functional-requirements.adoc)

### OID4VP authenticator configuration

Deployment-facing `oid4vp-authenticator` options (for example `clientIdentifierPrefix`,
`responseMode`, `customUrlScheme`, `accessCertificate`, and `registrationCertificate`) are documented in:
[`docs/modules/ROOT/pages/oid4vp-deployment-configuration.adoc`](./docs/modules/ROOT/pages/oid4vp-deployment-configuration.adoc).

## Documentation site (Antora)

The AsciiDoc content in `docs/` is built with [Antora](https://docs.antora.org/antora/latest/)
and published at [adorsys-gis.github.io/keycloak-oid4vp-plugin](https://adorsys-gis.github.io/keycloak-oid4vp-plugin/).
See `docs/README.md` for build and preview instructions.

## Releasing to Maven Central

The plugin is available on
[Maven Central](https://central.sonatype.com/artifact/io.github.adorsys-gis/keycloak-oid4vp-plugin).
Releases are published from GitHub Actions when a tag `vX.Y.Z` is pushed.

The workflow expects these repository secrets:

- `CENTRAL_TOKEN_USERNAME`
- `CENTRAL_TOKEN_PASSWORD`
- `GPG_PRIVATE_KEY`
- `GPG_PASSPHRASE`

The release build publishes signed artifacts (`jar`, `sources`, `javadoc`) for version `X.Y.Z`.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).
See [LICENSE](./LICENSE) for details.
