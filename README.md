# keycloak-oid4vp-plugin

This plugin adds OpenID4VP authentication to Keycloak

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).
See [LICENSE](./LICENSE) for details.

## Compatibility

This plugin has been tested with:

| **Requirement** | **Version** |
| --------------- |-------------|
| **Java**        | 21          |
| **Keycloak**    | 26.5.4      |

While it may work with other versions, compatibility is not guaranteed. Ensure your environment matches the tested
versions for best results.

## Build the Plugin

To compile the plugin, run:

```sh
./mvnw clean package
```

The built JAR will be located at `target/keycloak-oid4vp-plugin-{version}.jar`.

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

If you need to make specific changes (e.g., environment variables, ports, or database settings),
you are encouraged to create a `docker-compose.override.yml` based on the provided `docker-compose.yml`.

## Documentation site (Antora)

The AsciiDoc content in `docs/` is published with [Antora](https://docs.antora.org/antora/latest/).
See `docs/README.md` for build and preview instructions.

## Releasing to Maven Central

Releases are published from GitHub Actions when a tag `vX.Y.Z` is pushed.
The workflow expects these repository secrets:

- `CENTRAL_TOKEN_USERNAME`
- `CENTRAL_TOKEN_PASSWORD`
- `GPG_PRIVATE_KEY`
- `GPG_PASSPHRASE`

The release build publishes signed artifacts (`jar`, `sources`, `javadoc`) for version `X.Y.Z`.
