# keycloak-oid4vp-plugin

This plugin adds OpenID4VP authentication to Keycloak

## Compatibility

This plugin has been tested with:

| **Requirement** | **Version** |
|-----------------|-------------|
| **Java**        | 17          |
| **Keycloak**    | nightly     |

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

The AsciiDoc content in `docs/` is published with [Antora](https://antora.org/).

Build the static site:
```sh
npm run docs:build
```

Preview locally after building (serves on port 8080):
```sh
npm run docs:serve
```

The generated site is written to `build/site/` and ignored by git.
