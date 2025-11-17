# Consequential changes as we ported code to this plugin version

_This file will be removed as from the first stable release of the plugin._

- The realm migration logic was moved to `OID4VPUserAuthEndpointFactory`.
- Client scheme was hardcoded for compatibility with the Lissi wallet, because aud claim pattern matching is not yet
  available in base Keycloak.
