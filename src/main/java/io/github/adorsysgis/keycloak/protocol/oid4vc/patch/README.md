# Temporary patches for Keycloak OpenID4VC

The code in this package does not belong in this plugin. It only exists for convenience and is **meant to be removed**
in future versions when Keycloak is updated with these features.

### Configure and expose root display object of Issuer Metadata

The realm attribute to configure with a valid JSON array is `oid4vci.display`.

```json
{
  "oid4vci.display": "[{\"name\": \"Example Credential Issuer\", \"locale\": \"en-US\", \"logo\": {\"uri\": \"https://example.com/logo.png\", \"alt_text\": \"Issuer Logo\"}}, {\"name\": \"Beispiel-Aussteller für Berechtigungsnachweise\", \"locale\": \"de\", \"logo\": {\"uri\": \"https://example.com/logo-de.png\", \"alt_text\": \"Ausstellerlogo\"}}]"
}
```

### Presentation during issuance metadata

When the realm attribute `oid4vci.presentation_during_issuance` is `true`, the plugin advertises
`authorization_challenge_endpoint` in both:

- the Credential Issuer Metadata, as required by the German EUDI Wallet ecosystem profile; and
- the OAuth Authorization Server Metadata, as defined by OAuth 2.0 for First-Party Applications.

### OIDC DPoP compatibility patch

`PatchedOIDCLoginProtocol` removes the `dpop_jkt` client-session note when the client has not
enabled DPoP. This prevents Keycloak from binding an unsolicited wallet-supplied thumbprint to
the authorization code and subsequently requiring a matching DPoP proof at the token endpoint.

This works around [Keycloak issue #51573](https://github.com/keycloak/keycloak/issues/51573),
which describes Valera Wallet sending `dpop_jkt` for clients that do not use DPoP. The patch
is to be removed once Valera addresses the issue.
