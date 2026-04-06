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
