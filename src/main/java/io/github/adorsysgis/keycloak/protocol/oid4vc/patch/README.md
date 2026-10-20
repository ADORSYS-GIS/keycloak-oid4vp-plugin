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

### Omit encryption parameters from Issuer Metadata

By default the Credential Issuer Metadata advertises `credential_response_encryption` and
`credential_request_encryption` as provided by Keycloak. When the realm attribute
`oid4vci.omit_encryption_metadata` is `true`, the plugin sets both to `null` so they are omitted from the
metadata. The attribute defaults to `false`.

### Omit empty `zip_values_supported` arrays from Issuer Metadata

The spec does not allow empty arrays. Keycloak, however, may advertise empty `zip_values_supported` arrays
in the request and response encryption metadata due to https://github.com/keycloak/keycloak/issues/54115.
The plugin omits such empty arrays (sets them to `null`) so they are dropped from the metadata. This patch
is to be removed once the upstream bug is fixed.

### Presentation during issuance metadata

When the realm attribute `oid4vci.presentation_during_issuance` is `true`, the plugin advertises
`authorization_challenge_endpoint` in both:

- the Credential Issuer Metadata, as required by the German EUDI Wallet ecosystem profile; and
- the OAuth Authorization Server Metadata, as defined by OAuth 2.0 for First-Party Applications.

### Patch Wallet Credential Requests

Some wallet applications send the OID4VCI Credential Request with `credential_configuration_id`
instead of `credential_identifier` (OID4VCI §8.2). The plugin transcribes the former onto the
latter whether the request is plaintext JSON or a JWE (OID4VCI §10): plaintext requests are patched
as is, while JWE-encrypted requests are first decrypted with the realm encryption key, then patched,
and re-encrypted with the same key material before the request reaches the issuance endpoint. This
patch only applies provided the realm attribute `oid4vci.patch_credential_requests` is set to`true`;
otherwise requests are forwarded untouched.

### OIDC DPoP compatibility patch

`PatchedOIDCLoginProtocol` removes the `dpop_jkt` client-session note when the client has not
enabled DPoP. This prevents Keycloak from binding an unsolicited wallet-supplied thumbprint to
the authorization code and subsequently requiring a matching DPoP proof at the token endpoint.

This works around [Keycloak issue #51573](https://github.com/keycloak/keycloak/issues/51573),
which describes Valera Wallet sending `dpop_jkt` for clients that do not use DPoP. The patch
is to be removed once Valera addresses the issue.

### Tolerate a mismatched `iss` claim in JWT proofs

In compliance with the spec, Keycloak's `JwtProofValidator` rejects a JWT proof whose `iss`
claim is not the requesting `client_id` (OID4VCI F.1). The German EUDI iOS wallet sets `iss`
to the Credential Issuer identifier instead. See bug tracker:
[german-national-wallet/issues-tracker-ios#36](https://github.com/german-national-wallet/issues-tracker-ios/issues/36).
This patch relaxes this validation provided the realm attribute `oid4vci.allow_proof_iss_mismatch`
is set to `true`. Only is allowed when the proof's `iss` equals the Credential Issuer identifier;
any other `iss` value is rejected as before and all other validations remain enforced. The patch
is to be removed once the wallet is fixed.
