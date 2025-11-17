# Unported changes so far

_This file will be removed as from the first stable release of the plugin._

## Display metadata at legacy location

```java
// SupportedCredentialConfiguration.java
@JsonIgnore
private static final String LEGACY_DISPLAY_KEY = "display";

@JsonProperty(value = LEGACY_DISPLAY_KEY, access = JsonProperty.Access.READ_ONLY)
public List<DisplayObject> getDisplay() {
    return credentialMetadata != null ? credentialMetadata.getDisplay() : null;
}

// Backward compatibility check for display metadata
Map<String, SupportedCredentialConfiguration> credentialsSupported = issuer.getCredentialsSupported();
assertEquals(4, credentialsSupported.size());
credentialsSupported.values().forEach(credentialSupported -> assertSame(
credentialSupported.getCredentialMetadata().getDisplay(),
                credentialSupported.getDisplay()
        ));
```

## Adjustments in IssuerEndpoint

- Relax CORS policy (Pending PR)
- Update code leading to DPoP proof reuse (PR in preparation)
- Backward compatibility with Lissi wallet (In preparation)

## Custom Keycloak theme

```json
}, {
    "name" : "keycloak.v2+oid4vp",
    "types": [ "login" ]
}]
```

```java
// FreeMarkerLoginFormsProvider.java
if (Profile.isFeatureEnabled(Feature.OID4VC_VPAUTH)) {
    attributes.put("oid4vp", new OID4VPUserAuthBean(session, realm, baseUri));
}
```

## Certificate generation with SAN for Lissi wallet

0c211765d0 (HEAD -> datev-develop-decoy-v2, origin/datev-develop-decoy-v2) Final file updates - oidc chaining and certificate generation

## OIDC chaining support

0c211765d0 (HEAD -> datev-develop-decoy-v2, origin/datev-develop-decoy-v2) Final file updates - oidc chaining and certificate generation
