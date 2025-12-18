_This file will be removed as from the first stable release of the plugin._

# Unported changes so far

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

## OIDC chaining support

```java
// Custom query parameter indicating the login method (NOT CRITICAL)
String kcLoginMethod = userSession.getNote(OIDCLoginProtocol.LOGIN_METHOD_PARAM);
if (kcLoginMethod != null) {
    redirectUri.addParam(OIDCLoginProtocol.LOGIN_METHOD_PARAM, kcLoginMethod);
}
```

# Consequential changes as we ported code to this plugin version

- The realm migration logic was moved to `OID4VPUserAuthEndpointFactory`.
