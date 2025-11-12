# Unported changes so far

## Aud verification with pattern matching

```java
    public Builder withAud(String aud) {
        this.aud = Pattern.compile(Pattern.quote(aud));
        return this;
    }
    
    public Builder withAud(Pattern aud) {
        this.aud = aud;
        return this;
    }

    /**
     * Run checks for replay protection.
     *
     * <p>
     * Determine that the Key Binding JWT is bound to the current transaction and was created for this
     * Verifier (replay protection) by validating nonce and aud claims.
     * </p>
     *
     * @throws VerificationException if verification failed
     */
    private void preventKeyBindingJwtReplay(
            KeyBindingJwtVerificationOpts keyBindingJwtVerificationOpts
    ) throws VerificationException {
        JsonNode nonce = keyBindingJwt.getPayload().get("nonce");
        String expectedNonce = keyBindingJwtVerificationOpts.getNonce();
        if (nonce == null || !nonce.isTextual() || !nonce.asText().equals(expectedNonce)) {
            logger.errorf("Key binding JWT: Unexpected `nonce` value. Expected: %s, but got: %s",
                    expectedNonce, nonce);
            throw new VerificationException("Key binding JWT: Unexpected `nonce` value");
        }

        Pattern expectedAud = keyBindingJwtVerificationOpts.getAud();
        if (expectedAud == null) {
            throw new VerificationException("Key binding JWT: No `aud` policy configured");
        }

        JsonNode aud = keyBindingJwt.getPayload().get("aud");
        if (aud == null || !aud.isTextual() || !expectedAud.matcher(aud.asText()).matches()) {
            logger.errorf("Key binding JWT: Unexpected `aud` value. Expected pattern: /%s/, but got: %s",
                    expectedAud.pattern(), aud);
            throw new VerificationException("Key binding JWT: Unexpected `aud` value");
        }
    }
```

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

## Default OID4VP authentication flow and migration

```java
public static final String OID4VP_AUTH_FLOW = "oid4vp auth";

public static void addFlows(RealmModel realm) {
    // ...
    if (realm.getFlowByAlias(OID4VP_AUTH_FLOW) == null) oid4vpAuthenticationFlow(realm);
}

public static void migrateFlows(RealmModel realm) {
    // ...
    if (realm.getFlowByAlias(OID4VP_AUTH_FLOW) == null) oid4vpAuthenticationFlow(realm);
}

public static void oid4vpAuthenticationFlow(final RealmModel realm) {
    if (!Profile.isFeatureEnabled(Feature.OID4VC_VPAUTH)) {
        return;
    }

    AuthenticationFlowModel oid4vpAuthFlow = new AuthenticationFlowModel();

    oid4vpAuthFlow.setAlias(OID4VP_AUTH_FLOW);
    oid4vpAuthFlow.setDescription("Authenticate via OpenID4VP presentations of self-issued identity credentials");
    oid4vpAuthFlow.setProviderId("basic-flow");
    oid4vpAuthFlow.setTopLevel(true);
    oid4vpAuthFlow.setBuiltIn(true);
    oid4vpAuthFlow = realm.addAuthenticationFlow(oid4vpAuthFlow);
    // TODO: realm.setOid4vpAuthFlow(oid4vpAuthFlow);

    AuthenticationExecutionModel execution = new AuthenticationExecutionModel();

    execution.setParentFlow(oid4vpAuthFlow.getId());
    execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
    execution.setAuthenticator("sd-jwt-authenticator");
    execution.setPriority(10);
    execution.setAuthenticatorFlow(false);

    realm.addAuthenticatorExecution(execution);
}

// Migration

@Override
public void migrateRealm(KeycloakSession session, RealmModel realm) {
    if (realm.getFlowByAlias(DefaultAuthenticationFlows.OID4VP_AUTH_FLOW) == null) {
        LOG.infof("Creating default OpenID4VP user auth flow for realm '%s'", realm.getName());
        DefaultAuthenticationFlows.oid4vpAuthenticationFlow(realm);
    } else {
        LOG.debugf("OpenID4VP user auth flow flow already exists for realm '%s'", realm.getName());
    }
}
```

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

## Miscellaneous improvements and fixes.

```java
// SdJwtCredentialBody.java
public static final String CNF_CLAIM = "cnf";
public static final String JWK_CLAIM = "jwk";
```
