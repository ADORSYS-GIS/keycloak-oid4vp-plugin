
## Proper event firing

```java
    OID4VP_INIT_AUTH(65, true),
    OID4VP_INIT_AUTH_ERROR(0x10000 + OID4VP_INIT_AUTH.getStableIndex(), true);
```

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
