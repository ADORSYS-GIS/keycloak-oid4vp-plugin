package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

/**
 * Authentication identity established from a verified credential.
 *
 * <p>The subject is meaningful only inside the verified Credential Issuer's namespace.
 */
public record CredentialIdentity(String issuer, String subject) {}
