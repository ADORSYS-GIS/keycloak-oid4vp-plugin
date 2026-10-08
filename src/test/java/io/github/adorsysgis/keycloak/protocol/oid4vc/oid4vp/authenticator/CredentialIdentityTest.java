package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Covers the verified-identity value objects introduced for user import: the issuer/subject pair,
 * its fail-closed resolution for primary login credentials, and the canonical external-ID
 * encoding stored in federated identity links.
 */
class CredentialIdentityTest {

    @Test
    void externalIdIsStableAndVersioned() {
        String first = CredentialIdentity.externalId("https://issuer.example.com", "subject-1");
        String second = CredentialIdentity.externalId("https://issuer.example.com", "subject-1");

        assertEquals(first, second);
        assertTrue(first.startsWith(CredentialIdentity.EXTERNAL_ID_VERSION + "."));
    }

    @Test
    void externalIdKeepsIssuerAndSubjectUnambiguous() {
        // Without length-prefix framing, ("ab", "c") and ("a", "bc") would hash identically.
        assertNotEquals(CredentialIdentity.externalId("ab", "c"), CredentialIdentity.externalId("a", "bc"));
        assertNotEquals(
                CredentialIdentity.externalId("issuer-a", "subject"),
                CredentialIdentity.externalId("issuer-b", "subject"));
        assertNotEquals(
                CredentialIdentity.externalId("issuer", "subject-a"),
                CredentialIdentity.externalId("issuer", "subject-b"));
    }

    @Test
    void externalIdRejectsBlankValues() {
        assertThrows(IllegalArgumentException.class, () -> CredentialIdentity.externalId(null, "subject"));
        assertThrows(IllegalArgumentException.class, () -> CredentialIdentity.externalId("issuer", "  "));
    }

    @Test
    void missingIssuerOrSubjectResolvesToNull() {
        // Verification never fails for a missing identity (existing trust configurations without
        // an issuer namespace keep authenticating); the import path refuses import without one.
        assertNull(
                CredentialIdentity.forCredential(primaryLoginCredential(), CredentialOrigin.EXTERNAL, null, "subject"));
        assertNull(
                CredentialIdentity.forCredential(primaryLoginCredential(), CredentialOrigin.EXTERNAL, "issuer", null));
        assertNull(CredentialIdentity.forCredential(primaryLoginCredential(), CredentialOrigin.EXTERNAL, null, null));

        CredentialIdentity identity = CredentialIdentity.forCredential(
                primaryLoginCredential(), CredentialOrigin.CURRENT_REALM, "issuer", "subject");
        assertEquals(CredentialOrigin.CURRENT_REALM, identity.origin());
        assertEquals("issuer", identity.issuer());
        assertEquals("subject", identity.subject());
    }

    @Test
    void supportingCredentialExposesNoUserIdentity() {
        CredentialRequirement supporting = new CredentialRequirement().setId("supporting");

        assertNull(CredentialIdentity.forCredential(supporting, CredentialOrigin.EXTERNAL, null, "subject"));
        assertNull(CredentialIdentity.forCredential(supporting, CredentialOrigin.EXTERNAL, "issuer", null));
        assertNull(CredentialIdentity.forCredential(supporting, CredentialOrigin.EXTERNAL, "issuer", "subject"));
    }

    @Test
    void primaryOriginComesFromVerifiedTrustPolicy() {
        CredentialRequirement selfTrusted =
                primaryLoginCredential().setTrust(List.of(new TrustPolicy().setType(TrustPolicy.SELF)));
        CredentialRequirement externallyTrusted =
                primaryLoginCredential().setTrust(List.of(new TrustPolicy().setType(TrustPolicy.EUDI_PID_TRUST_LIST)));

        assertEquals(CredentialOrigin.CURRENT_REALM, CredentialOrigin.fromPrimaryTrust(selfTrusted));
        assertEquals(CredentialOrigin.EXTERNAL, CredentialOrigin.fromPrimaryTrust(externallyTrusted));
    }

    @Test
    void mixedPrimaryTrustHasNoAmbiguousOrigin() {
        CredentialRequirement mixed = primaryLoginCredential()
                .setTrust(List.of(
                        new TrustPolicy().setType(TrustPolicy.SELF),
                        new TrustPolicy().setType(TrustPolicy.EUDI_PID_TRUST_LIST)));

        assertThrows(IllegalStateException.class, () -> CredentialOrigin.fromPrimaryTrust(mixed));
    }

    @Test
    void sessionBoundPresentationExposesNoIdentity() {
        CredentialRequirement sessionPrimary =
                primaryLoginCredential().setIdentitySource(CredentialRequirement.IDENTITY_SOURCE_SESSION);

        assertNull(CredentialIdentity.forCredential(sessionPrimary, CredentialOrigin.EXTERNAL, null, null));
        assertNull(CredentialIdentity.forCredential(sessionPrimary, CredentialOrigin.EXTERNAL, "issuer", "subject"));
    }

    private static CredentialRequirement primaryLoginCredential() {
        return new CredentialRequirement().setId("primary").setRole(CredentialRole.PRIMARY);
    }
}
