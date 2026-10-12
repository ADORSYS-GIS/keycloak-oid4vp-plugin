package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialIdentity.Origin;
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
        // Fixed legacy vector: changing the hashing utility must not orphan existing links.
        assertEquals("v1.dc9e9875b558505dbf0e1591b64428443d2ff1af7dde7b9eb011d1cf7ba9306d", first);
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
        assertNull(CredentialIdentity.forCredential(primaryLoginCredential(), Origin.EXTERNAL, null, "subject"));
        assertNull(CredentialIdentity.forCredential(primaryLoginCredential(), Origin.EXTERNAL, "issuer", null));
        assertNull(CredentialIdentity.forCredential(primaryLoginCredential(), Origin.EXTERNAL, null, null));

        CredentialIdentity identity =
                CredentialIdentity.forCredential(primaryLoginCredential(), Origin.CURRENT_REALM, "issuer", "subject");
        assertEquals(Origin.CURRENT_REALM, identity.origin());
        assertEquals("issuer", identity.issuer());
        assertEquals("subject", identity.subject());
    }

    @Test
    void supportingCredentialExposesNoUserIdentity() {
        CredentialRequirement supporting = new CredentialRequirement().setId("supporting");

        assertNull(CredentialIdentity.forCredential(supporting, Origin.EXTERNAL, null, "subject"));
        assertNull(CredentialIdentity.forCredential(supporting, Origin.EXTERNAL, "issuer", null));
        assertNull(CredentialIdentity.forCredential(supporting, Origin.EXTERNAL, "issuer", "subject"));
    }

    @Test
    void primaryOriginComesFromVerifiedTrustPolicy() {
        CredentialRequirement selfTrusted =
                primaryLoginCredential().setTrust(List.of(new TrustPolicy().setType(TrustPolicy.SELF)));
        CredentialRequirement externallyTrusted =
                primaryLoginCredential().setTrust(List.of(new TrustPolicy().setType(TrustPolicy.EUDI_PID_TRUST_LIST)));

        assertEquals(Origin.CURRENT_REALM, Origin.fromPrimaryTrust(selfTrusted));
        assertEquals(Origin.EXTERNAL, Origin.fromPrimaryTrust(externallyTrusted));
    }

    @Test
    void mixedPrimaryTrustHasNoAmbiguousOrigin() {
        CredentialRequirement mixed = primaryLoginCredential()
                .setTrust(List.of(
                        new TrustPolicy().setType(TrustPolicy.SELF),
                        new TrustPolicy().setType(TrustPolicy.EUDI_PID_TRUST_LIST)));

        assertThrows(IllegalStateException.class, () -> Origin.fromPrimaryTrust(mixed));
    }

    @Test
    void sessionBoundPresentationExposesNoIdentity() {
        CredentialRequirement sessionPrimary =
                primaryLoginCredential().setIdentitySource(CredentialRequirement.IDENTITY_SOURCE_SESSION);

        assertNull(CredentialIdentity.forCredential(sessionPrimary, Origin.EXTERNAL, null, null));
        assertNull(CredentialIdentity.forCredential(sessionPrimary, Origin.EXTERNAL, "issuer", "subject"));
    }

    private static CredentialRequirement primaryLoginCredential() {
        return new CredentialRequirement().setId("primary").setRole(CredentialRole.PRIMARY);
    }
}
