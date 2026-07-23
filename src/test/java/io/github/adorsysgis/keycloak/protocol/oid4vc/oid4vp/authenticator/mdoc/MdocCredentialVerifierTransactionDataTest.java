package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.authlete.mdoc.DeviceNameSpaces;
import com.authlete.mdoc.DeviceNameSpacesEntry;
import com.authlete.mdoc.DeviceResponse;
import com.authlete.mdoc.DeviceSignedItems;
import com.authlete.mdoc.DeviceSignedItemsEntry;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationOpts;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataSupport;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

class MdocCredentialVerifierTransactionDataTest {

    private static final String DOC_TYPE = "com.example.doctype";
    private static final String NAMESPACE = "com.example.namespace1";

    @Test
    void acceptsMatchingTransactionData() throws Exception {
        String wire = wireEntry("payment");
        String hash = hashForWire(wire);

        String mdoc = buildMdocWithTransactionData(hash);
        MdocVerificationContext verificationContext = new MdocVerificationContext(mdoc);
        AuthenticationSessionModel authSession = authSessionWithWire(List.of(wire));

        MdocCredentialVerifier handler = new MdocCredentialVerifier(mock(StatusListJwtFetcher.class));
        assertDoesNotThrow(() -> handler.validateTransactionData(authSession, verificationContext));
    }

    @Test
    void rejectsMismatchedTransactionData() throws Exception {
        String wire = wireEntry("payment");
        String mdoc = buildMdocWithTransactionData("different-hash");

        MdocVerificationContext verificationContext = new MdocVerificationContext(mdoc);
        AuthenticationSessionModel authSession = authSessionWithWire(List.of(wire));

        MdocCredentialVerifier handler = new MdocCredentialVerifier(mock(StatusListJwtFetcher.class));
        assertThrows(
                VerificationException.class, () -> handler.validateTransactionData(authSession, verificationContext));
    }

    @Test
    void rejectsMissingTransactionDataHashes() throws Exception {
        String wire = wireEntry("payment");
        // Build mDoc with empty device namespaces (no transaction_data_hashes)
        MdocVerificationOpts opts =
                MdocBaseTest.getDefaultMdocVerificationOpts().build();
        String mdoc = MdocBaseTest.buildDeviceResponse(opts, Map.of(NAMESPACE, Map.of("c", "v")), DOC_TYPE)
                .encodeToBase64Url();

        MdocVerificationContext verificationContext = new MdocVerificationContext(mdoc);
        AuthenticationSessionModel authSession = authSessionWithWire(List.of(wire));

        MdocCredentialVerifier handler = new MdocCredentialVerifier(mock(StatusListJwtFetcher.class));
        assertThrows(
                VerificationException.class, () -> handler.validateTransactionData(authSession, verificationContext));
    }

    @Test
    void skipsValidationWhenNoTransactionDataOnSession() throws Exception {
        MdocVerificationOpts opts =
                MdocBaseTest.getDefaultMdocVerificationOpts().build();
        String mdoc = MdocBaseTest.buildDeviceResponse(opts, Map.of(NAMESPACE, Map.of("c", "v")), DOC_TYPE)
                .encodeToBase64Url();

        MdocVerificationContext verificationContext = new MdocVerificationContext(mdoc);
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(authSession.getAuthNote(OID4VPAuthenticator.TRANSACTION_DATA_WIRE_KEY))
                .thenReturn(null);

        MdocCredentialVerifier handler = new MdocCredentialVerifier(mock(StatusListJwtFetcher.class));
        assertDoesNotThrow(() -> handler.validateTransactionData(authSession, verificationContext));
    }

    private static AuthenticationSessionModel authSessionWithWire(List<String> wireEntries) throws Exception {
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(authSession.getAuthNote(OID4VPAuthenticator.TRANSACTION_DATA_WIRE_KEY))
                .thenReturn(JsonSerialization.writeValueAsString(wireEntries));
        return authSession;
    }

    // Builds an mDoc with transaction_data_hashes in its device namespaces.
    private static String buildMdocWithTransactionData(String hash) throws Exception {
        DeviceSignedItemsEntry txDataEntry = new DeviceSignedItemsEntry("transaction_data_hashes", List.of(hash));
        DeviceSignedItems items = new DeviceSignedItems(List.of(txDataEntry));
        DeviceNameSpacesEntry nsEntry = new DeviceNameSpacesEntry(DOC_TYPE, items);
        DeviceNameSpaces deviceNameSpaces = new DeviceNameSpaces(List.of(nsEntry));

        MdocVerificationOpts opts =
                MdocBaseTest.getDefaultMdocVerificationOpts().build();
        DeviceResponse dr =
                MdocBaseTest.buildDeviceResponse(opts, Map.of(NAMESPACE, Map.of("c", "v")), DOC_TYPE, deviceNameSpaces);
        return dr.encodeToBase64Url();
    }

    private static String wireEntry(String type) {
        var tx = JsonSerialization.mapper.createObjectNode();
        tx.put(TransactionDataSupport.TYPE_CLAIM, type);
        tx.putArray(TransactionDataSupport.CREDENTIAL_IDS_CLAIM).add("cred-1");
        return TransactionDataSupport.prepareWireEntry(TransactionDataSupport.encodeWireObject(tx), "cred-1");
    }

    private static String hashForWire(String wire) {
        return TransactionDataSupport.base64UrlEncodeHash(
                TransactionDataSupport.hashWireString(wire, TransactionDataSupport.DEFAULT_HASH_ALG));
    }
}
