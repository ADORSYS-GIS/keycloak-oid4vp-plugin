package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import static org.apache.http.HttpStatus.SC_CONFLICT;
import static org.apache.http.HttpStatus.SC_SERVICE_UNAVAILABLE;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedCertificateUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificate;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificateCreationRequest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificatePage;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificateStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.OrganizationDetails;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.OrganizationPage;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.OrganizationSummary;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

/** In-process stub for the Hub API; it does not open a port or start a server. */
final class StubEudiHubClientProvider implements EudiHubClientProvider {

    static final String TOKEN_PASSTHROUGH_TOKEN = "organizations-token-passthrough";
    private static final String CREATE_TOKEN_PREFIX = "create-";
    private static final String DUPLICATE_TOKEN_PREFIX = "duplicate-";
    private static final String DUPLICATE_NO_MATCH_TOKEN_PREFIX = "duplicate-no-match-";
    private static final String DUPLICATE_REVOKED_TOKEN_PREFIX = "duplicate-revoked-";
    private static final String DUPLICATE_EXPIRED_TOKEN_PREFIX = "duplicate-expired-";
    private static final String DUPLICATE_MALFORMED_TOKEN_PREFIX = "duplicate-malformed-";
    private static final String UPSTREAM_FAILURE_TOKEN_PREFIX = "upstream-failure-";
    private static final String ORGANIZATION_ID = "stub-organization";
    private static final String EXISTING_CERTIFICATE_ID = "existing-certificate";
    private static final String ISSUED_CERTIFICATE_ID = "issued-certificate";

    private static final Map<String, byte[]> certificatesByToken = new ConcurrentHashMap<>();

    @Override
    public <T> T get(String token, URI uri, Class<T> responseType) {
        String path = uri.getPath();
        if (path.endsWith("/v1/me") && responseType == OrganizationPage.class) {
            return responseType.cast(new OrganizationPage(List.of(new OrganizationSummary(
                    ORGANIZATION_ID, token.equals(TOKEN_PASSTHROUGH_TOKEN) ? token : "Stub Org"))));
        }
        if (path.endsWith("/organizations/" + ORGANIZATION_ID) && responseType == OrganizationDetails.class) {
            String supportUri = token.equals(TOKEN_PASSTHROUGH_TOKEN)
                    ? "https://support.example.test/token/" + token
                    : "https://support.example.test";
            return responseType.cast(new OrganizationDetails(
                    new OrganizationDetails.ContactInformation(List.of(supportUri)), List.of("sandbox", "live")));
        }
        if (path.endsWith("/access-certificates") && responseType == AccessCertificatePage.class) {
            return certificatePage(token, responseType);
        }
        throw new IllegalArgumentException("Unexpected EUDI Hub stub GET: " + uri);
    }

    @Override
    public <T> T post(String token, URI uri, Object body, Class<T> responseType) {
        if (!(body instanceof AccessCertificateCreationRequest request) || responseType != AccessCertificate.class) {
            throw new IllegalArgumentException("Unexpected EUDI Hub stub POST body: " + body);
        }
        if (token.startsWith(UPSTREAM_FAILURE_TOKEN_PREFIX)) {
            throw hubError(SC_SERVICE_UNAVAILABLE, "Stub Hub unavailable");
        }
        if (token.startsWith(DUPLICATE_NO_MATCH_TOKEN_PREFIX)) {
            throw hubError(SC_CONFLICT, "The Hub already has a certificate for this key");
        }

        byte[] certificate = certificateForSigningRequest(request.csr());
        if (token.startsWith(DUPLICATE_TOKEN_PREFIX)) {
            certificatesByToken.put(token, certificate);
            throw hubError(SC_CONFLICT, "The Hub already has a certificate for this key");
        }
        if (token.startsWith(CREATE_TOKEN_PREFIX)) {
            certificatesByToken.put(token, certificate);
            return responseType.cast(new AccessCertificate(
                    ISSUED_CERTIFICATE_ID, request.name(), AccessCertificateStatus.VALID, request.environment(), null));
        }
        throw new IllegalArgumentException("Unknown EUDI Hub stub scenario token");
    }

    @Override
    public byte[] download(String token, URI uri) {
        String certificateId =
                token.startsWith(DUPLICATE_TOKEN_PREFIX) ? EXISTING_CERTIFICATE_ID : ISSUED_CERTIFICATE_ID;
        if (!uri.getPath().endsWith("/" + certificateId + "/download")) {
            throw new IllegalArgumentException("Unexpected EUDI Hub stub download URI: " + uri);
        }
        byte[] certificate = certificatesByToken.get(token);
        if (certificate == null) {
            throw new IllegalStateException("No certificate has been issued for this stub token");
        }
        if (token.startsWith(DUPLICATE_MALFORMED_TOKEN_PREFIX)) {
            return new byte[] {0x30, 0x00};
        }
        return certificate;
    }

    @Override
    public void close() {}

    private static <T> T certificatePage(String token, Class<T> responseType) {
        if (!token.startsWith(DUPLICATE_TOKEN_PREFIX) || token.startsWith(DUPLICATE_NO_MATCH_TOKEN_PREFIX)) {
            return responseType.cast(new AccessCertificatePage(List.of()));
        }
        return responseType.cast(new AccessCertificatePage(List.of(new AccessCertificate(
                EXISTING_CERTIFICATE_ID,
                "Existing Stub Certificate",
                duplicateCertificateStatus(token),
                "sandbox",
                null))));
    }

    private static AccessCertificateStatus duplicateCertificateStatus(String token) {
        if (token.startsWith(DUPLICATE_REVOKED_TOKEN_PREFIX)) {
            return AccessCertificateStatus.REVOKED;
        }
        if (token.startsWith(DUPLICATE_EXPIRED_TOKEN_PREFIX)) {
            return AccessCertificateStatus.EXPIRED;
        }
        return AccessCertificateStatus.VALID;
    }

    private static byte[] certificateForSigningRequest(String csrPem) {
        try {
            String encodedCsr = csrPem.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                    .replace("-----END CERTIFICATE REQUEST-----", "")
                    .replaceAll("\\s", "");
            PKCS10CertificationRequest csr =
                    new PKCS10CertificationRequest(Base64.getDecoder().decode(encodedCsr));
            PublicKey subjectPublicKey = new JcaPEMKeyConverter()
                    .setProvider(BouncyIntegration.PROVIDER)
                    .getPublicKey(SubjectPublicKeyInfo.getInstance(csr.getSubjectPublicKeyInfo()));

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair issuerKeyPair = keyPairGenerator.generateKeyPair();
            X509Certificate issuerCertificate =
                    CertificateUtils.generateV1SelfSignedCertificate(issuerKeyPair, "Stub EUDI Hub CA");
            return ExtendedCertificateUtils.generateV3Certificate(
                            issuerKeyPair.getPrivate(),
                            issuerCertificate,
                            subjectPublicKey,
                            "Stub Access Certificate",
                            List.of())
                    .getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Could not create a certificate for the EUDI Hub stub", e);
        }
    }

    private static WebApplicationException hubError(int status, String detail) {
        return new WebApplicationException(
                detail,
                Response.status(status)
                        .entity(new OAuth2ErrorRepresentation(OAuthErrorException.SERVER_ERROR, detail))
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build());
    }
}
