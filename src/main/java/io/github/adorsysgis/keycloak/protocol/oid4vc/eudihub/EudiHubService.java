package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import static org.apache.http.HttpStatus.SC_CONFLICT;
import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedCertificateUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.AccessCertificateResult;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.Environment;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.ExistingCertificate;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.Organization;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificate;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificateCreationRequest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificatePage;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificateStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.OrganizationDetails;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.OrganizationPage;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.OrganizationSummary;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.ProblemDetail;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.VerifierDiscoveryService;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Client for the Organization API of the German EUDI Hub.
 *
 * <p>Every call takes the portal access token of the user and uses it for that request only. The
 * token is never stored or logged.
 */
public class EudiHubService {

    private static final Logger logger = Logger.getLogger(EudiHubService.class);

    /** Organization API of the production EUDI Hub. */
    static final String DEFAULT_BASE_URL = "https://api.eudi-hub.gov.de/org-management";

    private final KeycloakSession session;
    private final String baseUrl;
    private final EudiHubClientProvider hubClient;
    private final ExistingAccessCertificateFinder existingAccessCertificateFinder;

    public EudiHubService(KeycloakSession session) {
        this(session, DEFAULT_BASE_URL);
    }

    EudiHubService(KeycloakSession session, String baseUrl) {
        this.session = session;
        this.baseUrl = baseUrl;
        this.hubClient = session.getProvider(EudiHubClientProvider.class);
        this.existingAccessCertificateFinder =
                new ExistingAccessCertificateFinder(this::listAccessCertificates, this::downloadAccessCertificate);
    }

    /**
     * Returns the organizations the token's user is assigned to, together with the environment and
     * support URIs the certificate request needs.
     */
    public List<Organization> listOrganizations(String token) {
        String portalToken = Objects.requireNonNull(token, "The portal access token is required.");
        OrganizationPage page =
                hubClient.get(portalToken, urlBuilder().path("/v1/me").build(), OrganizationPage.class);

        List<Organization> result = new ArrayList<>();
        for (OrganizationSummary entry : page.organizations()) {
            String organizationId = entry.id();
            OrganizationDetails details = getDetails(portalToken, organizationId);
            result.add(
                    new Organization(organizationId, entry.name(), environmentOptions(details), supportUris(details)));
        }
        return List.copyOf(result);
    }

    /**
     * Requests an access certificate from the EUDI Hub for the realm's OpenID4VP signing key.
     *
     * <p>The CSR is created for the public key of the signing key and signed by its private key, so
     * the private key never leaves Keycloak. The issued certificate is returned as base64 DER, the
     * form the OpenID4VP authenticator expects.
     */
    public AccessCertificateResult requestAccessCertificate(
            String token, String organizationId, String environment, String supportUri, String name) {
        String portalToken = Objects.requireNonNull(token, "The portal access token is required.");
        String certificateName = StringUtil.isBlank(name) ? "Access Certificate" : name.trim();
        KeyWrapper signingKey = getSigningKey();
        String csr = createCertificateSigningRequest(signingKey, certificateName);

        AccessCertificate created;
        try {
            created = hubClient.post(
                    portalToken,
                    accessCertificatesUri(organizationId).build(),
                    new AccessCertificateCreationRequest(certificateName, csr, environment, supportUri),
                    AccessCertificate.class);
        } catch (WebApplicationException e) {
            if (e.getResponse().getStatus() != SC_CONFLICT) {
                throw e;
            }

            logger.debug("The EUDI Hub rejected the certificate request; checking for an existing certificate.", e);

            // The EUDI Hub issues one certificate per key. When the current
            // OpenID4VP signing key already has one, retrieve that certificate
            // instead of failing the request.
            Optional<ExistingCertificate> recovered =
                    existingAccessCertificateFinder.find(portalToken, organizationId, environment, signingKey);
            if (recovered.isEmpty()) {
                throw e;
            }

            ExistingCertificate existing = recovered.get();
            AccessCertificateStatus status = existing.certificate().status();
            if (status != AccessCertificateStatus.VALID) {
                throw error(
                        SC_CONFLICT,
                        "The EUDI Hub already has a certificate for the current OpenID4VP signing key that is not valid (status: %s); rotate the signing key and request again."
                                .formatted(status == null ? null : status.value()));
            }

            logger.infof(
                    "Reusing the access certificate the EUDI Hub already issued for the OpenID4VP signing key (%s)",
                    signingKey.getKid());
            return new AccessCertificateResult(
                    Base64.getEncoder().encodeToString(existing.der()),
                    existing.certificate().name());
        }

        byte[] certificate =
                hubClient.download(portalToken, accessCertificateDownloadUri(organizationId, created.id()));
        return new AccessCertificateResult(Base64.getEncoder().encodeToString(certificate), created.name());
    }

    /** Lists access certificates for an organization in the requested environment. */
    private List<AccessCertificate> listAccessCertificates(String token, String organizationId, String environment) {
        AccessCertificatePage page = hubClient.get(
                token,
                accessCertificatesUri(organizationId)
                        .queryParam("environment", environment)
                        .queryParam("limit", 100)
                        .build(),
                AccessCertificatePage.class);
        return page.items();
    }

    /** Retrieves the Hub details for an organization. */
    private OrganizationDetails getDetails(String token, String organizationId) {
        return hubClient.get(token, organizationUri(organizationId), OrganizationDetails.class);
    }

    /** Downloads the specified access certificate for key matching or reuse. */
    private byte[] downloadAccessCertificate(String token, String organizationId, AccessCertificate certificate) {
        return hubClient.download(token, accessCertificateDownloadUri(organizationId, certificate.id()));
    }

    /** Resolves the realm's configured OpenID4VP signing key. */
    private KeyWrapper getSigningKey() {
        try {
            // The discovery service only needs the session for this lookup; DCQL
            // capabilities are irrelevant here.
            return new VerifierDiscoveryService(session, null).getSigningKey(false);
        } catch (IllegalArgumentException | IllegalStateException e) {
            logger.error("Could not get the OpenID4VP signing key.", e);
            throw error(SC_CONFLICT, e.getMessage());
        }
    }

    /** Creates a certificate signing request for the signing key and requested name. */
    private static String createCertificateSigningRequest(KeyWrapper signingKey, String name) {
        if (signingKey == null || !(signingKey.getPrivateKey() instanceof PrivateKey privateKey)) {
            throw error(SC_INTERNAL_SERVER_ERROR, "The OpenID4VP signing key has no private key.");
        }
        if (!(signingKey.getPublicKey() instanceof PublicKey publicKey)) {
            throw error(SC_INTERNAL_SERVER_ERROR, "The OpenID4VP signing key has no public key.");
        }

        try {
            return ExtendedCertificateUtils.generateCsr(privateKey, publicKey, signingKey.getAlgorithm(), name);
        } catch (RuntimeException e) {
            logger.error("Could not create the certificate signing request.", e);
            throw error(SC_INTERNAL_SERVER_ERROR, "Could not create the certificate signing request.");
        }
    }

    /** Returns the distinct support URIs reported in the organization's Hub details. */
    private static List<String> supportUris(OrganizationDetails details) {
        return details.contactInformation().supportUris().stream().distinct().toList();
    }

    /** Converts Hub environments to distinct options for the admin UI. */
    private static List<Environment> environmentOptions(OrganizationDetails details) {
        return details.environments().stream()
                .map(value -> Environment.valueOf(value.toUpperCase(Locale.ROOT)))
                .distinct()
                .toList();
    }

    private KeycloakUriBuilder urlBuilder() {
        return KeycloakUriBuilder.fromUri(baseUrl);
    }

    private URI organizationUri(String organizationId) {
        return urlBuilder().path("/v1/organizations").segment(organizationId).build();
    }

    private KeycloakUriBuilder accessCertificatesUri(String organizationId) {
        return urlBuilder().path("/v1/organizations").segment(organizationId).path("/access-certificates");
    }

    private URI accessCertificateDownloadUri(String organizationId, String certificateId) {
        return accessCertificatesUri(organizationId)
                .segment(certificateId)
                .path("/download")
                .build();
    }

    /** Extracts the title and detail from a Hub problem response, or returns a generic message. */
    static String problemDetail(String payload) {
        try {
            ProblemDetail problem = JsonSerialization.mapper.readValue(payload, ProblemDetail.class);
            if (problem != null) {
                String detail = Stream.of(problem.title(), problem.detail())
                        .filter(value -> !StringUtil.isBlank(value))
                        .collect(Collectors.joining(": "));
                if (!detail.isEmpty()) {
                    return detail;
                }
            }
        } catch (IOException e) {
            logger.warnf(e, "The EUDI Hub returned an error response that was not valid problem JSON.");
        }

        return "The EUDI Hub rejected the request.";
    }

    static WebApplicationException error(int status, String detail) {
        Response response = Response.status(status)
                .entity(new OAuth2ErrorRepresentation(OAuthErrorException.SERVER_ERROR, detail))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        return new WebApplicationException(detail, response);
    }
}
