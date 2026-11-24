package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/**
 * Realm admin sub-resource at {@code /admin/realms/{realm}/eudi-hub}.
 *
 * <p>The admin console calls this endpoint instead of the EUDI Hub directly, because the EUDI Hub
 * only allows its own portal origin through CORS. The portal access token is sent in the request
 * body and used only for the upstream request.
 */
public class EudiHubAdminResource {

    private static final Logger logger = Logger.getLogger(EudiHubAdminResource.class);

    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final EudiHubService service;

    public EudiHubAdminResource(RealmModel realm, AdminPermissionEvaluator auth, EudiHubService service) {
        this.realm = realm;
        this.auth = auth;
        this.service = service;
    }

    @POST
    @Path("organizations")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response organizations(OrganizationsRequest request) {
        auth.realm().requireViewRealm();

        if (request == null || request.token() == null || request.token().isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "The portal access token is required.");
        }

        try {
            List<EudiHubService.Organization> organizations = service.listOrganizations(request.token());
            return Response.ok(Map.of("organizations", organizations)).build();
        } catch (EudiHubService.EudiHubException e) {
            logger.warnf("EUDI Hub organization lookup failed: %s", e.getMessage());
            Response.Status status = Response.Status.fromStatusCode(e.getStatus());
            return error(status != null ? status : Response.Status.BAD_GATEWAY, "eudi_hub_error", e.getMessage());
        } catch (IllegalArgumentException e) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", e.getMessage());
        }
    }

    @POST
    @Path("access-certificate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response accessCertificate(AccessCertificateRequest request) {
        auth.realm().requireManageRealm();

        if (request == null || request.token() == null || request.token().isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "The portal access token is required.");
        }
        if (request.organizationId() == null || request.organizationId().isBlank()) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", "The organization ID is required.");
        }

        try {
            String certificate = service.requestAccessCertificate(
                    request.token(), request.organizationId(), request.environment(), request.name());
            configureAccessCertificate(certificate);
            return Response.ok(Map.of("accessCertificate", certificate)).build();
        } catch (EudiHubService.EudiHubException e) {
            logger.warnf("EUDI Hub access certificate request failed: %s", e.getMessage());
            Response.Status status = Response.Status.fromStatusCode(e.getStatus());
            return error(status != null ? status : Response.Status.BAD_GATEWAY, "eudi_hub_error", e.getMessage());
        } catch (IllegalArgumentException e) {
            return error(Response.Status.BAD_REQUEST, "invalid_request", e.getMessage());
        }
    }

    /**
     * Overrides the {@code accessCertificate} of the OpenID4VP authenticator in the realm's
     * {@code oid4vp auth} flow. The authenticator must already have a configuration; a realm
     * without one is reported as a conflict instead of being changed.
     */
    private void configureAccessCertificate(String certificate) throws EudiHubService.EudiHubException {
        AuthenticationFlowModel flow = realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW);
        if (flow == null) {
            throw new EudiHubService.EudiHubException(409, "The realm has no 'oid4vp auth' flow.");
        }

        AuthenticationExecutionModel execution = realm.getAuthenticationExecutionsStream(flow.getId())
                .filter(candidate -> OID4VPAuthenticatorFactory.PROVIDER_ID.equals(candidate.getAuthenticator()))
                .findFirst()
                .orElseThrow(() -> new EudiHubService.EudiHubException(
                        409, "The 'oid4vp auth' flow has no OpenID4VP authenticator."));

        AuthenticatorConfigModel config = execution.getAuthenticatorConfig() == null
                ? null
                : realm.getAuthenticatorConfigById(execution.getAuthenticatorConfig());
        if (config == null) {
            throw new EudiHubService.EudiHubException(
                    409, "The OpenID4VP authenticator has no configuration to store the certificate in.");
        }

        Map<String, String> updated = new LinkedHashMap<>();
        if (config.getConfig() != null) {
            updated.putAll(config.getConfig());
        }
        updated.put(OID4VPAuthenticatorFactory.ACCESS_CERTIFICATE_CONFIG, certificate);
        config.setConfig(updated);
        realm.updateAuthenticatorConfig(config);
    }

    private static Response error(Response.StatusType status, String error, String detail) {
        return Response.status(status)
                .entity(Map.of("error", error, "detail", detail))
                .build();
    }

    /** Request body of the organization lookup. */
    public record OrganizationsRequest(String token) {}

    /** Request body of the access certificate request. */
    public record AccessCertificateRequest(String token, String organizationId, String environment, String name) {}
}
