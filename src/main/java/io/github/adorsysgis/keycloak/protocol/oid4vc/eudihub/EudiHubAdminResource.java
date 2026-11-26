package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.AccessCertificateRequest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.AccessCertificateResult;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.OrganizationsRequest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.OrganizationsResponse;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.utils.StringUtil;

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
        if (request == null) {
            throw badRequest("The request body is required.");
        }
        if (StringUtil.isBlank(request.token())) {
            throw badRequest("The portal access token is required.");
        }
        return Response.ok(new OrganizationsResponse(service.listOrganizations(request.token())))
                .build();
    }

    @POST
    @Path("access-certificate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response accessCertificate(AccessCertificateRequest request) {
        auth.realm().requireManageRealm();
        if (request == null) {
            throw badRequest("The request body is required.");
        }
        if (StringUtil.isBlank(request.token())) {
            throw badRequest("The portal access token is required.");
        }
        if (StringUtil.isBlank(request.organizationId())) {
            throw badRequest("The organization ID is required.");
        }

        logger.debugf(
                "Requesting EUDI Hub access certificate for organization %s in the %s environment",
                request.organizationId(), request.environment());

        AccessCertificateResult result;
        try {
            result = service.requestAccessCertificate(
                    request.token(),
                    request.organizationId(),
                    request.environment(),
                    request.supportUri(),
                    request.name());
        } catch (IllegalArgumentException e) {
            throw badRequest(e.getMessage(), e);
        }

        logger.debug("EUDI Hub returned an access certificate; storing it in the OpenID4VP authenticator");
        configureAccessCertificate(result.accessCertificate());

        return Response.ok(result).build();
    }

    /**
     * Overrides the {@code accessCertificate} of the OpenID4VP authenticator in the realm's
     * {@code oid4vp auth} flow, creating and attaching an authenticator configuration when needed.
     */
    private void configureAccessCertificate(String certificate) {
        AuthenticationFlowModel flow = realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW);
        if (flow == null) {
            throw new WebApplicationException(error(
                    Response.Status.CONFLICT,
                    OAuthErrorException.SERVER_ERROR,
                    "The realm has no 'oid4vp auth' flow."));
        }

        AuthenticationExecutionModel execution = realm.getAuthenticationExecutionsStream(flow.getId())
                .filter(candidate -> OID4VPAuthenticatorFactory.PROVIDER_ID.equals(candidate.getAuthenticator()))
                .findFirst()
                .orElseThrow(() -> new WebApplicationException(error(
                        Response.Status.CONFLICT,
                        OAuthErrorException.SERVER_ERROR,
                        "The 'oid4vp auth' flow has no OpenID4VP authenticator.")));

        AuthenticatorConfigModel config = Optional.ofNullable(execution.getAuthenticatorConfig())
                .map(realm::getAuthenticatorConfigById)
                .orElse(null);

        if (config == null) {
            config = new AuthenticatorConfigModel();
            config.setAlias("OpenID4VP Authenticator Config (%s)".formatted(execution.getId()));
            config.setConfig(new LinkedHashMap<>());
            config = realm.addAuthenticatorConfig(config);

            execution.setAuthenticatorConfig(config.getId());
            realm.updateAuthenticatorExecution(execution);
        }

        Map<String, String> updated = new LinkedHashMap<>();
        if (config.getConfig() != null) {
            updated.putAll(config.getConfig());
        }

        updated.put(OID4VPAuthenticatorFactory.ACCESS_CERTIFICATE_CONFIG, certificate);
        config.setConfig(updated);
        realm.updateAuthenticatorConfig(config);
    }

    private static BadRequestException badRequest(String description) {
        return new BadRequestException(
                error(Response.Status.BAD_REQUEST, OAuthErrorException.INVALID_REQUEST, description));
    }

    private static BadRequestException badRequest(String description, Throwable cause) {
        return new BadRequestException(
                error(Response.Status.BAD_REQUEST, OAuthErrorException.INVALID_REQUEST, description), cause);
    }

    private static Response error(Response.Status status, String error, String detail) {
        return Response.status(status)
                .entity(new OAuth2ErrorRepresentation(error, detail))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }
}
