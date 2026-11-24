package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
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

    private final AdminPermissionEvaluator auth;
    private final EudiHubService service;

    public EudiHubAdminResource(AdminPermissionEvaluator auth, EudiHubService service) {
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

    private static Response error(Response.StatusType status, String error, String detail) {
        return Response.status(status)
                .entity(Map.of("error", error, "detail", detail))
                .build();
    }

    /** Request body of the organization lookup. */
    public record OrganizationsRequest(String token) {}
}
