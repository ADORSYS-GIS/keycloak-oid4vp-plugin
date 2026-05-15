package demo.lib;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

public final class Oid4vpResponseFactory {

    private Oid4vpResponseFactory() {}

    public static String describeResponseFormat(RequestObject requestObject) {
        if (requestObject.getDcqlQuery() != null) {
            return "dcql";
        }
        return "unknown";
    }

    public static Map<String, String> createResponseForm(RequestObject requestObject, String vpToken)
            throws Exception {
        Map<String, String> responseForm = new LinkedHashMap<>();

        // Prefer the final OpenID4VP vp_token object shape when DCQL is present.
        if (requestObject.getDcqlQuery() != null) {
            DcqlQuery query = requestObject.getDcqlQuery();
            Credential credential = query.getCredentials().getFirst();
            Map<String, List<String>> vpTokenMap = Map.of(credential.getId(), List.of(vpToken));
            responseForm.put(ResponseObject.VP_TOKEN_KEY, JsonSerialization.writeValueAsString(vpTokenMap));
        } else {
            throw new IllegalStateException("Request object does not contain a dcql_query");
        }

        responseForm.put(ResponseObject.STATE_KEY, requestObject.getState());
        return responseForm;
    }
}
