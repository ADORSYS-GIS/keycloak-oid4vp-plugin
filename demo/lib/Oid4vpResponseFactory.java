package demo.lib;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Descriptor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.InputDescriptor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationSubmission;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.keycloak.util.JsonSerialization;

public final class Oid4vpResponseFactory {

    private Oid4vpResponseFactory() {}

    public static String describeResponseFormat(RequestObject requestObject) {
        if (requestObject.getPresentationDefinition() != null) {
            return "presentation-exchange";
        }
        if (requestObject.getDcqlQuery() != null) {
            return "dcql";
        }
        return "unknown";
    }

    public static Map<String, String> createResponseForm(RequestObject requestObject, String vpToken)
            throws Exception {
        Map<String, String> responseForm = new LinkedHashMap<>();

        // The plugin accepts either the older Presentation Exchange shape or the newer DCQL shape.
        // The demo mirrors whichever format Keycloak requested so the wallet stays compatible with both.
        if (requestObject.getPresentationDefinition() != null) {
            PresentationSubmission submission =
                    buildPresentationSubmission(requestObject.getPresentationDefinition());
            responseForm.put(ResponseObject.VP_TOKEN_KEY, vpToken);
            responseForm.put(
                    ResponseObject.PRESENTATION_SUBMISSION_KEY, JsonSerialization.writeValueAsString(submission));
        } else if (requestObject.getDcqlQuery() != null) {
            DcqlQuery query = requestObject.getDcqlQuery();
            Credential credential = query.getCredentials().getFirst();
            Map<String, List<String>> vpTokenMap = Map.of(credential.getId(), List.of(vpToken));
            responseForm.put(ResponseObject.VP_TOKEN_KEY, JsonSerialization.writeValueAsString(vpTokenMap));
        } else {
            throw new IllegalStateException(
                    "Request object contains neither presentation_definition nor dcql_query");
        }

        responseForm.put(ResponseObject.STATE_KEY, requestObject.getState());
        return responseForm;
    }

    private static PresentationSubmission buildPresentationSubmission(PresentationDefinition definition) {
        InputDescriptor inputDescriptor = definition.getInputDescriptors().getFirst();

        PresentationSubmission submission = new PresentationSubmission();
        submission.setId(UUID.randomUUID().toString());
        submission.setDefinitionId(definition.getId());

        Descriptor descriptor = new Descriptor();
        descriptor.setId(inputDescriptor.getId());
        descriptor.setFormat(Descriptor.Format.VC_SD_JWT);
        descriptor.setPath("$");
        submission.setDescriptorMap(List.of(descriptor));

        return submission;
    }
}
