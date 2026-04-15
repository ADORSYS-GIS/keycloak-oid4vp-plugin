package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationSubmission;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Response object payload for OpenID4VP Authorization Response.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-response-parameters">
 * Response</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseObject {

    public static final String VP_TOKEN_KEY = "vp_token";
    public static final String PRESENTATION_SUBMISSION_KEY = "presentation_submission";
    public static final String STATE_KEY = "state";

    // This field is a String in Draft 20, and a Map<String, List<String>> in 1.0 final.
    // We use Object here to support both formats for now.
    @JsonProperty(VP_TOKEN_KEY)
    @JsonDeserialize(using = VpTokenDeserializer.class)
    private Object vpToken;

    @JsonProperty(PRESENTATION_SUBMISSION_KEY)
    @JsonDeserialize(using = PresentationSubmissionDeserializer.class)
    @Deprecated
    private PresentationSubmission presentationSubmission;

    @JsonProperty(STATE_KEY)
    private String state;

    ResponseObject() {}

    public ResponseObject(String vpToken, String presentationSubmission, String state) throws JsonProcessingException {
        this.vpToken = parseVpToken(vpToken);
        this.presentationSubmission = parsePresentationSubmission(presentationSubmission);
        this.state = state;
    }

    private static Object parseVpToken(String vpToken) throws JsonProcessingException {
        if (StringUtil.isBlank(vpToken)) {
            throw new IllegalArgumentException("vp_token must not be null or blank");
        }

        if (vpToken.trim().startsWith("{")) {
            return JsonSerialization.mapper.readValue(vpToken, new TypeReference<Map<String, List<String>>>() {});
        } else {
            return vpToken;
        }
    }

    public static PresentationSubmission parsePresentationSubmission(String presentationSubmission)
            throws JsonProcessingException {
        if (StringUtil.isBlank(presentationSubmission)) {
            return null;
        }

        return JsonSerialization.mapper.readValue(presentationSubmission, PresentationSubmission.class);
    }

    public Object getVpToken() {
        return vpToken;
    }

    public ResponseObject setVpToken(Object vpToken) {
        this.vpToken = vpToken;
        return this;
    }

    public PresentationSubmission getPresentationSubmission() {
        return presentationSubmission;
    }

    public ResponseObject setPresentationSubmission(PresentationSubmission presentationSubmission) {
        this.presentationSubmission = presentationSubmission;
        return this;
    }

    public String getState() {
        return state;
    }

    public ResponseObject setState(String state) {
        this.state = state;
        return this;
    }

    private static class VpTokenDeserializer extends JsonDeserializer<Object> {

        @Override
        public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            String raw = getValueAsString(p);
            return parseVpToken(raw);
        }
    }

    private static class PresentationSubmissionDeserializer extends JsonDeserializer<Object> {

        @Override
        public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            String raw = getValueAsString(p);
            return parsePresentationSubmission(raw);
        }
    }

    private static String getValueAsString(JsonParser p) throws IOException {
        JsonNode node = p.readValueAsTree();
        return node.isTextual() ? node.asText() : JsonSerialization.writeValueAsString(node);
    }
}
