package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationSubmission;
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
    private Object vpToken;

    @JsonProperty(PRESENTATION_SUBMISSION_KEY)
    @Deprecated
    private PresentationSubmission presentationSubmission;

    @JsonProperty(STATE_KEY)
    private String state;

    public ResponseObject(String vpToken, String presentationSubmission, String state) throws JsonProcessingException {
        this.vpToken = parseVpToken(requireNonBlank(vpToken, VP_TOKEN_KEY));
        this.presentationSubmission = parsePresentationSubmission(presentationSubmission);
        this.state = requireNonBlank(state, STATE_KEY);
    }

    private static String requireNonBlank(String value, String fieldName) {
        if (StringUtil.isBlank(value)) {
            throw new IllegalArgumentException(fieldName + " must not be null or blank");
        }

        return value;
    }

    public static Object parseVpToken(String vpToken) throws JsonProcessingException {
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
}
