package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationSubmission;
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

    @JsonProperty(VP_TOKEN_KEY)
    private String vpToken;

    @JsonProperty(PRESENTATION_SUBMISSION_KEY)
    private PresentationSubmission presentationSubmission;

    @JsonProperty(STATE_KEY)
    private String state;

    public ResponseObject() {}

    public ResponseObject(String vpToken, String presentationSubmission, String state) throws JsonProcessingException {
        this.vpToken = requireNonBlank(vpToken, VP_TOKEN_KEY);
        this.presentationSubmission = JsonSerialization.mapper.readValue(
                requireNonBlank(presentationSubmission, PRESENTATION_SUBMISSION_KEY), PresentationSubmission.class);
        this.state = requireNonBlank(state, STATE_KEY);
    }

    private static String requireNonBlank(String value, String fieldName) {
        if (StringUtil.isBlank(value)) {
            throw new IllegalArgumentException(fieldName + " must not be null or blank");
        }

        return value;
    }

    public String getVpToken() {
        return vpToken;
    }

    public ResponseObject setVpToken(String vpToken) {
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
