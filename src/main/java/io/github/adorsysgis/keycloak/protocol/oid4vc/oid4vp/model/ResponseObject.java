package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import java.util.List;
import java.util.Map;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Response object payload for OpenID4VP Authorization Response.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-parameters">
 * Response</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseObject {

    public static final String VP_TOKEN_KEY = "vp_token";
    public static final String STATE_KEY = "state";

    @JsonProperty(VP_TOKEN_KEY)
    private Map<String, List<String>> vpToken;

    @JsonProperty(STATE_KEY)
    private String state;

    ResponseObject() {}

    public ResponseObject(String vpToken, String state) throws JsonProcessingException {
        this.vpToken = parseVpToken(vpToken);
        this.state = state;
    }

    private static Map<String, List<String>> parseVpToken(String vpToken) throws JsonProcessingException {
        if (StringUtil.isBlank(vpToken)) {
            throw new IllegalArgumentException("vp_token must not be null or blank");
        }

        return JsonSerialization.mapper.readValue(vpToken, new TypeReference<Map<String, List<String>>>() {});
    }

    public Map<String, List<String>> getVpToken() {
        return vpToken;
    }

    public ResponseObject setVpToken(Map<String, List<String>> vpToken) {
        this.vpToken = vpToken;
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
