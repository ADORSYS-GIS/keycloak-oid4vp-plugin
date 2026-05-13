package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
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

    private Map<String, List<String>> vpToken;

    @JsonProperty(STATE_KEY)
    private String state;

    ResponseObject() {}

    public ResponseObject(String vpToken, String state) throws JsonProcessingException {
        this.vpToken = readVpToken(vpToken);
        this.state = state;
    }

    private static Map<String, List<String>> readVpToken(String vpToken) throws JsonProcessingException {
        if (StringUtil.isBlank(vpToken)) {
            throw new IllegalArgumentException("vp_token must not be null or blank");
        }

        return parseVpToken(JsonSerialization.mapper.readTree(vpToken));
    }

    private static Map<String, List<String>> parseVpToken(JsonNode vpToken) {
        if (vpToken == null || !vpToken.isObject()) {
            throw new IllegalArgumentException("vp_token must be a JSON object keyed by DCQL credential query IDs");
        }

        Map<String, List<String>> result = new LinkedHashMap<>();
        vpToken.properties().forEach(entry -> {
            JsonNode presentations = entry.getValue();
            if (!presentations.isArray()) {
                throw new IllegalArgumentException(
                        "vp_token entry `%s` must be an array of presentations".formatted(entry.getKey()));
            }

            List<String> presentationStrings = new ArrayList<>();
            presentations.forEach(presentation -> {
                if (!presentation.isTextual()) {
                    throw new IllegalArgumentException(
                            "vp_token entry `%s` must contain string presentations".formatted(entry.getKey()));
                }
                presentationStrings.add(presentation.asText());
            });
            result.put(entry.getKey(), List.copyOf(presentationStrings));
        });
        return Collections.unmodifiableMap(result);
    }

    @JsonProperty(VP_TOKEN_KEY)
    public Map<String, List<String>> getVpToken() {
        return vpToken;
    }

    @JsonProperty(VP_TOKEN_KEY)
    public void setVpToken(JsonNode vpToken) {
        this.vpToken = parseVpToken(vpToken);
    }

    public String getState() {
        return state;
    }

    public ResponseObject setState(String state) {
        this.state = state;
        return this;
    }
}
