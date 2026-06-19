package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class Claim {

    @JsonProperty("id")
    private String id;

    /**
     * Object-key path segments (e.g. {@code credentialSubject}, {@code given_name}, {@code street_address}).
     * Nested paths such as {@code ["address", "street_address"]} use multiple string segments.
     */
    @JsonProperty("path")
    private List<String> path;

    @JsonProperty("values")
    private List<String> values;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<String> getPath() {
        return path;
    }

    public void setPath(List<String> path) {
        this.path = path;
    }

    public List<String> getValues() {
        return values;
    }

    public void setValues(List<String> values) {
        this.values = values;
    }
}
