package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class Claim {

    @JsonProperty("id")
    private String id;

    /**
     * Object-key path segments only (e.g. {@code credentialSubject}, {@code given_name}). Does not
     * support {@code null} array wildcards or integer indexes from OpenID4VP Claims Path Pointers.
     */
    @JsonProperty("path")
    private List<Object> path;

    @JsonProperty("values")
    private List<Object> values;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<Object> getPath() {
        return path;
    }

    public void setPath(List<Object> path) {
        this.path = path;
    }

    public List<Object> getValues() {
        return values;
    }

    public void setValues(List<Object> values) {
        this.values = values;
    }
}
