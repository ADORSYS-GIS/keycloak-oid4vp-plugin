package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class CredentialSet {

    @JsonProperty("required")
    private Boolean required;

    @JsonProperty("options")
    private List<List<String>> options;

    public Boolean getRequired() {
        return required;
    }

    public void setRequired(Boolean required) {
        this.required = required;
    }

    public List<List<String>> getOptions() {
        return options;
    }

    public void setOptions(List<List<String>> options) {
        this.options = options;
    }
}
