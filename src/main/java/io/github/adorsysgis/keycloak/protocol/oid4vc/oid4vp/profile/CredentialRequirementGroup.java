package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class CredentialRequirementGroup {

    @JsonProperty("id")
    private String id;

    @JsonProperty("required")
    private Boolean required = Boolean.TRUE;

    @JsonProperty("options")
    private List<List<String>> options;

    public String getId() {
        return id;
    }

    public CredentialRequirementGroup setId(String id) {
        this.id = id;
        return this;
    }

    public Boolean getRequired() {
        return required;
    }

    public CredentialRequirementGroup setRequired(Boolean required) {
        this.required = required;
        return this;
    }

    public boolean isRequired() {
        return !Boolean.FALSE.equals(required);
    }

    public List<List<String>> getOptions() {
        return options;
    }

    public CredentialRequirementGroup setOptions(List<List<String>> options) {
        this.options = options;
        return this;
    }
}
