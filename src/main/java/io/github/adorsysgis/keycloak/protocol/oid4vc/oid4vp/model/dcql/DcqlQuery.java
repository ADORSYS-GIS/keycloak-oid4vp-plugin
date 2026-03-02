package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class DcqlQuery {

    @JsonProperty("credentials")
    private List<Credential> credentials;

    @JsonProperty("credential_sets")
    private List<CredentialSet> credentialSets;

    public List<Credential> getCredentials() {
        return credentials;
    }

    public void setCredentials(List<Credential> credentials) {
        this.credentials = credentials;
    }

    public List<CredentialSet> getCredentialSets() {
        return credentialSets;
    }

    public void setCredentialSets(List<CredentialSet> credentialSets) {
        this.credentialSets = credentialSets;
    }
}
