package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class Meta {

    @JsonProperty("doctype_value")
    private String doctypeValue;

    @JsonProperty("vct_values")
    private List<String> vctValues;

    @JsonProperty("type_values")
    private List<List<String>> typeValues;

    public String getDoctypeValue() {
        return doctypeValue;
    }

    public void setDoctypeValue(String doctypeValue) {
        this.doctypeValue = doctypeValue;
    }

    public List<String> getVctValues() {
        return vctValues;
    }

    public void setVctValues(List<String> vctValues) {
        this.vctValues = vctValues;
    }

    public List<List<String>> getTypeValues() {
        return typeValues;
    }

    public void setTypeValues(List<List<String>> typeValues) {
        this.typeValues = typeValues;
    }
}
