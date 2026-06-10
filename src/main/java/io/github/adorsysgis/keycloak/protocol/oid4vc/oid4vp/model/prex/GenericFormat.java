package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"alg_values"})
@Generated("jsonschema2pojo")
public class GenericFormat {

    @JsonProperty("alg_values")
    private List<String> algValues = new ArrayList<String>();

    @JsonProperty("alg_values")
    public List<String> getAlgValues() {
        return algValues;
    }

    @JsonProperty("alg_values")
    public void setAlgValues(List<String> algValues) {
        this.algValues = algValues;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(GenericFormat.class.getName())
                .append('@')
                .append(Integer.toHexString(System.identityHashCode(this)))
                .append('[');
        sb.append("algValues");
        sb.append('=');
        sb.append(((this.algValues == null) ? "<null>" : this.algValues));
        sb.append(',');
        if (sb.charAt((sb.length() - 1)) == ',') {
            sb.setCharAt((sb.length() - 1), ']');
        } else {
            sb.append(']');
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = ((result * 31) + ((this.algValues == null) ? 0 : this.algValues.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof GenericFormat) == false) {
            return false;
        }
        GenericFormat rhs = ((GenericFormat) other);
        return ((this.algValues == rhs.algValues)
                || ((this.algValues != null) && this.algValues.equals(rhs.algValues)));
    }
}
