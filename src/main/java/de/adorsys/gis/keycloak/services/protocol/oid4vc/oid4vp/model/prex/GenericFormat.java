package de.adorsys.gis.keycloak.services.protocol.oid4vc.oid4vp.model.prex;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import javax.annotation.processing.Generated;
import java.util.ArrayList;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"alg"})
@Generated("jsonschema2pojo")
public class GenericFormat {

    @JsonProperty("alg")
    private List<String> alg = new ArrayList<String>();

    @JsonProperty("alg")
    public List<String> getAlg() {
        return alg;
    }

    @JsonProperty("alg")
    public void setAlg(List<String> alg) {
        this.alg = alg;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(GenericFormat.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("alg");
        sb.append('=');
        sb.append(((this.alg == null) ? "<null>" : this.alg));
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
        result = ((result * 31) + ((this.alg == null) ? 0 : this.alg.hashCode()));
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
        return ((this.alg == rhs.alg) || ((this.alg != null) && this.alg.equals(rhs.alg)));
    }

}
