package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.processing.Generated;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"field_id", "directive"})
@Generated("jsonschema2pojo")
public class IsHolder {

    /**
     * (Required)
     */
    @JsonProperty("field_id")
    private List<String> fieldId = new ArrayList<String>();
    /**
     * (Required)
     */
    @JsonProperty("directive")
    private Directive directive;

    /**
     * (Required)
     */
    @JsonProperty("field_id")
    public List<String> getFieldId() {
        return fieldId;
    }

    /**
     * (Required)
     */
    @JsonProperty("field_id")
    public void setFieldId(List<String> fieldId) {
        this.fieldId = fieldId;
    }

    /**
     * (Required)
     */
    @JsonProperty("directive")
    public Directive getDirective() {
        return directive;
    }

    /**
     * (Required)
     */
    @JsonProperty("directive")
    public void setDirective(Directive directive) {
        this.directive = directive;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(IsHolder.class.getName())
                .append('@')
                .append(Integer.toHexString(System.identityHashCode(this)))
                .append('[');
        sb.append("fieldId");
        sb.append('=');
        sb.append(((this.fieldId == null) ? "<null>" : this.fieldId));
        sb.append(',');
        sb.append("directive");
        sb.append('=');
        sb.append(((this.directive == null) ? "<null>" : this.directive));
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
        result = ((result * 31) + ((this.fieldId == null) ? 0 : this.fieldId.hashCode()));
        result = ((result * 31) + ((this.directive == null) ? 0 : this.directive.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof IsHolder) == false) {
            return false;
        }
        IsHolder rhs = ((IsHolder) other);
        return (((this.fieldId == rhs.fieldId) || ((this.fieldId != null) && this.fieldId.equals(rhs.fieldId)))
                && ((this.directive == rhs.directive)
                        || ((this.directive != null) && this.directive.equals(rhs.directive))));
    }

    @Generated("jsonschema2pojo")
    public enum Directive {
        REQUIRED("required"),
        PREFERRED("preferred");
        private static final Map<String, Directive> CONSTANTS = new HashMap<String, Directive>();

        static {
            for (Directive c : values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private final String value;

        Directive(String value) {
            this.value = value;
        }

        @JsonCreator
        public static Directive fromValue(String value) {
            Directive constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }
    }
}
