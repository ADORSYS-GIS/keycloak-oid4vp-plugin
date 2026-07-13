package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * VP format metadata for {@code mso_mdoc} credentials per OpenID4VP Final 1.0 Appendix B.2.2.
 *
 * <p>Carries COSE algorithm identifiers for issuer authentication and device authentication.
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder({"issuerauth_alg_values", "deviceauth_alg_values"})
public class MdocGenericFormat {

    @JsonProperty("issuerauth_alg_values")
    private List<Integer> issuerAuthAlgValues = new ArrayList<>();

    @JsonProperty("deviceauth_alg_values")
    private List<Integer> deviceAuthAlgValues = new ArrayList<>();

    public List<Integer> getIssuerAuthAlgValues() {
        return issuerAuthAlgValues;
    }

    public void setIssuerAuthAlgValues(List<Integer> issuerAuthAlgValues) {
        this.issuerAuthAlgValues = issuerAuthAlgValues;
    }

    public List<Integer> getDeviceAuthAlgValues() {
        return deviceAuthAlgValues;
    }

    public void setDeviceAuthAlgValues(List<Integer> deviceAuthAlgValues) {
        this.deviceAuthAlgValues = deviceAuthAlgValues;
    }

    @Override
    public String toString() {
        return "MdocGenericFormat{" + "issuerAuthAlgValues="
                + issuerAuthAlgValues + ", deviceAuthAlgValues="
                + deviceAuthAlgValues + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        MdocGenericFormat that = (MdocGenericFormat) o;
        return Objects.equals(getIssuerAuthAlgValues(), that.getIssuerAuthAlgValues())
                && Objects.equals(getDeviceAuthAlgValues(), that.getDeviceAuthAlgValues());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getIssuerAuthAlgValues(), getDeviceAuthAlgValues());
    }
}
