package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.util.JsonSerialization;

/**
 * Value stored in the user-session note that records a successfully verified presentation during
 * issuance. It binds the {@link PresentationDuringIssuanceMode} through which the presentation was
 * obtained to the concrete OpenID4VP authentication profile that was used, so the issuance gate can
 * verify the proof against the specific credential configuration.
 *
 * @param mode the {@link PresentationDuringIssuanceMode} value
 * @param profileId the OpenID4VP authentication profile id used
 */
public record PresentationVerifiedNote(
        @JsonProperty("mode") String mode,
        @JsonProperty("profileId") String profileId) {

    public static PresentationVerifiedNote of(PresentationDuringIssuanceMode mode, String profileId) {
        return new PresentationVerifiedNote(mode.getValue(), profileId);
    }

    public String toJson() {
        return JsonSerialization.valueAsString(this);
    }

    public static PresentationVerifiedNote fromJson(String json) {
        return JsonSerialization.valueFromString(json, PresentationVerifiedNote.class);
    }
}
