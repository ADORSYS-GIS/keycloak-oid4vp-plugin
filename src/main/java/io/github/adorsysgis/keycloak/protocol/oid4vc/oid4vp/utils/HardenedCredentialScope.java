package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.utils.StringUtil;

/**
 * Hardened {@link CredentialScopeModel} for an OID4VCI credential configuration that centralizes the
 * "presentation during issuance" policy.
 *
 * <p>The {@value #VC_REQUIRES_PRESENTATION_ATTR} client-scope attribute is the single authority for
 * whether, and via which {@link PresentationDuringIssuanceMode mode(s)}, a credential requires a
 * Verifiable Presentation prior to issuance. Its value may be:
 * <ul>
 *   <li>a legacy boolean ({@code true}/{@code false}, case-insensitive) — a {@code true} means
 *       every {@link PresentationDuringIssuanceMode mode} is supported;</li>
 *   <li>a comma/whitespace-separated list of {@link PresentationDuringIssuanceMode#wireValue wire
 *       values}, e.g. {@code interactive_authorization} or
 *       {@code interactive_authorization,nested_oid4vp_flow}.</li>
 * </ul>
 */
public class HardenedCredentialScope extends CredentialScopeModel {

    /**
     * Credential-configuration (client-scope) attribute declaring whether the credential requires a
     * Verifiable Presentation prior to issuance, and which {@link PresentationDuringIssuanceMode
     * mode(s)} are supported (legacy boolean or mode list).
     */
    public static final String VC_REQUIRES_PRESENTATION_ATTR = "vc.requires_presentation";

    /**
     * Credential-configuration (client-scope) attribute naming the OpenID4VP authentication profile that
     * MUST be enforced when a presentation is requested during issuance of this credential.
     */
    public static final String VC_PRESENTATION_PROFILE_ID_ATTR = "vc.presentation_profile_id";

    /** Boolean literals accepted for the legacy {@code vc.requires_presentation} value. */
    private static final EnumSet<PresentationDuringIssuanceMode> ALL_MODES =
            EnumSet.allOf(PresentationDuringIssuanceMode.class);

    /**
     * Decorates the underlying {@code ClientScopeModel} with the presentation during issuance policy.
     * A {@link CredentialScopeModel} is also a {@link ClientScopeModel}, so a credential configuration
     * can be re-decorated directly.
     */
    public HardenedCredentialScope(ClientScopeModel clientScope) {
        super(clientScope);
    }

    /** Decorates a credential configuration, or returns {@code null} when the scope is {@code null}. */
    public static HardenedCredentialScope from(CredentialScopeModel credentialScope) {
        return credentialScope == null ? null : new HardenedCredentialScope(credentialScope);
    }

    /**
     * Whether the credential requires a Verifiable Presentation prior to issuance.
     */
    public boolean requiresPresentation() {
        String value = getAttribute(VC_REQUIRES_PRESENTATION_ATTR);
        return Boolean.parseBoolean(value) || !parsePresentationModes(value).isEmpty();
    }

    /**
     * Whether this credential supports the given presentation during issuance {@code mode}.
     *
     * <p>The {@code nested_oid4vp_flow} mode is supported only when the credential's
     * {@code vc.requires_presentation} explicitly lists it (or the legacy boolean {@code true}).
     * The {@code interactive_authorization} mode is supported when explicitly listed, or — as a
     * backward-compatible fallback for scopes that predate the mode list — when the credential
     * carries a {@code vc.presentation_profile_id} (the historical enabling condition of the
     * Authorization Challenge Endpoint), even if presentation is not hard-required.
     */
    public boolean supportsPresentationMode(PresentationDuringIssuanceMode mode) {
        if (mode == null) {
            return false;
        }
        String value = getAttribute(VC_REQUIRES_PRESENTATION_ATTR);
        Set<PresentationDuringIssuanceMode> explicit = parsePresentationModes(value);
        if (explicit.contains(mode)) {
            return true;
        }
        if (mode == PresentationDuringIssuanceMode.INTERACTIVE_AUTHORIZATION
                && explicit.isEmpty()
                && StringUtil.isNotBlank(getAttribute(VC_PRESENTATION_PROFILE_ID_ATTR))) {
            return true;
        }
        return false;
    }

    /**
     * The OpenID4VP authentication profile enforced when presenting during issuance of this
     * credential, or {@code null} when none is configured.
     */
    public String presentationProfileId() {
        String profileId = getAttribute(VC_PRESENTATION_PROFILE_ID_ATTR);
        return StringUtil.isBlank(profileId) ? null : profileId;
    }

    /**
     * Parses a {@code vc.requires_presentation} attribute value into the set of supported
     * {@link PresentationDuringIssuanceMode modes}. A legacy boolean {@code true} maps to every mode; a
     * mode list maps to exactly the listed modes; a blank value or boolean {@code false} maps to an
     * empty set.
     */
    public static Set<PresentationDuringIssuanceMode> parsePresentationModes(String attributeValue) {
        if (StringUtil.isBlank(attributeValue)) {
            return Collections.emptySet();
        }
        if ("true".equalsIgnoreCase(attributeValue.trim())) {
            return ALL_MODES;
        }
        if ("false".equalsIgnoreCase(attributeValue.trim())) {
            return Collections.emptySet();
        }
        Set<PresentationDuringIssuanceMode> modes = EnumSet.noneOf(PresentationDuringIssuanceMode.class);
        for (String token : attributeValue.split("[,\\s]+")) {
            PresentationDuringIssuanceMode mode = PresentationDuringIssuanceMode.fromWireValue(token);
            if (mode != null) {
                modes.add(mode);
            }
        }
        return Collections.unmodifiableSet(modes);
    }
}
