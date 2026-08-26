package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

/**
 * Session data of a presentation-during-issuance authorization. Groups the attributes that describe
 * how an authorization serves credential issuance.
 *
 * @param mode          the presentation-during-issuance mode through which authorization was started
 * @param subjectUserId id of the brokered user the credential offer is bound to
 * @param responseUri   override the default URI to which the wallet posts its OpenID4VP response
 */
public record PresentationDuringIssuanceSession(
        PresentationDuringIssuanceMode mode, String subjectUserId, String responseUri) {

    /**
     * Whether this authorization serves the OID4VCI interactive authorization (ia_post) flow, where
     * the OpenID4VP Authorization Response is submitted back to the Authorization Challenge Endpoint.
     */
    public boolean isInteractive() {
        return mode == PresentationDuringIssuanceMode.INTERACTIVE_AUTHORIZATION;
    }
}
