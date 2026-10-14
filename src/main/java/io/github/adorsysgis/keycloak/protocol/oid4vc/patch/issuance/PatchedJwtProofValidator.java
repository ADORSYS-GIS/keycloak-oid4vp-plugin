package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import java.util.List;
import java.util.Objects;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.issuance.keybinding.AttestationKeyResolver;
import org.keycloak.protocol.oid4vc.issuance.keybinding.JwtProofValidator;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Temporary decorator that tolerates a JWT proof whose {@code iss} claim is the Credential Issuer
 * identifier instead of the requesting {@code client_id}.
 *
 * <p>Opt-in per realm via the attribute {@code oid4vci.allow_proof_iss_mismatch} set to {@code true}.
 */
public final class PatchedJwtProofValidator extends JwtProofValidator {

    private static final Logger logger = Logger.getLogger(PatchedJwtProofValidator.class);

    public static final String ATTR_ALLOW_PROOF_ISS_MISMATCH = "oid4vci.allow_proof_iss_mismatch";

    private final KeycloakSession session;

    public PatchedJwtProofValidator(KeycloakSession session, AttestationKeyResolver keyResolver) {
        super(session, keyResolver);
        this.session = session;
    }

    @Override
    public List<JWK> validateProof(VCIssuanceContext vcIssuanceContext) throws VCIssuerException {
        String proofIssuer = extractProofIssuer(vcIssuanceContext);
        AccessToken token = authToken(vcIssuanceContext);
        String originalIssuedFor = token == null ? null : token.getIssuedFor();

        if (StringUtil.isNotBlank(proofIssuer)
                && StringUtil.isNotBlank(originalIssuedFor)
                && isCredentialIssuer(proofIssuer)
                && !Objects.equals(proofIssuer, originalIssuedFor)
                && issuerMismatchAllowed()) {
            token.issuedFor(proofIssuer);
        }

        try {
            return super.validateProof(vcIssuanceContext);
        } finally {
            if (token != null) {
                token.issuedFor(originalIssuedFor);
            }
        }
    }

    private AccessToken authToken(VCIssuanceContext vcIssuanceContext) {
        var authResult = vcIssuanceContext.getAuthResult();
        return authResult != null ? authResult.token() : null;
    }

    private boolean isCredentialIssuer(String proofIssuer) {
        return proofIssuer.equals(OID4VCIssuerWellKnownProvider.getIssuer(session.getContext()));
    }

    private boolean issuerMismatchAllowed() {
        RealmModel realm = session.getContext().getRealm();
        return realm != null && Boolean.parseBoolean(realm.getAttribute(ATTR_ALLOW_PROOF_ISS_MISMATCH));
    }

    private String extractProofIssuer(VCIssuanceContext vcIssuanceContext) {
        CredentialRequest request = vcIssuanceContext.getCredentialRequest();
        if (request == null
                || request.getProofs() == null
                || request.getProofs().getJwt() == null
                || request.getProofs().getJwt().isEmpty()) {
            return null;
        }
        try {
            String issuer = null;
            for (String jwt : request.getProofs().getJwt()) {
                // It is assumed all proofs carry the same "iss" value. If not the case,
                // null is returned for upstream validator to fail naturally.
                JWSInput jwsInput = new JWSInput(jwt);
                AccessToken payload = JsonSerialization.readValue(jwsInput.getContent(), AccessToken.class);
                if (issuer == null) {
                    issuer = payload.getIssuer();
                } else if (!Objects.equals(issuer, payload.getIssuer())) {
                    return null;
                }
            }
            return issuer;
        } catch (Exception e) {
            logger.errorf(e, "Could not extract proof issuer");
            return null;
        }
    }
}
