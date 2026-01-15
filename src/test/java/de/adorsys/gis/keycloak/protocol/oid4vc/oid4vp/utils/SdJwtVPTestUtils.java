package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.utils;

import com.fasterxml.jackson.databind.node.ObjectNode;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory;
import de.adorsys.gis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Objects;

import static de.adorsys.gis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_FIELD;
import static de.adorsys.gis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_LIST_FIELD;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_CNF;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_EXP;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_JWK;

/**
 * Test helper for crafting SD-JWT verifiable presentations.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtVPTestUtils {

    public static final int ISSUER_SIGNED_JWT_LIFESPAN_SECS = 300;
    public static final int KB_JWT_LIFESPAN_SECS = 60;

    private final KeycloakContainer keycloak;
    private final String activeTestRealm;

    public SdJwtVPTestUtils(KeycloakContainer keycloak, String activeTestRealm) {
        this.keycloak = keycloak;
        this.activeTestRealm = activeTestRealm;
    }

    /**
     * Requests that Keycloak issue an SD-JWT credential.
     */
    public String requestSdJwtCredential(String vct, String username) {
        return requestSdJwtCredential(vct, username, true, true);
    }

    /**
     * Requests that Keycloak issue an SD-JWT credential.
     *
     * @param vct            The verifiable credential type
     * @param username       The username of the user whom the credential is issued for
     * @param setKid         Specifies if the ID of the key used by Keycloak for issuing the credential
     *                       should be set to the `kid` header of the SD-JWT
     * @param setStatusClaim Specifies whether to include a status claim in the issued credential
     */
    public String requestSdJwtCredential(String vct, String username, boolean setKid, boolean setStatusClaim) {

        SignatureSignerContext signer;

        try {
            KeyWrapper keyWrapper = RSATestUtils.getRsaKeyWrapper(getKeycloakJwk());
            if (!setKid) {
                keyWrapper.setKid(null);
            }

            signer = new AsymmetricSignatureSignerContext(keyWrapper);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        String serverUrl = keycloak.getAuthServerUrl();
        String keycloakIssuerURI = KeycloakUriBuilder.fromUri(serverUrl)
                .path("/realms/{realm}")
                .build(activeTestRealm)
                .toString();

        IssuerSignedJWT issuerSignedJWT = exampleSdJwtCredential(keycloakIssuerURI, vct, username, setStatusClaim);
        return SdJwt.builder()
                .withIssuerSignedJwt(issuerSignedJWT)
                .withIssuerSigningContext(signer)
                .build()
                .toSdJwtString();
    }

    /**
     * Scaffold an SD-JWT identity credential that can clear authentication.
     */
    private static IssuerSignedJWT exampleSdJwtCredential(
            String iss, String vct, String username, boolean setStatusClaim) {
        Objects.requireNonNull(iss);
        Objects.requireNonNull(vct);

        ObjectNode claimSet = JsonSerialization.mapper.createObjectNode();
        claimSet.put(OAuth2Constants.ISSUER, iss);
        claimSet.put(SdJwtAuthenticatorFactory.VCT_CONFIG, vct);
        claimSet.put(CLAIM_NAME_EXP, Time.currentTime() + ISSUER_SIGNED_JWT_LIFESPAN_SECS);

        // Add status list claim (Token Status List)
        if (setStatusClaim) {
            claimSet.set(STATUS_FIELD, JsonSerialization.mapper.valueToTree(
                    Map.of(STATUS_LIST_FIELD, new ReferencedTokenValidator.StatusInfo(
                            0, "https://example.com/status-list-jwt"))));
        }

        DisclosureSpec.Builder disclosure = DisclosureSpec.builder()
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA");

        // Bind credential to user
        JWK jwk = ECTestUtils.getECPublicJwk(getUserJwk());
        ObjectNode cnf = JsonSerialization.mapper.createObjectNode();
        cnf.set(CLAIM_NAME_JWK, JsonSerialization.mapper.valueToTree(jwk));
        claimSet.set(CLAIM_NAME_CNF, cnf);

        if (username != null) {
            claimSet.put(OAuth2Constants.USERNAME, username);
            disclosure = disclosure.withUndisclosedClaim(OAuth2Constants.USERNAME, "eI8ZWm9QnKPpNPeNenHdhQ");
        }

        return IssuerSignedJWT.builder()
                .withClaims(claimSet, disclosure.build())
                .build();
    }

    /**
     * Creates an SD-JWT verifiable presentation of an SD-JWT credential.
     */
    public String presentSdJwt(String sdjwt, String nonce, String aud, JWK holderKey)
            throws Exception {
        return presentSdJwt(sdjwt, nonce, aud, holderKey, KB_JWT_LIFESPAN_SECS);
    }

    /**
     * Creates an SD-JWT verifiable presentation of an SD-JWT credential.
     *
     * @param sdjwt         The SD-JWT credential (without key-binding JWT)
     * @param nonce         A nonce value for replay protection
     * @param aud           An audience for replay protection
     * @param holderKey     The holder's private key
     * @param kbJwtLifespan The validity of the key-binding JWT in seconds
     */
    public String presentSdJwt(String sdjwt, String nonce, String aud, JWK holderKey, long kbJwtLifespan)
            throws Exception {
        JsonWebToken kbJwtClaims = new JsonWebToken();

        long currentTime = Time.currentTime();
        kbJwtClaims.iat(currentTime);
        kbJwtClaims.exp(currentTime + kbJwtLifespan);

        kbJwtClaims.getOtherClaims().put(IDToken.NONCE, nonce);
        kbJwtClaims.getOtherClaims().put(IDToken.AUD, aud);

        KeyWrapper keyWrapper = ECTestUtils.getEcKeyWrapper(holderKey);
        SignatureSignerContext signer = new ECDSASignatureSignerContext(keyWrapper);

        SdJwtVP sdJwtVP = SdJwtVP.of(sdjwt);
        return sdJwtVP.present(
                null,
                true,
                JsonSerialization.mapper.valueToTree(kbJwtClaims),
                signer);
    }

    public static JWK getKeycloakJwk() {
        return testJwkResource("/keys/keycloak.json");
    }

    public static JWK getUserJwk() {
        return testJwkResource("/keys/user-wallet-key.json");
    }

    public static JWK getStrayJwk() {
        return testJwkResource("/keys/stray-key.json");
    }

    /**
     * Load a test resource file, assuming it is a JWK.
     */
    private static JWK testJwkResource(String filename) {
        try (InputStream stream = SdJwtVPTestUtils.class.getResourceAsStream(filename)) {
            return JsonSerialization.readValue(stream, JWK.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
