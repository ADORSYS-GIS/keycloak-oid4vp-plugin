package demo.lib;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.util.JsonSerialization;

// Builds the small set of hardcoded demo credentials and turns them into SD-JWT presentations.
public final class WalletPresentationService {

    private static final int ISSUER_SIGNED_JWT_LIFESPAN_SECS = 300;
    private static final int KB_JWT_LIFESPAN_SECS = 60;

    private final DemoConfig cfg;
    private final DemoKeyMaterial keyMaterial;

    public WalletPresentationService(DemoConfig cfg) throws Exception {
        this.cfg = cfg;
        this.keyMaterial = DemoKeyMaterial.load(cfg);
    }

    public String buildPresentation(RequestObject requestObject, CredentialScenario scenario) throws Exception {
        String sdJwt = buildCredential(scenario);
        return presentCredential(sdJwt, requestObject);
    }

    private String buildCredential(CredentialScenario scenario) throws Exception {
        long now = Time.currentTime();

        ObjectNode claimSet = JsonSerialization.mapper.createObjectNode();
        claimSet.put(OAuth2Constants.ISSUER, cfg.issuer());
        claimSet.put("vct", cfg.vct());
        // DCQL requires sub (see SdJwtAuthRequirements); tests use username + "-id" as a stable subject id.
        claimSet.put(JsonWebToken.SUBJECT, scenario.username(cfg) + "-id");
        claimSet.put(OAuth2Constants.USERNAME, scenario.username(cfg));
        claimSet.put("iat", now);
        claimSet.put("exp", now + scenario.expirationOffsetSeconds(ISSUER_SIGNED_JWT_LIFESPAN_SECS));

        ObjectNode cnf = JsonSerialization.mapper.createObjectNode();
        cnf.set("jwk", JsonSerialization.mapper.valueToTree(keyMaterial.holderPublicJwk()));
        claimSet.set("cnf", cnf);

        DisclosureSpec.Builder disclosure = DisclosureSpec.builder()
                .withUndisclosedClaim(OAuth2Constants.USERNAME, "eI8ZWm9QnKPpNPeNenHdhQ")
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA");

        IssuerSignedJWT issuerSignedJWT = IssuerSignedJWT.builder()
                .withClaims(claimSet, disclosure.build())
                .build();

        return SdJwt.builder()
                .withIssuerSignedJwt(issuerSignedJWT)
                .withIssuerSigningContext(keyMaterial.newIssuerSigner())
                .build()
                .toSdJwtString();
    }

    private String presentCredential(String sdJwt, RequestObject requestObject) throws Exception {
        // The wallet proves possession of the bound holder key with a KB-JWT that echoes
        // the verifier-provided nonce and audience from the request object.
        JsonWebToken kbJwtClaims = new JsonWebToken();
        long now = Time.currentTime();
        kbJwtClaims.iat(now);
        kbJwtClaims.exp(now + KB_JWT_LIFESPAN_SECS);
        kbJwtClaims.getOtherClaims().put("nonce", requestObject.getNonce());
        kbJwtClaims.getOtherClaims().put("aud", requestObject.getClientId());

        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwt);
        return sdJwtVP.present(
                null, true, JsonSerialization.mapper.valueToTree(kbJwtClaims), keyMaterial.newHolderSigner());
    }
}
