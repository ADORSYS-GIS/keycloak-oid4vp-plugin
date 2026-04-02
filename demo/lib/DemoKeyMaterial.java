package demo.lib;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Objects;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.JWKSUtils;

public final class DemoKeyMaterial {

    private final JWK issuerJwk;
    private final JWK holderJwk;

    private DemoKeyMaterial(JWK issuerJwk, JWK holderJwk) {
        this.issuerJwk = issuerJwk;
        this.holderJwk = holderJwk;
    }

    public static DemoKeyMaterial load(DemoConfig cfg) throws Exception {
        return new DemoKeyMaterial(
                loadJwk(Path.of(cfg.issuerJwkPath())), loadJwk(Path.of(cfg.holderJwkPath())));
    }

    public SignatureSignerContext newIssuerSigner() throws Exception {
        if (!Objects.equals(issuerJwk.getKeyType(), "RSA")) {
            throw new IllegalArgumentException("Only RSA keys are supported for the demo issuer");
        }

        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(issuerJwk);
        keyWrapper.setPrivateKey(readRsaPrivateKey(issuerJwk));
        return new AsymmetricSignatureSignerContext(keyWrapper);
    }

    public SignatureSignerContext newHolderSigner() throws Exception {
        if (!Objects.equals(holderJwk.getKeyType(), "EC")) {
            throw new IllegalArgumentException("Only EC keys are supported for the demo holder");
        }

        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(holderJwk);
        keyWrapper.setPrivateKey(readEcPrivateKey(holderJwk));
        return new ECDSASignatureSignerContext(keyWrapper);
    }

    public JWK holderPublicJwk() throws Exception {
        // The credential must bind to the wallet's public key, so the demo strips
        // the private "d" member before embedding the holder key in cnf.jwk.
        JWK copy = JsonSerialization.readValue(JsonSerialization.writeValueAsString(holderJwk), JWK.class);
        copy.setOtherClaims("d", null);
        return copy;
    }

    private static JWK loadJwk(Path path) throws IOException {
        if (!Files.exists(path)) {
            throw new IllegalArgumentException("JWK file not found: " + path);
        }

        try (InputStream in = Files.newInputStream(path)) {
            return JsonSerialization.readValue(in, JWK.class);
        }
    }

    // The demo works from checked-in JWK files rather than a running wallet/key store,
    // so we manually reconstruct Java private keys here before passing them to
    // Keycloak's signer contexts.
    private static PrivateKey readRsaPrivateKey(JWK jwk) throws Exception {
        byte[] n = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("n"));
        byte[] e = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("e"));
        byte[] d = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("d"));
        byte[] p = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("p"));
        byte[] q = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("q"));
        byte[] dp = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("dp"));
        byte[] dq = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("dq"));
        byte[] qi = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("qi"));

        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(
                new java.math.BigInteger(1, n),
                new java.math.BigInteger(1, e),
                new java.math.BigInteger(1, d),
                new java.math.BigInteger(1, p),
                new java.math.BigInteger(1, q),
                new java.math.BigInteger(1, dp),
                new java.math.BigInteger(1, dq),
                new java.math.BigInteger(1, qi));
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static PrivateKey readEcPrivateKey(JWK jwk) throws Exception {
        String curve = (String) jwk.getOtherClaims().get(ECPublicJWK.CRV);
        byte[] dBytes = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("d"));
        ECPrivateKeySpec spec =
                new ECPrivateKeySpec(new java.math.BigInteger(1, dBytes), getEcParameterSpec(curve));
        return KeyFactory.getInstance("EC").generatePrivate(spec);
    }

    private static ECParameterSpec getEcParameterSpec(String jwkCurve) throws Exception {
        String curveName = switch (jwkCurve) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            case "P-521" -> "secp521r1";
            default -> throw new IllegalArgumentException("Unsupported curve: " + jwkCurve);
        };

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curveName));
        return params.getParameterSpec(ECParameterSpec.class);
    }
}
