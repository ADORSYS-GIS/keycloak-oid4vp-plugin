package de.adorsys.gis.keycloak.services.protocol.oid4vc.oid4vp.utils;

import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.util.JWKSUtils;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Objects;
import java.util.function.Function;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class RSATestUtils {

    private static final String JWK_SECRET_D_FIELD = "d";
    private static final String JWK_SECRET_P_FIELD = "p";
    private static final String JWK_SECRET_Q_FIELD = "q";
    private static final String JWK_SECRET_DP_FIELD = "dp";
    private static final String JWK_SECRET_DQ_FIELD = "dq";
    private static final String JWK_SECRET_QI_FIELD = "qi";

    public static RSAPublicJWK getRsaPublicJwk(JWK jwk) {
        RSAPublicJWK rsaPublicJWK = new RSAPublicJWK();
        rsaPublicJWK.setKeyType(KeyType.RSA);
        rsaPublicJWK.setAlgorithm(jwk.getAlgorithm());
        rsaPublicJWK.setModulus((String) jwk.getOtherClaims().get(RSAPublicJWK.MODULUS));
        rsaPublicJWK.setPublicExponent((String) jwk.getOtherClaims().get(RSAPublicJWK.PUBLIC_EXPONENT));
        return rsaPublicJWK;
    }

    public static KeyWrapper getRsaKeyWrapper(JWK jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (!KeyType.RSA.equals(jwk.getKeyType())) {
            throw new IllegalArgumentException("Only RSA keys are supported");
        }

        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
        Objects.requireNonNull(keyWrapper);
        keyWrapper.setPrivateKey(getRsaPrivateKey(jwk));

        return keyWrapper;
    }

    private static PrivateKey getRsaPrivateKey(JWK jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Function<String, byte[]> getField = name
                -> Base64Url.decode((String) jwk.getOtherClaims().get(name));

        BigInteger n = new BigInteger(1, getField.apply(RSAPublicJWK.MODULUS));
        BigInteger e = new BigInteger(1, getField.apply(RSAPublicJWK.PUBLIC_EXPONENT));
        BigInteger d = new BigInteger(1, getField.apply(JWK_SECRET_D_FIELD));
        BigInteger p = new BigInteger(1, getField.apply(JWK_SECRET_P_FIELD));
        BigInteger q = new BigInteger(1, getField.apply(JWK_SECRET_Q_FIELD));
        BigInteger dp = new BigInteger(1, getField.apply(JWK_SECRET_DP_FIELD));
        BigInteger dq = new BigInteger(1, getField.apply(JWK_SECRET_DQ_FIELD));
        BigInteger qi = new BigInteger(1, getField.apply(JWK_SECRET_QI_FIELD));

        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi);
        KeyFactory keyFactory = KeyFactory.getInstance(KeyType.RSA);
        return keyFactory.generatePrivate(spec);
    }
}
