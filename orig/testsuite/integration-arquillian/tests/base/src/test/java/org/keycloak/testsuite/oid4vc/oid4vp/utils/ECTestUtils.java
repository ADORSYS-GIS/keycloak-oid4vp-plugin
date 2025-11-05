/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.oid4vc.oid4vp.utils;

import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JWKSUtils;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class ECTestUtils {

    private static final String JWK_SECRET_D_FIELD = "d";

    public static JWK getECPublicJwk(JWK jwk) {
        jwk.setOtherClaims(ECTestUtils.JWK_SECRET_D_FIELD, null);
        return jwk;
    }

    public static KeyWrapper getEcKeyWrapper(JWK jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (jwk.getKeyType() == null || !jwk.getKeyType().equals(KeyType.EC)) {
            throw new IllegalArgumentException("Only EC keys are supported");
        }

        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
        Objects.requireNonNull(keyWrapper);
        keyWrapper.setPrivateKey(getEcPrivateKey(jwk));

        return keyWrapper;
    }

    static PrivateKey getEcPrivateKey(JWK jwk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (jwk.getKeyType() == null || !jwk.getKeyType().equals(KeyType.EC)) {
            throw new IllegalArgumentException("Only EC keys are supported");
        }

        String jwkCrv = (String) jwk.getOtherClaims().get(ECPublicJWK.CRV);
        ECParameterSpec ecSpec = getECParameterSpec(jwkCrv);

        KeyFactory keyFactory = KeyFactory.getInstance(KeyType.EC);
        byte[] dBytes = Base64Url.decode((String) jwk.getOtherClaims().get(JWK_SECRET_D_FIELD));
        BigInteger dValue = new BigInteger(1, dBytes);
        return keyFactory.generatePrivate(new ECPrivateKeySpec(dValue, ecSpec));
    }

    private static ECParameterSpec getECParameterSpec(String jwkCrv) {
        String crvStdName = switch (jwkCrv) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            case "P-521" -> "secp521r1";
            default -> throw new IllegalArgumentException("Unsupported curve: " + jwkCrv);
        };

        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(KeyType.EC);
            params.init(new ECGenParameterSpec(crvStdName));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
