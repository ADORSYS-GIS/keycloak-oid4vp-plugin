package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.keycloak.crypto.KeyWrapper;

/** Builds the PKCS#10 certificate signing request an access certificate is issued for. */
final class EudiHubCsr {

    private static final String PEM_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----";
    private static final String PEM_END = "-----END CERTIFICATE REQUEST-----";

    private EudiHubCsr() {}

    /**
     * Creates a PEM CSR for the public key of the given signing key, signed by its private key.
     *
     * @throws IllegalArgumentException if the key has no usable key material
     */
    static String create(KeyWrapper key, String commonName) throws Exception {
        if (key == null || !(key.getPrivateKey() instanceof PrivateKey privateKey)) {
            throw new IllegalArgumentException("The OpenID4VP signing key has no private key.");
        }
        if (!(key.getPublicKey() instanceof PublicKey publicKey)) {
            throw new IllegalArgumentException("The OpenID4VP signing key has no public key.");
        }

        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, commonName == null || commonName.isBlank() ? "Keycloak OpenID4VP" : commonName)
                .build();
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(key.getAlgorithm())).build(privateKey);
        PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(subject, publicKey).build(signer);

        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(request.getEncoded());
        return PEM_BEGIN + "\n" + body + "\n" + PEM_END + "\n";
    }

    private static String signatureAlgorithm(String keyAlgorithm) {
        return switch (keyAlgorithm == null ? "" : keyAlgorithm) {
            case "ES256" -> "SHA256withECDSA";
            case "ES384" -> "SHA384withECDSA";
            case "ES512" -> "SHA512withECDSA";
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            case "PS256" -> "SHA256withRSAandMGF1";
            case "PS384" -> "SHA384withRSAandMGF1";
            case "PS512" -> "SHA512withRSAandMGF1";
            case "EdDSA", "Ed25519" -> "Ed25519";
            default ->
                throw new IllegalArgumentException(
                        "The OpenID4VP signing key algorithm is not supported: " + keyAlgorithm);
        };
    }
}
