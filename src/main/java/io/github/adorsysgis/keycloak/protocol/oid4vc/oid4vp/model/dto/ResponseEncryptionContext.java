package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Ephemeral response-encryption material for {@code direct_post.jwt} (JWE-encrypted authorization responses).
 *
 * <p>Held as part of {@link AuthorizationContext} so the verifier can decrypt wallet posts and validate
 * the advertised encryption {@code kid}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseEncryptionContext {

    @JsonProperty("ephemeral_key")
    private String ephemeralKey;

    @JsonProperty("expected_encryption_kid")
    private String expectedEncryptionKid;

    public String getEphemeralKey() {
        return ephemeralKey;
    }

    public ResponseEncryptionContext setEphemeralKey(String ephemeralKey) {
        this.ephemeralKey = ephemeralKey;
        return this;
    }

    public String getExpectedEncryptionKid() {
        return expectedEncryptionKid;
    }

    public ResponseEncryptionContext setExpectedEncryptionKid(String expectedEncryptionKid) {
        this.expectedEncryptionKid = expectedEncryptionKid;
        return this;
    }
}
