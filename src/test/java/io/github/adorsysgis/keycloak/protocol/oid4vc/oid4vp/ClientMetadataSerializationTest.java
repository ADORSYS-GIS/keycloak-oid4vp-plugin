package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.GenericFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.SdGenericFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.Algorithm;
import org.keycloak.util.JsonSerialization;

class ClientMetadataSerializationTest {

    @Test
    void serializesFinalSpecVpFormatIdentifiers() throws Exception {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();

        SdGenericFormat sdJwt = new SdGenericFormat();
        sdJwt.setSdJwtAlgValues(List.of(Algorithm.ES256));
        sdJwt.setKbJwtAlgValues(List.of(Algorithm.ES256));
        vpFormat.setDcSdJwt(sdJwt);

        GenericFormat jwtVcJson = new GenericFormat();
        jwtVcJson.setAlgValues(List.of(Algorithm.ES256));
        vpFormat.setJwtVcJson(jwtVcJson);

        ClientMetadata metadata = new ClientMetadata().setVpFormat(vpFormat);
        JsonNode json = JsonSerialization.mapper.valueToTree(metadata);
        JsonNode formats = json.get("vp_formats_supported");

        assertTrue(formats.has("dc+sd-jwt"));
        assertTrue(formats.get("dc+sd-jwt").has("sd-jwt_alg_values"));
        assertTrue(formats.has("jwt_vc_json"));
        assertTrue(formats.get("jwt_vc_json").has("alg_values"));
    }
}
