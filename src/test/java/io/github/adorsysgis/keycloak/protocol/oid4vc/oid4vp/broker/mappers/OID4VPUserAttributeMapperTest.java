package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProvider;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.util.JsonSerialization;

/**
 * Covers the supported import mapper: claims land on the brokered context (username, email,
 * names, custom attributes) without touching any user, keeping preprocessing safe to run before
 * the user is created.
 */
class OID4VPUserAttributeMapperTest {

    private final OID4VPUserAttributeMapper mapper = new OID4VPUserAttributeMapper();

    @Test
    void preprocessStagesUsernameEmailAndNames() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree(
                "{\"preferred_username\":\"ada\",\"email\":\"ada@example.com\",\"given_name\":\"Ada\",\"family_name\":\"Lovelace\"}");
        BrokeredIdentityContext context = brokeredContext(claims);

        mapper.preprocessFederatedIdentity(null, null, mapperModel("preferred_username", "username"), context);
        mapper.preprocessFederatedIdentity(null, null, mapperModel("email", "email"), context);
        mapper.preprocessFederatedIdentity(null, null, mapperModel("given_name", "firstName"), context);
        mapper.preprocessFederatedIdentity(null, null, mapperModel("family_name", "lastName"), context);

        assertEquals("ada", context.getModelUsername());
        assertEquals("ada@example.com", context.getEmail());
        assertEquals("Ada", context.getFirstName());
        assertEquals("Lovelace", context.getLastName());
    }

    @Test
    void preprocessStagesCustomAttributes() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"nationalities\":[\"DE\",\"FR\"],\"age\":42}");
        BrokeredIdentityContext context = brokeredContext(claims);

        mapper.preprocessFederatedIdentity(null, null, mapperModel("nationalities[]", "nationality"), context);
        mapper.preprocessFederatedIdentity(null, null, mapperModel("age", "age"), context);

        assertEquals("DE", context.getUserAttribute("nationality"));
        assertEquals(List.of("DE", "FR"), context.getAttributes().get("nationality"));
        assertEquals("42", context.getUserAttribute("age"));
    }

    @Test
    void absentClaimLeavesContextUntouched() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"preferred_username\":\"ada\"}");
        BrokeredIdentityContext context = brokeredContext(claims);
        context.setModelUsername("original");

        mapper.preprocessFederatedIdentity(null, null, mapperModel("email", "email"), context);

        assertEquals("original", context.getModelUsername());
        assertNull(context.getEmail());
    }

    @Test
    void misconfiguredMapperIsIgnored() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"preferred_username\":\"ada\"}");
        BrokeredIdentityContext context = brokeredContext(claims);

        IdentityProviderMapperModel blankClaim = mapperModel("preferred_username", "username");
        blankClaim.getConfig().put(AbstractOID4VPClaimMapper.CLAIM, "  ");
        mapper.preprocessFederatedIdentity(null, null, blankClaim, context);

        IdentityProviderMapperModel blankAttribute = mapperModel("preferred_username", "  ");
        mapper.preprocessFederatedIdentity(null, null, blankAttribute, context);

        assertEquals("staged-user", context.getModelUsername());
    }

    private static BrokeredIdentityContext brokeredContext(JsonNode claims) {
        IdentityProviderModel idp = new IdentityProviderModel();
        idp.setAlias("oid4vp-import");
        idp.setEnabled(true);
        BrokeredIdentityContext context = new BrokeredIdentityContext("staged-user", idp);
        context.setModelUsername("staged-user");
        context.getContextData().put(OID4VPImportIdentityProvider.CREDENTIAL_CLAIMS, claims);
        return context;
    }

    private static IdentityProviderMapperModel mapperModel(String claim, String attribute) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName("test-mapper");
        model.setIdentityProviderAlias("oid4vp-import");
        model.setIdentityProviderMapper(OID4VPUserAttributeMapper.PROVIDER_ID);
        Map<String, String> config = new HashMap<>();
        config.put(AbstractOID4VPClaimMapper.CLAIM, claim);
        config.put(OID4VPUserAttributeMapper.USER_ATTRIBUTE, attribute);
        model.setConfig(config);
        return model;
    }
}
