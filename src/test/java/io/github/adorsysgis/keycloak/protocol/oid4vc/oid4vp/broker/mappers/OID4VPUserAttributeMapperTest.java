package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderFactory;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.oid4vp.mappers.AbstractOID4VPClaimMapper;
import org.keycloak.broker.oid4vp.mappers.ClaimPath;
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
    void adapterKeepsPluginIdentityAndAvailability() {
        assertEquals("oid4vp-user-attribute-idp-mapper", mapper.getId());
        assertArrayEquals(
                new String[] {OID4VPImportIdentityProviderFactory.PROVIDER_ID}, mapper.getCompatibleProviders());
        assertTrue(mapper.isSupported(null));
        assertEquals(
                org.keycloak.broker.oid4vp.OID4VPIdentityProvider.CREDENTIAL_CLAIMS,
                OID4VPImportIdentityProvider.CREDENTIAL_CLAIMS);
    }

    @Test
    void preprocessHandlesMdocNamespacesAndStructuredValues() throws Exception {
        BrokeredIdentityContext context = brokeredContext(
                JsonSerialization.mapper.readTree(
                        "{\"org.iso.18013.5.1\":{\"family_name\":\"Mustermann\"},\"adult\":true,\"address\":{\"city\":\"Berlin\"}}"));
        mapper.preprocessFederatedIdentity(
                null, null, mapperModel("org\\.iso\\.18013\\.5\\.1.family_name", "lastName"), context);
        mapper.preprocessFederatedIdentity(null, null, mapperModel("adult", "adult"), context);
        mapper.preprocessFederatedIdentity(null, null, mapperModel("address", "address"), context);
        assertEquals("Mustermann", context.getLastName());
        assertEquals("true", context.getUserAttribute("adult"));
        assertEquals("{\"city\":\"Berlin\"}", context.getUserAttribute("address"));
    }

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

    @Test
    void selectsNestedClaim() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"address\":{\"locality\":\"Berlin\"}}");

        assertEquals(
                List.of("Berlin"),
                ClaimPath.parse("address.locality").select(claims).stream()
                        .map(JsonNode::asText)
                        .toList());
    }

    @Test
    void selectsAllArrayElements() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"nationalities\":[\"DE\",\"FR\"]}");

        assertEquals(
                List.of("DE", "FR"),
                ClaimPath.parse("nationalities[]").select(claims).stream()
                        .map(JsonNode::asText)
                        .toList());
    }

    @Test
    void selectsFirstArrayElement() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"nationalities\":[\"DE\",\"FR\"]}");

        assertEquals(
                List.of("DE"),
                ClaimPath.parse("nationalities[0]").select(claims).stream()
                        .map(JsonNode::asText)
                        .toList());
    }

    @Test
    void supportsEscapedDotInClaimName() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"a.b\":\"value\"}");

        assertEquals(
                List.of("value"),
                ClaimPath.parse("a\\.b").select(claims).stream()
                        .map(JsonNode::asText)
                        .toList());
    }

    @Test
    void missingPathsSelectNothing() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"given_name\":\"Ada\"}");

        assertTrue(ClaimPath.parse("family_name").select(claims).isEmpty());
        assertTrue(ClaimPath.parse("given_name[]").select(claims).isEmpty());
        assertTrue(ClaimPath.parse("address.locality").select(claims).isEmpty());
    }

    @Test
    void malformedPathsReturnNull() {
        assertNull(ClaimPath.parse(null));
        assertNull(ClaimPath.parse(""));
        assertNull(ClaimPath.parse("address."));
        assertNull(ClaimPath.parse("[0]"));
        assertNull(ClaimPath.parse("nationalities[1]"));
        assertNull(ClaimPath.parse("nationalities["));
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
