package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata.OID4VCIssuerMetadataProvider.ATTR_PRESENTATION_DURING_ISSUANCE;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScope.VC_PRESENTATION_PROFILE_ID_ATTR;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScope.VC_REQUIRES_PRESENTATION_ATTR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCSubjectIdMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OID4VCUserAttributeMapper;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedCodeGrant;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * Shared realm and credential-configuration setup for issuance-gating tests.
 */
public abstract class PresentationDuringIssuanceBaseTest extends OID4VPBaseUserAuthEndpointTest {

    protected static void assertPresentationDuringIssuanceEnabled(RealmResource realm) {
        assertEquals(
                "true",
                realm.toRepresentation().getAttributes().get(ATTR_PRESENTATION_DURING_ISSUANCE),
                "The realm feature flag must enable presentation during issuance");
    }

    protected static void ensureCredentialScope(
            RealmResource realm,
            String configurationId,
            String credentialType,
            PresentationDuringIssuanceMode mode,
            String profileId) {
        // Create the credential configuration once; the shared test container is reused by test classes.
        boolean scopeExists = realm.clientScopes().findAll().stream()
                .anyMatch(candidate -> configurationId.equals(candidate.getName()));
        if (!scopeExists) {
            ClientScopeRepresentation representation = new ClientScopeRepresentation();
            representation.setName(configurationId);
            representation.setProtocol(OID4VC_PROTOCOL);
            Map<String, String> attributes = new HashMap<>(Map.of(
                    "vc.credential_configuration_id",
                    configurationId,
                    "vc.verifiable_credential_type",
                    credentialType,
                    "vc.format",
                    "dc+sd-jwt",
                    "vc.build_config.sd_jwt.visible_claims",
                    "sub"));
            if (mode != null) {
                attributes.put(VC_REQUIRES_PRESENTATION_ATTR, mode.getValue());
            }
            if (profileId != null) {
                attributes.put(VC_PRESENTATION_PROFILE_ID_ATTR, profileId);
            }
            representation.setAttributes(attributes);
            try (var response = realm.clientScopes().create(representation)) {
                int status = response.getStatus();
                assertTrue(
                        status == HttpStatus.SC_CREATED || status == HttpStatus.SC_CONFLICT,
                        "Failed to create credential scope: HTTP " + status);
            }
        }

        // Resolve the persisted scope after creation (or reuse) so it can be assigned to the client.
        String scopeId = realm.clientScopes().findAll().stream()
                .filter(candidate -> configurationId.equals(candidate.getName()))
                .map(ClientScopeRepresentation::getId)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Credential scope not found: " + configurationId));

        // Repair reused test containers so each test class gets the policy it declares.
        if (scopeExists) {
            ClientScopeResource scopeResource = realm.clientScopes().get(scopeId);
            ClientScopeRepresentation persisted = scopeResource.toRepresentation();

            Map<String, String> attributes =
                    new HashMap<>(persisted.getAttributes() == null ? Map.of() : persisted.getAttributes());
            attributes.put("vc.credential_configuration_id", configurationId);
            attributes.put("vc.verifiable_credential_type", credentialType);

            if (mode == null) {
                attributes.remove(VC_REQUIRES_PRESENTATION_ATTR);
            } else {
                attributes.put(VC_REQUIRES_PRESENTATION_ATTR, mode.getValue());
            }

            if (profileId == null) {
                attributes.remove(VC_PRESENTATION_PROFILE_ID_ATTR);
            } else {
                attributes.put(VC_PRESENTATION_PROFILE_ID_ATTR, profileId);
            }

            persisted.setAttributes(attributes);
            scopeResource.update(persisted);
        }

        // Add claims metadata and user mappings required by Keycloak's credential builder.
        ensureCredentialClaimMappers(realm, scopeId);

        // Assign the credential configuration as an optional scope, which is how the issuance flow resolves it.
        var clients = realm.clients().findByClientId(TEST_CLIENT_ID);
        if (clients.isEmpty()) {
            throw new IllegalStateException("Test client not found: " + TEST_CLIENT_ID);
        }
        var client = realm.clients().get(clients.getFirst().getId());
        client.addOptionalClientScope(scopeId);
    }

    private static void ensureCredentialClaimMappers(RealmResource realm, String scopeId) {
        createMapper(
                realm,
                scopeId,
                "subject",
                OID4VCSubjectIdMapper.MAPPER_ID,
                Map.of(OID4VCMapper.CLAIM_NAME, JsonWebToken.SUBJECT, OID4VCMapper.USER_ATTRIBUTE_KEY, UserModel.ID));

        createMapper(
                realm,
                scopeId,
                "given-name",
                OID4VCUserAttributeMapper.MAPPER_ID,
                Map.of(
                        OID4VCMapper.CLAIM_NAME,
                        IDToken.GIVEN_NAME,
                        OID4VCMapper.USER_ATTRIBUTE_KEY,
                        UserModel.FIRST_NAME));

        createMapper(
                realm,
                scopeId,
                "family-name",
                OID4VCUserAttributeMapper.MAPPER_ID,
                Map.of(
                        OID4VCMapper.CLAIM_NAME,
                        IDToken.FAMILY_NAME,
                        OID4VCMapper.USER_ATTRIBUTE_KEY,
                        UserModel.LAST_NAME));
    }

    private static void createMapper(
            RealmResource realm, String scopeId, String name, String mapperId, Map<String, String> config) {
        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName(name);
        mapper.setProtocol(OID4VC_PROTOCOL);
        mapper.setProtocolMapper(mapperId);
        mapper.setConfig(config);
        try (var response =
                realm.clientScopes().get(scopeId).getProtocolMappers().createMapper(mapper)) {
            int status = response.getStatus();
            assertTrue(
                    status == HttpStatus.SC_CREATED || status == HttpStatus.SC_CONFLICT,
                    "Failed to create credential mapper: HTTP " + status);
        }
    }

    protected static void grantCredentialToTestUser(String configurationId) {
        String adminToken = keycloak.getKeycloakAdminClient().tokenManager().getAccessTokenString();
        String url = KeycloakUriBuilder.fromUri(keycloak.getAuthServerUrl())
                .path("admin/realms/{realm}/users/{userId}/vc/credentials")
                .build(TEST_REALM_NAME, TEST_USER_ID)
                .toString();

        HttpPost post = new HttpPost(url);
        post.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken);
        post.setEntity(new StringEntity(
                "{\"credentialScopeName\":\"" + configurationId + "\"}", ContentType.APPLICATION_JSON));

        try (var client = HttpClientBuilder.create().build();
                var response = client.execute(post)) {
            int status = response.getStatusLine().getStatusCode();
            if (status != HttpStatus.SC_OK && status != HttpStatus.SC_CONFLICT) {
                throw new IllegalStateException("Failed to grant credential to test user: HTTP " + status);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to grant credential to test user", e);
        }
    }

    protected JsonNode createCredentialOffer(String configurationId, boolean preAuthorized) throws Exception {
        String authCode = getFreshAuthorizationCode();
        String accessToken = requestAccessToken(authCode, true);
        String createOfferUrl = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path("protocol/oid4vc/create-credential-offer")
                .queryParam("credential_configuration_id", configurationId)
                .queryParam("pre_authorized", Boolean.toString(preAuthorized))
                .queryParam("target_user", TEST_USER)
                .build()
                .toString();
        var createOfferRequest = new HttpGet(createOfferUrl);
        createOfferRequest.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        HttpResponse createOfferResponse = httpClient.execute(createOfferRequest);
        assertEquals(HttpStatus.SC_OK, createOfferResponse.getStatusLine().getStatusCode());
        JsonNode offerUri = parseJsonResponse(createOfferResponse);

        HttpResponse offerResponse = httpClient.execute(new HttpGet(
                offerUri.get("issuer").asText() + "/" + offerUri.get("nonce").asText()));
        assertEquals(HttpStatus.SC_OK, offerResponse.getStatusLine().getStatusCode());
        return parseJsonResponse(offerResponse);
    }

    protected String createAuthorizationCodeCredentialOffer(String configurationId) throws Exception {
        JsonNode offer = createCredentialOffer(configurationId, false);
        String issuerState = offer.path("grants")
                .path(OAuth2Constants.AUTHORIZATION_CODE)
                .path(OAuth2Constants.ISSUER_STATE)
                .asText(null);
        if (issuerState == null) {
            throw new IllegalStateException("Authorization-code credential offer has no issuer_state");
        }
        return issuerState;
    }

    protected String requestPreAuthorizedAccessToken(JsonNode offer) throws IOException {
        String preAuthorizedCode = offer.path("grants")
                .path(PreAuthorizedCodeGrant.PRE_AUTH_GRANT_TYPE)
                .path(PreAuthorizedCodeGrant.CODE_REQUEST_PARAM)
                .asText(null);
        if (preAuthorizedCode == null) {
            throw new IllegalStateException("Pre-authorized credential offer has no pre-authorized_code");
        }

        var params = getDefaultHttpParams();
        params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrant.PRE_AUTH_GRANT_TYPE));
        params.add(new BasicNameValuePair(PreAuthorizedCodeGrant.CODE_REQUEST_PARAM, preAuthorizedCode));
        return requestAccessToken(params);
    }

    protected HttpResponse requestCredentialWithIdentifier(String accessToken, String credentialIdentifier)
            throws IOException {
        return executeCredentialRequest(accessToken, "{\"credential_identifier\":\"" + credentialIdentifier + "\"}");
    }

    protected HttpResponse requestCredentialWithConfigurationId(String accessToken, String configurationId)
            throws IOException {
        return executeCredentialRequest(accessToken, "{\"credential_configuration_id\":\"" + configurationId + "\"}");
    }

    private HttpResponse executeCredentialRequest(String accessToken, String requestPayload) throws IOException {
        String credentialUrl = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path("protocol/oid4vc/credential")
                .build()
                .toString();
        HttpPost request = new HttpPost(credentialUrl);
        request.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        request.setEntity(new StringEntity(requestPayload, ContentType.APPLICATION_JSON));
        return httpClient.execute(request);
    }

    protected JsonNode parseJsonResponse(HttpResponse response) throws IOException {
        return JsonSerialization.mapper.readTree(EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
    }
}
