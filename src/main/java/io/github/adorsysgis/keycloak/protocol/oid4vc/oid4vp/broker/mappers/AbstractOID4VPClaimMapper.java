/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
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

package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPEnvironmentProviderFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderFactory;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Base for the plugin's import mappers that read a claim of the verified credential presentation,
 * addressed by a {@link ClaimPath} over the claims JSON. Subclasses decide where the resolved
 * values go. Not tied to a credential format: any format whose verification yields claims JSON
 * under {@link OID4VPImportIdentityProvider#CREDENTIAL_CLAIMS} can build on it.
 *
 * <p>Ported from Keycloak's {@code org.keycloak.broker.oid4vp.mappers.AbstractOID4VPClaimMapper}.
 * Differences from upstream: compatible providers point at this plugin's
 * {@code oid4vp-plugin-import} provider, and availability follows the plugin's own environment
 * gate instead of the upstream experimental feature flag.
 */
public abstract class AbstractOID4VPClaimMapper extends AbstractIdentityProviderMapper
        implements OID4VPEnvironmentProviderFactory {

    protected static final Logger logger = Logger.getLogger(AbstractOID4VPClaimMapper.class);

    public static final String CLAIM = "claim";

    private static final String[] COMPATIBLE_PROVIDERS = {OID4VPImportIdentityProviderFactory.PROVIDER_ID};

    protected static ProviderConfigProperty claimProperty() {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(CLAIM);
        property.setLabel("Claim");
        property.setHelpText("Path of the claim in the presented credential. Use dot notation for nested claims, "
                + "i.e. 'address.locality', [] to select all array elements, i.e. 'nationalities[]', and [0] to select the first element of the presented array. "
                + "To use dot (.) literally, escape it with backslash (\\.)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        return property;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return true;
    }

    protected JsonNode credentialClaims(BrokeredIdentityContext context) {
        Object claims = context.getContextData().get(OID4VPImportIdentityProvider.CREDENTIAL_CLAIMS);
        if (claims == null) {
            return null;
        }
        if (claims instanceof JsonNode node) {
            return node;
        }
        return JsonSerialization.mapper.valueToTree(claims);
    }

    protected List<String> claimValues(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String claimPath = mapperModel.getConfig().get(CLAIM);
        if (StringUtil.isBlank(claimPath)) {
            logger.warnf("No claim configured for mapper %s", mapperModel.getName());
            return null;
        }
        ClaimPath path = ClaimPath.parse(claimPath.trim());
        if (path == null) {
            logger.warnf("Invalid claim path '%s' in mapper %s", claimPath, mapperModel.getName());
            return null;
        }
        List<JsonNode> matches = path.select(credentialClaims(context));
        if (matches.isEmpty()) {
            return null;
        }
        Iterable<JsonNode> selected = matches.size() == 1 && matches.get(0).isArray() ? matches.get(0) : matches;
        // The values end up in the brokered context, whose serialization restores lists by their
        // concrete class, so they must stay plain ArrayLists.
        List<String> values = new ArrayList<>();
        for (JsonNode node : selected) {
            if (!node.isNull()) {
                values.add(value(node));
            }
        }
        return values;
    }

    protected String value(JsonNode node) {
        if (node.isValueNode()) {
            return node.asText();
        }
        try {
            return JsonSerialization.writeValueAsString(node);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize the claim value", e);
        }
    }
}
