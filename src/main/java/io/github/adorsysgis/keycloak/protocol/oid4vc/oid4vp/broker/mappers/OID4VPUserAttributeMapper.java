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

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPEnvironmentProviderFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderFactory;
import org.keycloak.Config;
import org.keycloak.broker.oid4vp.mappers.OID4VPSdJwtUserAttributeMapper;

/**
 * Adapts Keycloak's claim mapper to the plugin's hidden import provider. Despite its upstream
 * name, the mapper reads verified claims JSON, so both SD-JWT and mdoc claims use the same logic.
 * Claim selection, context-only staging, and attribute synchronization stay owned by Keycloak.
 */
public class OID4VPUserAttributeMapper extends OID4VPSdJwtUserAttributeMapper
        implements OID4VPEnvironmentProviderFactory {

    public static final String PROVIDER_ID = "oid4vp-user-attribute-idp-mapper";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return new String[] {OID4VPImportIdentityProviderFactory.PROVIDER_ID};
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return OID4VPEnvironmentProviderFactory.super.isSupported(config);
    }

    @Override
    public String getDisplayType() {
        return "OpenID4VP Attribute Importer";
    }

    @Override
    public String getHelpText() {
        return "Import a verified credential claim into a user property or attribute. "
                + "Supports SD-JWT and mdoc claims, including multivalued arrays and JSON objects.";
    }
}
