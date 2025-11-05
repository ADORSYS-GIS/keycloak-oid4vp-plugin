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

package org.keycloak.protocol.oid4vc.oid4vp.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oid4vc.oid4vp.OID4VPEnvironmentProviderFactory;
import org.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import org.keycloak.protocol.oid4vc.tokenstatus.http.TrustedStatusListJwtFetcher;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtAuthenticatorFactory implements AuthenticatorFactory, OID4VPEnvironmentProviderFactory {

    public static final String PROVIDER_ID = "sd-jwt-authenticator";
    public static final String REFERENCE_CATEGORY = "verifiable-credential";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String VCT_CONFIG = "vct";
    public static final String VCT_CONFIG_DEFAULT = "https://credentials.example.com/identity_credential";

    public static final String KBJWT_MAX_AGE_CONFIG = "kbJwtMaxAge";
    public static final int KBJWT_MAX_AGE_CONFIG_DEFAULT = 60;

    public static final String ENFORCE_NBF_CLAIM_CONFIG = "enforceNbfClaim";
    public static final boolean ENFORCE_NBF_CLAIM_CONFIG_DEFAULT = false;

    public static final String ENFORCE_EXP_CLAIM_CONFIG = "enforceExpClaim";
    public static final boolean ENFORCE_EXP_CLAIM_CONFIG_DEFAULT = false;

    public static final String ENFORCE_REVOCATION_STATUS_CONFIG = "enforceRevocationStatus";
    public static final boolean ENFORCE_REVOCATION_STATUS_CONFIG_DEFAULT = false;

    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(VCT_CONFIG);
        property.setLabel("Credential types allowed");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(VCT_CONFIG_DEFAULT);
        property.setHelpText("Only SD-JWTs of this comma-separated list of types (vct) will be accepted by the authenticator.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(ENFORCE_NBF_CLAIM_CONFIG);
        property.setLabel("Enforce Not Before claim");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(ENFORCE_NBF_CLAIM_CONFIG_DEFAULT);
        property.setHelpText("Verification policy whether or not to honor the nbf time claim of presented credentials.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(ENFORCE_EXP_CLAIM_CONFIG);
        property.setLabel("Reject expired credentials");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(ENFORCE_EXP_CLAIM_CONFIG_DEFAULT);
        property.setHelpText("Verification policy whether or not to honor the exp time claim of presented credentials.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(KBJWT_MAX_AGE_CONFIG);
        property.setLabel("Maximum age (in seconds) of presented key-binding JWT");
        property.setType(ProviderConfigProperty.INTEGER_TYPE);
        property.setDefaultValue(KBJWT_MAX_AGE_CONFIG_DEFAULT);
        property.setHelpText("Define a maximum age of accepted key-binding JWTs as part of measures to protect against replay.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(ENFORCE_REVOCATION_STATUS_CONFIG);
        property.setLabel("Reject revoked credentials (Token Status List)");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(ENFORCE_REVOCATION_STATUS_CONFIG_DEFAULT);
        property.setHelpText("Reject credentials whose status indicates they are no longer valid as per the Token Status List mechanism.");
        configProperties.add(property);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        StatusListJwtFetcher httpFetcher = new TrustedStatusListJwtFetcher(session);
        return new SdJwtAuthenticator(httpFetcher);
    }

    @Override
    public String getDisplayType() {
        return "SD-JWT Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Authenticates users via presentation of a Keycloak-issued SD-JWT identity credential";
    }

    @Override
    public String getReferenceCategory() {
        return REFERENCE_CATEGORY;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
