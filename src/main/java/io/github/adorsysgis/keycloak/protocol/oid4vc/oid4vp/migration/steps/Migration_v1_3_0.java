package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.steps;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.Migration;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MigrationUtils;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * All realm-level updates required to bring a realm from plugin v1.2.7 to v1.3.0:
 *
 * <ol>
 *   <li>Rename every {@code sd-jwt-authenticator} execution in the OID4VP auth flow to
 *       {@link #CURRENT_AUTHENTICATOR oid4vp-authenticator}.</li>
 *   <li>Rename the legacy {@code vct} authenticator config key to
 *       {@link #CURRENT_CREDENTIAL_TYPES_CONFIG_KEY credentialTypes}.</li>
 *   <li>Rename the legacy {@code kbJwtMaxAge} authenticator config key to
 *       {@link #CURRENT_HOLDER_BINDING_PROOF_MAX_AGE_CONFIG_KEY holderBindingProofMaxAge}.</li>
 *   <li>Backfill {@link #CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY
 *       fallbackToIsoSpecSessionTranscript} with the default {@code false} on every existing
 *       authenticator config that doesn't have it.</li>
 * </ol>
 *
 * <p>Each step is idempotent; the migration is safe to re-run.
 */
public class Migration_v1_3_0 implements Migration {

    private static final Logger logger = Logger.getLogger(Migration_v1_3_0.class);

    public static final String ID = "v1.3.0";

    public static final String LEGACY_AUTHENTICATOR = "sd-jwt-authenticator";
    public static final String LEGACY_VCT_CONFIG_KEY = "vct";
    public static final String LEGACY_KBJWT_MAX_AGE_CONFIG_KEY = "kbJwtMaxAge";

    // Snapshot of authenticator identifiers as they existed in v1.3.0
    public static final String CURRENT_AUTHENTICATOR = "oid4vp-authenticator";
    public static final String CURRENT_CREDENTIAL_TYPES_CONFIG_KEY = "credentialTypes";
    public static final String CURRENT_HOLDER_BINDING_PROOF_MAX_AGE_CONFIG_KEY = "holderBindingProofMaxAge";
    public static final String CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY =
            "fallbackToIsoSpecSessionTranscript";
    public static final String CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_DEFAULT = "false";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public void apply(KeycloakSession session, RealmModel realm) {
        renameAuthenticatorAlias(realm);
        renameCredentialTypesConfig(realm);
        renameHolderBindingMaxAgeConfig(realm);
        backfillFallbackToIsoSpecConfig(realm);
    }

    private void renameAuthenticatorAlias(RealmModel realm) {
        AuthenticationFlowModel flow = realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW);
        if (flow == null) {
            logger.debugf("No OID4VP auth flow in realm '%s'; nothing to rename", realm.getName());
            return;
        }

        int[] renamed = {0};
        for (AuthenticationExecutionModel execution :
                (Iterable<AuthenticationExecutionModel>) realm.getAuthenticationExecutionsStream(flow.getId())::iterator) {
            if (LEGACY_AUTHENTICATOR.equals(execution.getAuthenticator())) {
                execution.setAuthenticator(CURRENT_AUTHENTICATOR);
                realm.updateAuthenticatorExecution(execution);
                renamed[0]++;
            }
        }

        if (renamed[0] > 0) {
            logger.infof(
                    "Renamed %d execution(s) from '%s' to '%s' in realm '%s'",
                    renamed[0], LEGACY_AUTHENTICATOR, CURRENT_AUTHENTICATOR, realm.getName());
        } else {
            logger.debugf("No executions with legacy alias '%s' in realm '%s'", LEGACY_AUTHENTICATOR, realm.getName());
        }
    }

    private void renameCredentialTypesConfig(RealmModel realm) {
        renameConfigKey(
                realm,
                LEGACY_VCT_CONFIG_KEY,
                CURRENT_CREDENTIAL_TYPES_CONFIG_KEY,
                "Rename authenticator config key 'vct' to 'credentialTypes'");
    }

    private void renameHolderBindingMaxAgeConfig(RealmModel realm) {
        renameConfigKey(
                realm,
                LEGACY_KBJWT_MAX_AGE_CONFIG_KEY,
                CURRENT_HOLDER_BINDING_PROOF_MAX_AGE_CONFIG_KEY,
                "Rename authenticator config key 'kbJwtMaxAge' to 'holderBindingProofMaxAge'");
    }

    /**
     * Generic config-key rename helper. If {@code legacyKey} is present and {@code newKey} is not,
     * copies the legacy value to {@code newKey} and removes {@code legacyKey}.
     */
    private void renameConfigKey(RealmModel realm, String legacyKey, String newKey, String operation) {
        int renamed = MigrationUtils.renameKey(realm, legacyKey, newKey, LEGACY_AUTHENTICATOR, CURRENT_AUTHENTICATOR);
        if (renamed > 0) {
            logger.infof("%s on %d authenticator config(s) in realm '%s'", operation, renamed, realm.getName());
        } else {
            logger.debugf(
                    "No authenticator config in realm '%s' still carries legacy key '%s'", realm.getName(), legacyKey);
        }
    }

    private void backfillFallbackToIsoSpecConfig(RealmModel realm) {
        int updated = 0;
        for (AuthenticatorConfigModel config :
                MigrationUtils.configsInOid4vpFlow(realm, LEGACY_AUTHENTICATOR, CURRENT_AUTHENTICATOR)) {
            if (MigrationUtils.contains(config, CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY)) {
                continue;
            }
            MigrationUtils.put(
                    config,
                    CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY,
                    CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_DEFAULT);
            realm.updateAuthenticatorConfig(config);
            updated++;
        }

        if (updated > 0) {
            logger.infof(
                    "Backfilled '%s' default on %d authenticator config(s) in realm '%s'",
                    CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY, updated, realm.getName());
        } else {
            logger.debugf(
                    "No authenticator config in realm '%s' needed '%s' default backfill",
                    realm.getName(), CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY);
        }
    }
}
