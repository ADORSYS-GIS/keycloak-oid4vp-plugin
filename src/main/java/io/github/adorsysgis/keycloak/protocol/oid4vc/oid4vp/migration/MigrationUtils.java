package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;

/**
 * Internal helpers for iterating over the authenticator configs of executions in the
 * {@link OID4VPUserAuthEndpointBase#OID4VP_AUTH_FLOW oid4vp auth} flow, and for reading/writing
 * individual config entries. Returned configs are mutable Keycloak models callers may persist via
 * {@link RealmModel#updateAuthenticatorConfig(AuthenticatorConfigModel)}.
 */
public final class MigrationUtils {

    private MigrationUtils() {}

    /**
     * Returns the mutable authenticator configs of every execution in the OID4VP auth flow whose
     * authenticator matches any of the given provider IDs.
     *
     * <p>Configs whose ID is {@code null} (i.e. executions with no config attached) are skipped.
     * Passing multiple IDs lets callers match both the current authenticator and any legacy
     * aliases after a rename.
     *
     * <p>{@link Set#of(Object[])} is used to deduplicate the lookup set and intentionally throws
     * {@link IllegalArgumentException} when called with duplicate provider ids: the caller has
     * almost certainly made a mistake and silently dropping the duplicate would mask it.
     */
    public static List<AuthenticatorConfigModel> configsInOid4vpFlow(RealmModel realm, String... providerIds) {
        AuthenticationFlowModel flow = realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW);
        if (flow == null) {
            return List.of();
        }
        Set<String> ids = Set.of(providerIds);

        return realm.getAuthenticationExecutionsStream(flow.getId())
                .filter(execution -> ids.contains(execution.getAuthenticator()))
                .map(AuthenticationExecutionModel::getAuthenticatorConfig)
                .filter(configId -> configId != null && !configId.isBlank())
                .map(realm::getAuthenticatorConfigById)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /**
     * Sets {@code key} to {@code value} on {@code config}, creating the config map if missing.
     */
    public static void put(AuthenticatorConfigModel config, String key, String value) {
        Map<String, String> map = config.getConfig();
        if (map == null) {
            map = new LinkedHashMap<>();
            config.setConfig(map);
        }
        map.put(key, value);
    }

    /**
     * Removes {@code key} from {@code config}. No-op when the key or the config map is absent.
     */
    public static void remove(AuthenticatorConfigModel config, String key) {
        Map<String, String> map = config.getConfig();
        if (map != null) {
            map.remove(key);
        }
    }

    /**
     * Returns {@code true} when {@code config} contains {@code key}.
     */
    public static boolean contains(AuthenticatorConfigModel config, String key) {
        Map<String, String> map = config.getConfig();
        return map != null && map.containsKey(key);
    }

    /**
     * Returns the value of {@code key} from {@code config}, or {@code null} when absent.
     */
    public static String get(AuthenticatorConfigModel config, String key) {
        Map<String, String> map = config.getConfig();
        return map == null ? null : map.get(key);
    }

    /**
     * Renames a config key across every authenticator config of executions in the OID4VP auth flow
     * whose authenticator matches any of the given provider IDs. If {@code legacyKey} is present and
     * {@code newKey} is not, copies the legacy value to {@code newKey}; the legacy key is always
     * removed when present. Each touched config is persisted via
     * {@link RealmModel#updateAuthenticatorConfig(AuthenticatorConfigModel)}.
     *
     * @return the number of authenticator configs that were updated
     */
    public static int renameKey(RealmModel realm, String legacyKey, String newKey, String... providerIds) {
        int renamed = 0;
        for (AuthenticatorConfigModel config : configsInOid4vpFlow(realm, providerIds)) {
            String legacyValue = get(config, legacyKey);
            if (legacyValue == null) {
                continue;
            }
            if (!contains(config, newKey)) {
                put(config, newKey, legacyValue);
            }
            remove(config, legacyKey);
            realm.updateAuthenticatorConfig(config);
            renamed++;
        }
        return renamed;
    }
}
