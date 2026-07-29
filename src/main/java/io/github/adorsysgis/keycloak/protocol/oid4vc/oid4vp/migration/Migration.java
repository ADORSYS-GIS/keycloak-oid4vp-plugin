package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * A single, idempotent realm-level migration applied by {@link OID4VPMigrationManager}.
 *
 * <p>Migrations are applied in the order they are registered with the manager. The manager resumes
 * from the first migration whose {@link #id()} comes after the realm's recorded last-applied
 * migration; migrations before that point are skipped.
 *
 * <p>Implementations <strong>must</strong> be idempotent so that re-running a migration (e.g. after
 * a partial failure followed by a restart) does not corrupt realm state. Idempotency is typically
 * achieved by checking for the presence of the <em>pre-migration</em> marker (e.g. an authenticator
 * alias or a config key that no longer exists) before applying any change.
 */
public interface Migration {

    /**
     * Stable identifier for this migration. Logged on application and recorded on the realm as the
     * last-applied migration marker.
     */
    String id();

    /**
     * Apply this migration to the given realm.
     *
     * <p>Implementations must be idempotent and must not assume the realm is fresh. They should
     * inspect current state, mutate it as needed, and return without throwing on a successful (or
     * already-applied) migration. Throwing aborts the manager and is logged for the operator.
     */
    void apply(KeycloakSession session, RealmModel realm);
}
