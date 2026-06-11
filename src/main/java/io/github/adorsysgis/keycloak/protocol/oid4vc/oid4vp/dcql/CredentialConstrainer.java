package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;

/**
 * Builds a format-specific credential query within a DCQL query.
 */
public interface CredentialConstrainer<S> {

    String format();

    Credential buildCredential(S spec);

    default DcqlQuery buildQuery(S spec) {
        Credential credential = buildCredential(spec);
        DcqlQueryValidator.validateCredential(credential);
        return DcqlQueryBuilder.singleCredentialQuery(credential);
    }
}
