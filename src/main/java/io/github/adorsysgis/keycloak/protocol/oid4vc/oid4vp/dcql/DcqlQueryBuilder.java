package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import java.util.UUID;

/**
 * Shared utilities for assembling DCQL queries.
 */
public final class DcqlQueryBuilder {

    private DcqlQueryBuilder() {}

    public static List<Claim> claimsFromPaths(List<List<String>> paths) {
        return paths.stream().map(DcqlQueryBuilder::claimFromPath).toList();
    }

    public static Claim claimFromPath(List<String> path) {
        Claim claim = new Claim();
        claim.setId(UUID.randomUUID().toString());
        claim.setPath(path);
        return claim;
    }

    public static DcqlQuery singleCredentialQuery(Credential credential) {
        // Keep credential_sets even for one credential for wallet interoperability (HAIP tests expect this shape).
        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(List.of(List.of(credential.getId())));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        query.setCredentialSets(List.of(credentialSet));
        return query;
    }
}
