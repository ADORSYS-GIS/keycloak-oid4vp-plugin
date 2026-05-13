package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.List;
import java.util.UUID;
import org.keycloak.VCFormat;

/**
 * Constructs a DCQL query for requesting an SD-JWT credential.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtCredentialConstrainer {

    /**
     * Constructs a DCQL query requiring the disclosure of some claims.
     */
    public DcqlQuery generateDcqlQuery(QueryMap queryMap) {
        Meta meta = new Meta();
        meta.setVctValues(queryMap.expectedVcts());

        List<Claim> claims = queryMap.requiredClaims().stream()
                .map(claimName -> {
                    Claim claim = new Claim();
                    claim.setId(UUID.randomUUID().toString());
                    claim.setPath(List.of(claimName));
                    return claim;
                })
                .toList();

        Credential credential = new Credential();
        credential.setId(UUID.randomUUID().toString());
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(meta);
        credential.setClaims(claims);

        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(List.of(List.of(credential.getId())));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        query.setCredentialSets(List.of(credentialSet));
        return query;
    }

    public record QueryMap(List<String> expectedVcts, List<String> requiredClaims) {}
}
