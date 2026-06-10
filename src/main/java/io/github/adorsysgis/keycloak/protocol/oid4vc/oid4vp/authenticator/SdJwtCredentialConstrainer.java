package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
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
        Credential credential = toCredentialQuery(UUID.randomUUID().toString(), queryMap);

        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(List.of(List.of(credential.getId())));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        query.setCredentialSets(List.of(credentialSet));
        return query;
    }

    /**
     * Constructs a DCQL query with one credential query per configured profile credential.
     */
    public DcqlQuery generateDcqlQuery(AuthenticationProfile profile) {
        return generateDcqlQuery(profile, true);
    }

    /**
     * Constructs a DCQL query with one credential query per configured profile credential.
     */
    public DcqlQuery generateDcqlQuery(AuthenticationProfile profile, boolean requireCryptographicHolderBinding) {
        List<Credential> credentials = profile.getCredentials().stream()
                .map(requirement -> toCredentialQuery(requirement, requireCryptographicHolderBinding))
                .toList();

        CredentialSet credentialSet = new CredentialSet();
        // A single option containing all credential IDs means the profile requires
        // the wallet to satisfy every credential query, not just one alternative.
        credentialSet.setOptions(
                List.of(credentials.stream().map(Credential::getId).toList()));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(credentials);
        query.setCredentialSets(List.of(credentialSet));
        return query;
    }

    private Credential toCredentialQuery(CredentialRequirement requirement, boolean requireCryptographicHolderBinding) {
        return toCredentialQuery(
                requirement.getId(),
                new QueryMap(
                        requirement.getCredentialTypes(), requirement.getClaims(), requireCryptographicHolderBinding));
    }

    private Credential toCredentialQuery(String id, QueryMap queryMap) {
        Meta meta = new Meta();
        meta.setVctValues(queryMap.expectedVcts());

        List<Claim> claims = queryMap.requiredClaims().stream()
                .map(SdJwtCredentialConstrainer::toClaim)
                .toList();

        Credential credential = new Credential();
        credential.setId(id);
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(meta);
        credential.setClaims(claims);
        if (!queryMap.requireCryptographicHolderBinding()) {
            credential.setRequireCryptographicHolderBinding(false);
        }
        return credential;
    }

    private static Claim toClaim(String claimName) {
        Claim claim = new Claim();
        claim.setId(UUID.randomUUID().toString());
        claim.setPath(List.of(claimName));
        return claim;
    }

    public record QueryMap(
            List<String> expectedVcts, List<String> requiredClaims, boolean requireCryptographicHolderBinding) {
        public QueryMap(List<String> expectedVcts, List<String> requiredClaims) {
            this(expectedVcts, requiredClaims, true);
        }
    }
}
