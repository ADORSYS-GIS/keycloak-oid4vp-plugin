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

    /**
     * Constructs a DCQL query with one credential query per configured profile credential.
     */
    public DcqlQuery generateDcqlQuery(AuthenticationProfile profile) {
        List<Credential> credentials =
                profile.getCredentials().stream().map(this::toCredentialQuery).toList();

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

    private Credential toCredentialQuery(CredentialRequirement requirement) {
        Meta meta = new Meta();
        meta.setVctValues(requirement.getVct());

        List<Claim> claims = requirement.getClaims().stream()
                .map(claimName -> {
                    Claim claim = new Claim();
                    claim.setId(UUID.randomUUID().toString());
                    claim.setPath(List.of(claimName));
                    return claim;
                })
                .toList();

        Credential credential = new Credential();
        credential.setId(requirement.getId());
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(meta);
        credential.setClaims(claims);
        return credential;
    }

    public record QueryMap(List<String> expectedVcts, List<String> requiredClaims) {}
}
