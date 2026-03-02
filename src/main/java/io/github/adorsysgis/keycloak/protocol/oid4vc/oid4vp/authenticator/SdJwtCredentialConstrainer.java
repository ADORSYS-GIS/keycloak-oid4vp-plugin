package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Constraints;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Field;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Filter;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.InputDescriptor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.keycloak.protocol.oid4vc.model.Format;

/**
 * Constructs a presentation definition for requesting an SD-JWT credential.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtCredentialConstrainer {

    private static final String VCT_PATH = "$.vct";
    private static final String CLAIM_PATH_TEMPLATE = "$.%s";

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
        credential.setFormat(Format.SD_JWT_VC);
        credential.setMeta(meta);
        credential.setClaims(claims);

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        return query;
    }

    /**
     * Constructs a presentation definition requiring the disclosure of some claims.
     */
    public PresentationDefinition generatePresentationDefinition(QueryMap queryMap) {
        PresentationDefinition def = this.prebuildPresentationDefinition(queryMap.expectedVcts());

        // Set a unique identifier
        def.setId(UUID.randomUUID().toString());

        // Update field list with required claims
        List<Field> fieldList =
                def.getInputDescriptors().getFirst().getConstraints().getFields();
        queryMap.requiredClaims().forEach(claim -> {
            String path = String.format(CLAIM_PATH_TEMPLATE, claim);

            Field field = new Field();
            field.setPath(List.of(path));

            fieldList.add(field);
        });

        return def;
    }

    /**
     * Constructs a template presentation definition specifying no claims to disclose.
     */
    public PresentationDefinition prebuildPresentationDefinition(List<String> issuerVcts) {
        PresentationDefinition template = new PresentationDefinition();
        template.setName(OID4VPUserAuthEndpointFactory.PROVIDER_ID);

        InputDescriptor descriptor = new InputDescriptor();
        descriptor.setId(UUID.randomUUID().toString());
        template.setInputDescriptors(List.of(descriptor));

        Constraints constraints = new Constraints();
        constraints.setLimitDisclosure(Constraints.LimitDisclosure.REQUIRED);
        descriptor.setConstraints(constraints);

        Field field = new Field();
        field.setPath(List.of(VCT_PATH));
        constraints.setFields(new ArrayList<>(List.of(field)));

        List<Filter> anyOfFilters = issuerVcts.stream()
                .map(vct -> {
                    Filter filter = new Filter();
                    filter.setType(Filter.SimpleTypes.STRING);
                    filter.setConst(vct);
                    return filter;
                })
                .toList();

        Filter filter = new Filter();
        filter.setType(Filter.SimpleTypes.STRING);
        filter.setAnyOf(anyOfFilters);
        field.setFilter(filter);

        return template;
    }

    public record QueryMap(List<String> expectedVcts, List<String> requiredClaims) {}
}
