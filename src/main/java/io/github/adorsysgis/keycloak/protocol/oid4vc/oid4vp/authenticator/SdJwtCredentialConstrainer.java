package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Constraints;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Field;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Filter;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.InputDescriptor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Constructs a presentation definition for requesting an SD-JWT credential.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtCredentialConstrainer {

    private static final String VCT_PATH = "$.vct";
    private static final String CLAIM_PATH_TEMPLATE = "$.%s";

    /**
     * Constructs a presentation definition requiring the disclosure of some claims.
     */
    public PresentationDefinition generatePresentationDefinition(List<String> issuerVcts, List<String> requiredClaims) {
        PresentationDefinition def = this.prebuildPresentationDefinition(issuerVcts);

        // Set a unique identifier
        def.setId(UUID.randomUUID().toString());

        // Update field list with required claims
        List<Field> fieldList =
                def.getInputDescriptors().get(0).getConstraints().getFields();
        requiredClaims.forEach(claim -> {
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
}
