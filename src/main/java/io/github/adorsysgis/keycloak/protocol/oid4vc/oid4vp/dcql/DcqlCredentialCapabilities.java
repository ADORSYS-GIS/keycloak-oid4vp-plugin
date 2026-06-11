package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;

/**
 * Registry of format-specific {@link DcqlCredentialCapability} implementations.
 */
public final class DcqlCredentialCapabilities {

    private final List<DcqlCredentialCapability> capabilities;

    public DcqlCredentialCapabilities(List<DcqlCredentialCapability> capabilities) {
        if (capabilities == null || capabilities.isEmpty()) {
            throw new IllegalArgumentException("At least one DCQL credential capability is required");
        }
        this.capabilities = List.copyOf(capabilities);
    }

    public static DcqlCredentialCapabilities createDefault() {
        return new DcqlCredentialCapabilities(List.of(new SdJwtDcqlCredentialCapability()));
    }

    public List<DcqlCredentialCapability> all() {
        return capabilities;
    }

    public DcqlCredentialCapability resolve(VerifierConfig config) {
        return capabilities.stream()
                .filter(capability -> capability.supports(config))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No DCQL credential capability supports verifier config"));
    }

    public DcqlCredentialCapability resolveForPresentation(DcqlQuery query) {
        if (query == null
                || query.getCredentials() == null
                || query.getCredentials().size() != 1) {
            throw new IllegalStateException("DCQL presentation validation requires exactly one credential query");
        }
        String format = query.getCredentials().getFirst().getFormat();
        return capabilities.stream()
                .filter(capability -> capability.format().equals(format))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No DCQL credential capability for format: " + format));
    }
}
