package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.utils.StringUtil;

/**
 * Registry of format-specific {@link DcqlCredentialCapability} implementations.
 */
public final class DcqlCredentialCapabilities {

    private final Map<String, DcqlCredentialCapability> capabilitiesByFormat;

    public DcqlCredentialCapabilities(List<DcqlCredentialCapability> capabilities) {
        if (capabilities == null || capabilities.isEmpty()) {
            throw new IllegalArgumentException("At least one DCQL credential capability is required");
        }

        Map<String, DcqlCredentialCapability> registeredCapabilities = new LinkedHashMap<>();
        for (DcqlCredentialCapability capability : capabilities) {
            if (capability == null) {
                throw new IllegalArgumentException("DCQL credential capability must not be null");
            }
            String format = capability.format();
            if (StringUtil.isBlank(format)) {
                throw new IllegalArgumentException("DCQL credential capability format must be non-empty");
            }
            if (registeredCapabilities.putIfAbsent(format, capability) != null) {
                throw new IllegalArgumentException("Duplicate DCQL credential capability format: " + format);
            }
        }
        this.capabilitiesByFormat = Collections.unmodifiableMap(registeredCapabilities);
    }

    public static DcqlCredentialCapabilities createDefault() {
        return new DcqlCredentialCapabilities(
                List.of(new SdJwtDcqlCredentialCapability(), new MdocDcqlCredentialCapability()));
    }

    public List<DcqlCredentialCapability> all() {
        return List.copyOf(capabilitiesByFormat.values());
    }

    public DcqlCredentialCapability require(String format) {
        if (StringUtil.isBlank(format)) {
            throw new IllegalArgumentException("DCQL credential format must be non-empty");
        }
        DcqlCredentialCapability capability = capabilitiesByFormat.get(format);
        if (capability == null) {
            throw new IllegalArgumentException("No DCQL credential capability for format: " + format);
        }
        return capability;
    }
}
