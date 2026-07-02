package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding;

import org.keycloak.provider.Provider;

/**
 * Compares a credential claim value presented during a binding check against an expected value
 * (either another credential's claim or a Keycloak user attribute).
 *
 * <p>This SPI keeps value-comparison semantics pluggable and free of any hard-coded credential
 * schema. The open-source plugin ships only the schema-neutral {@code exact} strategy; deployments
 * requiring tolerant, locale-specific matching (e.g. umlaut transcription or name-fragment
 * stripping for German PID data) provide their own comparator via a separate provider
 */
public interface BindingValueComparator extends Provider {

    /**
     * @param presentedValue the value read from the presented credential (may be {@code null}/blank)
     * @param expectedValue the value to match against (may be {@code null})
     * @return {@code true} when the two values are considered equal under this strategy
     */
    boolean matches(String presentedValue, String expectedValue);

    @Override
    default void close() {}
}
