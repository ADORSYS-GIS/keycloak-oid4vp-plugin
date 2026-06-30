package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.matcher;

import java.util.List;
import org.keycloak.provider.Provider;

/**
 * SPI for matching the PID presented during OID4VCI "presentation during issuance" against the
 * brokered user's registration data. Implementations are external (e.g. a deployment-specific,
 * proprietary matcher) and are resolved by the issuance flow when present.
 *
 * <p>The issuance gate continues only when {@link #findMismatchedAttributes(PidData, PidData)}
 * returns an empty list. Implementations MUST return attribute identifiers only and MUST NOT return
 * or log the underlying personal values (PII).
 */
public interface PidMatcherProvider extends Provider {

    /**
     * @param presented the PID claims presented by the wallet
     * @param registered the brokered user's registration data
     * @return the identifiers of mismatching attributes; empty when the identities match
     */
    List<String> findMismatchedAttributes(PidData presented, PidData registered);

    @Override
    default void close() {}
}
