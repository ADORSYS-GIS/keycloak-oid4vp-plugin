package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.matcher;

/**
 * Format-neutral personal data exchanged across the PID matcher SPI. All fields are plain strings to
 * avoid coupling the SPI to any credential format or date representation; {@code birthDate} is the
 * raw claim/attribute value (typically ISO {@code yyyy-MM-dd}).
 *
 * <p>An implementation of {@link PidMatcherProvider} compares the {@code presented} PID against the
 * {@code registered} user data and reports mismatching attribute names only (never the values).
 */
public record PidData(String givenNames, String familyName, String birthDate) {}
