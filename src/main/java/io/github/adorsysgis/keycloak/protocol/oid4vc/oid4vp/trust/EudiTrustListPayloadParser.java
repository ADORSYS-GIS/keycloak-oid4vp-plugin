package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustListProvider.TrustedPidIssuanceService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustListProvider.TrustedPidProvider;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Parses the ETSI TS 119 602 JSON binding used by the EUDI PID Provider LoTE profile. */
class EudiTrustListPayloadParser {

    TrustListData parse(JsonNode payload, String serviceType) throws EudiPidTrustException {
        JsonNode lote = payload.path("LoTE");
        if (!lote.isObject()) {
            throw new EudiPidTrustException("EUDI trust list is missing LoTE");
        }

        JsonNode listInformation = lote.path("ListAndSchemeInformation");
        validateLoteType(listInformation);
        Instant nextUpdate = readInstant(listInformation.path("NextUpdate"), "NextUpdate");
        validateOptionalIssueTime(listInformation.path("ListIssueDateTime"), nextUpdate);

        return new TrustListData(nextUpdate, extractProviders(lote.path("TrustedEntitiesList"), serviceType));
    }

    private void validateLoteType(JsonNode listInformation) throws EudiPidTrustException {
        String loteType = listInformation.path("LoTEType").asText(null);
        if (!EudiPidTrustListProvider.PID_PROVIDERS_LOTE_TYPE.equals(loteType)) {
            throw new EudiPidTrustException("EUDI trust list is not an ETSI TS 119 602 PID Providers LoTE");
        }
    }

    private void validateOptionalIssueTime(JsonNode issueTimeNode, Instant nextUpdate) throws EudiPidTrustException {
        if (issueTimeNode.isMissingNode() || issueTimeNode.isNull()) {
            return;
        }
        Instant issueTime = readInstant(issueTimeNode, "ListIssueDateTime");
        if (!issueTime.isBefore(nextUpdate)) {
            throw new EudiPidTrustException("EUDI trust list ListIssueDateTime must be before NextUpdate");
        }
    }

    private Instant readInstant(JsonNode value, String fieldName) throws EudiPidTrustException {
        if (!value.isTextual()) {
            throw new EudiPidTrustException("EUDI trust list is missing LoTE.ListAndSchemeInformation." + fieldName);
        }
        try {
            return Instant.parse(value.asText());
        } catch (DateTimeParseException e) {
            throw new EudiPidTrustException("EUDI trust list " + fieldName + " is not an ISO-8601 instant", e);
        }
    }

    private List<TrustedPidProvider> extractProviders(JsonNode entities, String serviceType)
            throws EudiPidTrustException {
        if (!entities.isArray()) {
            throw new EudiPidTrustException("EUDI trust list is missing LoTE.TrustedEntitiesList");
        }

        List<TrustedPidProvider> providers = new ArrayList<>();
        for (JsonNode entity : entities) {
            TrustedPidProvider provider = parseProvider(entity, serviceType);
            if (!provider.issuanceServices().isEmpty()) {
                providers.add(provider);
            }
        }
        return providers;
    }

    private TrustedPidProvider parseProvider(JsonNode entity, String serviceType) throws EudiPidTrustException {
        JsonNode entityInformation = entity.path("TrustedEntityInformation");
        List<String> names = readValues(entityInformation.path("TEName"));
        if (names.isEmpty()) {
            throw new EudiPidTrustException("EUDI PID Provider entry is missing TrustedEntityInformation.TEName");
        }

        // Annex D carries the official registration identifier in TETradeName where one exists. Fall back to TEName
        // only for older sandbox LoTEs which omit TETradeName; a display name must not override an available official
        // identifier.
        List<String> tradeNames = readValues(entityInformation.path("TETradeName"));
        Set<String> identifiers = new LinkedHashSet<>(tradeNames.isEmpty() ? names : tradeNames);

        JsonNode servicesNode = entity.path("TrustedEntityServices");
        if (!servicesNode.isArray()) {
            throw new EudiPidTrustException(
                    "EUDI PID Provider entry is missing TrustedEntityServices: " + names.getFirst());
        }

        List<TrustedPidIssuanceService> services = new ArrayList<>();
        for (JsonNode serviceNode : servicesNode) {
            JsonNode serviceInformation = serviceNode.path("ServiceInformation");
            if (!serviceType.equals(
                    serviceInformation.path("ServiceTypeIdentifier").asText())) {
                continue;
            }

            List<X509Certificate> certificates = readCertificates(serviceInformation);
            if (certificates.isEmpty()) {
                throw new EudiPidTrustException(
                        "EUDI PID issuance service contains no X.509 certificates: " + names.getFirst());
            }
            List<String> serviceNames = readValues(serviceInformation.path("ServiceName"));
            services.add(new TrustedPidIssuanceService(
                    serviceNames.isEmpty() ? serviceType : serviceNames.getFirst(), certificates));
        }

        return new TrustedPidProvider(names.getFirst(), List.copyOf(identifiers), services);
    }

    private List<X509Certificate> readCertificates(JsonNode serviceInformation) throws EudiPidTrustException {
        JsonNode x509Certificates = serviceInformation.at("/ServiceDigitalIdentity/X509Certificates");
        if (!x509Certificates.isArray()) {
            return List.of();
        }

        List<X509Certificate> certificates = new ArrayList<>();
        for (JsonNode certificateNode : x509Certificates) {
            JsonNode value = certificateNode.path("val");
            if (!value.isTextual()) {
                throw new EudiPidTrustException("EUDI trust-list X509Certificates entry is missing val");
            }
            certificates.add(parseTrustListCertificate(value.asText()));
        }
        return certificates;
    }

    private List<String> readValues(JsonNode values) {
        if (!values.isArray()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (JsonNode value : values) {
            String text = value.path("value").asText(null);
            if (text != null && !text.isBlank()) {
                result.add(text);
            }
        }
        return result;
    }

    private X509Certificate parseTrustListCertificate(String value) throws EudiPidTrustException {
        try {
            return CertificateUtil.parseCertificate(value);
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not parse EUDI trust-list service certificate", e);
        }
    }

    record TrustListData(Instant nextUpdate, List<TrustedPidProvider> providers) {
        TrustListData {
            providers = List.copyOf(providers);
        }
    }
}
