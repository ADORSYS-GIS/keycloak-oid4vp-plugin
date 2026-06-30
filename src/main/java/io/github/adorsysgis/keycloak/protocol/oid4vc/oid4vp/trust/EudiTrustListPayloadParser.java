package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import com.fasterxml.jackson.databind.JsonNode;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

class EudiTrustListPayloadParser {

    TrustListData parse(JsonNode payload, String serviceType) throws EudiPidTrustException {
        return new TrustListData(readNextUpdate(payload), extractServiceCertificates(payload, serviceType));
    }

    private Instant readNextUpdate(JsonNode payload) throws EudiPidTrustException {
        JsonNode nextUpdate = payload.at("/LoTE/ListAndSchemeInformation/NextUpdate");
        if (!nextUpdate.isTextual()) {
            throw new EudiPidTrustException("EUDI trust list is missing LoTE.ListAndSchemeInformation.NextUpdate");
        }
        try {
            return Instant.parse(nextUpdate.asText());
        } catch (DateTimeParseException e) {
            throw new EudiPidTrustException("EUDI trust list NextUpdate is not an ISO-8601 instant", e);
        }
    }

    private List<X509Certificate> extractServiceCertificates(JsonNode payload, String serviceType)
            throws EudiPidTrustException {
        List<X509Certificate> certificates = new ArrayList<>();
        JsonNode entities = payload.at("/LoTE/TrustedEntitiesList");
        if (!entities.isArray()) {
            throw new EudiPidTrustException("EUDI trust list is missing LoTE.TrustedEntitiesList");
        }

        for (JsonNode entity : entities) {
            JsonNode services = entity.at("/TrustedEntityServices");
            if (!services.isArray()) {
                continue;
            }
            for (JsonNode service : services) {
                JsonNode serviceInfo = service.at("/ServiceInformation");
                if (!serviceType.equals(
                        serviceInfo.path("ServiceTypeIdentifier").asText())) {
                    continue;
                }
                addServiceCertificates(certificates, serviceInfo);
            }
        }
        return certificates;
    }

    private void addServiceCertificates(List<X509Certificate> certificates, JsonNode serviceInfo)
            throws EudiPidTrustException {
        JsonNode x509Certificates = serviceInfo.at("/ServiceDigitalIdentity/X509Certificates");
        if (!x509Certificates.isArray()) {
            return;
        }
        for (JsonNode certificateNode : x509Certificates) {
            JsonNode value = certificateNode.path("val");
            if (value.isTextual()) {
                certificates.add(parseTrustListCertificate(value.asText()));
            }
        }
    }

    private X509Certificate parseTrustListCertificate(String value) throws EudiPidTrustException {
        try {
            return CertificateUtil.parseCertificate(value);
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not parse EUDI trust-list service certificate", e);
        }
    }

    record TrustListData(Instant nextUpdate, List<X509Certificate> serviceCertificates) {}
}
