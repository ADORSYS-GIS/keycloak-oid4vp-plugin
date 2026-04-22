package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum QueryLanguage {
    DCQL_QUERY("dcql_query"),
    DIF_PRESENTATION_EXCHANGE("dif_presentation_exchange"),
    ;

    private final String value;

    QueryLanguage(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    public static QueryLanguage fromValue(String value) {
        for (QueryLanguage lang : QueryLanguage.values()) {
            if (lang.value.equalsIgnoreCase(value)) {
                return lang;
            }
        }

        throw new IllegalArgumentException("Unknown query language: " + value);
    }
}
