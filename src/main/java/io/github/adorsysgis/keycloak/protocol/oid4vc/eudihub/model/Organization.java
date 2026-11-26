package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model;

import java.util.List;

/** An organization with the environment and support URI options loaded from its EUDI Hub details. */
public record Organization(String id, String name, List<Environment> environments, List<String> supportUris) {}
