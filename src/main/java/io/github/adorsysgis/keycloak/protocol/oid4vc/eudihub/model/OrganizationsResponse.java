package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model;

import java.util.List;

/** Organizations returned to the admin UI. */
public record OrganizationsResponse(List<Organization> organizations) {}
