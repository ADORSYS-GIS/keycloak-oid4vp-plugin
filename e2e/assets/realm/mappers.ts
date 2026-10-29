// The OID4VC claim mappers of the IdentityCredential scope.

// ---- Claim mappers ------------------------------------------------------------

export const mapper = {
  userAttribute(claimName: string, userAttribute: string, display: string) {
    return {
      name: `${claimName}-mapper`,
      protocol: "oid4vc",
      protocolMapper: "oid4vc-user-attribute-mapper",
      config: {
        "claim.name": claimName,
        userAttribute,
        "vc.mandatory": "false",
        "vc.display": display,
      },
    };
  },
  givenName() {
    return this.userAttribute(
      "given_name",
      "firstName",
      '[{"name": "Given Name", "locale": "en"}]',
    );
  },
  familyName() {
    return this.userAttribute(
      "family_name",
      "lastName",
      '[{"name": "Family Name", "locale": "en"}]',
    );
  },
  issuedAt() {
    return {
      name: `iat-oid4vc-issued-at-time-claim-mapper-identity_credential`,
      protocol: "oid4vc",
      protocolMapper: "oid4vc-issued-at-time-claim-mapper",
      config: { "claim.name": "iat", truncateToTimeUnit: "HOURS", valueSource: "COMPUTE" },
    };
  },
  notBefore() {
    return {
      name: `nbf-oid4vc-issued-at-time-claim-mapper-identity_credential`,
      protocol: "oid4vc",
      protocolMapper: "oid4vc-issued-at-time-claim-mapper",
      config: { "claim.name": "nbf", valueSource: "COMPUTE" },
    };
  },
  // `sub` = the Keycloak user id; the OpenID4VP authenticator resolves the
  // authenticating user through this claim.
  subject() {
    return {
      name: "id-mapper-identity",
      protocol: "oid4vc",
      protocolMapper: "oid4vc-subject-id-mapper",
      config: { "claim.name": "sub", userAttribute: "id" },
    };
  },
  // Ties the credential to the revocation status-list published on the status
  // server; without it the token-status plugin has nothing to look up on revoke.
  statusListClaim() {
    return {
      name: "status-list-claim-mapper",
      protocol: "oid4vc",
      protocolMapper: "oid4vc-status-list-claim-mapper",
      config: {},
    };
  },
};
