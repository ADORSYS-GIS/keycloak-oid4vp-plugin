# Dual Credential PID Login Implementation Plan

## Purpose

Add a separate OpenID4VP login flow that requests and verifies both a PID credential and a Tax Advisor credential in one wallet presentation. The existing single-credential wallet login must remain unchanged.

The initial matching rule is:

- `PID.firstname == TaxAdvisor.firstname`
- `PID.lastname == TaxAdvisor.lastname`

These claim names are intentionally isolated in configuration because the customer may later choose stronger or different matching claims.

## Goals

- Keep the current wallet login flow working as it does today.
- Add a new "login with PID" flow with its own configuration and verification policy.
- Request two SD-JWT VC credentials in a single OpenID4VP authorization request.
- Verify each credential against the correct trust policy.
- Enforce a trust chain for externally issued PID credentials.
- Match identity claims across PID and Tax Advisor credentials before authenticating the Keycloak user.
- Authenticate the Keycloak user from the Tax Advisor credential, not from the PID.
- Keep the implementation maintainable enough to support future credential types and stronger matching rules.

## Non-Goals

- Do not replace or weaken the existing Keycloak-issued SD-JWT login flow.
- Do not accept arbitrary external PID issuers.
- Do not disable issuer validation as a shortcut for external PID support.
- Do not hard-code customer-specific claim mappings outside a dedicated configuration object.
- Do not implement mdoc support as part of this flow.

## Key Design Decisions

### Separate Verification Profile

Introduce a verification profile concept so the same OpenID4VP transport can serve multiple login flows:

- `single_sd_jwt`: current wallet login behavior.
- `dual_pid_tax_advisor`: new PID plus Tax Advisor login behavior.

The selected profile must be stored in the authorization context because the wallet response arrives later through the `requestId`.

### Separate Configuration

The dual flow must have separate configuration from the existing single credential flow. The configuration should include:

- PID credential query ID, for example `pid`.
- PID accepted `vct` values.
- PID issuer trust policy.
- PID required claims, initially `firstname`, `lastname`.
- Tax Advisor credential query ID, for example `tax_advisor`.
- Tax Advisor accepted `vct` values.
- Tax Advisor issuer trust policy, initially existing Keycloak realm trust.
- Tax Advisor required claims, initially `sub`, `username`, `firstname`, `lastname`.
- Claim matching rules, initially `firstname` and `lastname`.
- Revocation/status policy per credential role.

### Trust Model

The external PID issuer must be trusted through explicit policy. The minimum acceptable trust model is:

- Allow-list the PID issuer identifier.
- Validate the credential signature using issuer keys resolved from a trusted source.
- Validate the issuer key material against configured trust anchors or pinned keys.
- Reject credentials from unknown issuers, unknown keys, expired certificates, unsupported algorithms, or invalid chains.

Prefer X.509 trust anchors for production PID issuer trust. Pinned JWKS can be useful for a first controlled integration, but it is weaker operationally unless key rotation is handled carefully.

### Authentication Source

The Tax Advisor credential remains the source for resolving the Keycloak user. The PID credential only strengthens possession and identity binding by proving that the wallet holder can present a matching externally issued PID.

## Proposed Flow

1. The login page shows the existing wallet login option and a new PID login option.
2. The user selects PID login.
3. The plugin starts OpenID4VP authorization with profile `dual_pid_tax_advisor`.
4. The request object contains a DCQL query for both `pid` and `tax_advisor`.
5. The wallet returns `vp_token` as a JSON object keyed by DCQL credential query IDs.
6. The response parser extracts the PID SD-JWT VP and Tax Advisor SD-JWT VP by query ID.
7. The verifier validates the PID credential using the external issuer trust policy.
8. The verifier validates the Tax Advisor credential using Keycloak or configured Tax Advisor trust.
9. The verifier extracts `firstname` and `lastname` from both credentials.
10. The verifier rejects the response if the configured claims do not match.
11. The authenticator resolves and authenticates the Keycloak user from the Tax Advisor credential.

## Sub-Tickets

| Ticket | Title | Description | Estimate |
| --- | --- | --- | --- |
| DUAL-01 | Introduce Verification Profile Model | Add an enum or value object for verification profiles. Include `single_sd_jwt` and `dual_pid_tax_advisor`. Store the selected profile in `AuthorizationContext` and preserve current behavior as the default. | 0.5-1 day |
| DUAL-02 | Add Dual Flow Configuration Model | Add configuration classes for PID and Tax Advisor credential policies, required claims, matching rules, issuer trust, and status validation. Keep config separate from the current single SD-JWT authenticator settings. | 1-2 days |
| DUAL-03 | Add Profile Selection to Login UI Backend | Extend `OID4VPUserAuthBean` and endpoint startup logic so a new login method can start the dual profile without affecting `login_method=oid4vp`. Use a clear value such as `login_method=dual_pid`. | 1 day |
| DUAL-04 | Add Frontend PID Login Button | Update the client app to show a second button for "login with PID". The button should call the same Keycloak flow with the new login method/profile selector. This is likely in the mock frontend repository, not this plugin repository. | 0.5-1 day |
| DUAL-05 | Build Dual-Credential DCQL Query | Extend or replace `SdJwtCredentialConstrainer` so it can generate a DCQL query with stable credential IDs for `pid` and `tax_advisor`. Each credential entry must include the correct format, vct values, required claims, and credential set requirements. | 1-2 days |
| DUAL-06 | Preserve Query-ID to VP Mapping | Extend `VpTokenCandidateExtractor` or add a new extractor that returns SD-JWT presentations by credential query ID. The dual flow must not collapse all SD-JWT candidates into a single token. | 1 day |
| DUAL-07 | Create External Issuer Trust Policy Parser | Add a parser for configured trusted PID issuers. It should validate required fields at startup/request time and fail closed for incomplete trust policy. | 1-1.5 days |
| DUAL-08 | Implement External PID Issuer Key Resolver | Implement a `TrustedSdJwtIssuer` resolver for configured external PID issuers. It should resolve issuer keys from configured trusted material and reject unknown issuer/key combinations. | 2-3 days |
| DUAL-09 | Add X.509 Chain Validation | Validate `x5c` chains against configured trust anchors when PID issuer trust is certificate based. Check certificate validity, chain signatures, key usage where available, and supported algorithms. | 2-4 days |
| DUAL-10 | Support Pinned JWKS as Optional Trust Mode | Optionally support pinned JWKS for controlled test or pilot environments. Document the operational risk and require explicit issuer allow-listing. | 1-2 days |
| DUAL-11 | Verify Multiple SD-JWT Presentations | Add a verification service that accepts the mapped PID and Tax Advisor SD-JWT VPs, applies the correct trust policy to each, and returns verified credential payloads plus disclosures. | 2 days |
| DUAL-12 | Implement Claim Extraction Service | Centralize extraction of plain and selectively disclosed claims from SD-JWT credentials. Support nested paths later, but initially support top-level `firstname` and `lastname`. | 1 day |
| DUAL-13 | Implement Claim Matching Rules | Add a matcher that compares configured claims across PID and Tax Advisor credentials. Start with exact string equality for `firstname` and `lastname`. Normalize only if explicitly agreed later. | 1 day |
| DUAL-14 | Authenticate User from Tax Advisor Credential | Ensure the final Keycloak user lookup uses the verified Tax Advisor credential. Keep current checks for subject, username, enabled user, and username mismatch. | 1 day |
| DUAL-15 | Add Dual Flow Error Handling | Add clear errors for missing PID, missing Tax Advisor credential, unknown issuer, failed trust chain, missing claims, and claim mismatch. Sanitize responses while keeping logs useful. | 1 day |
| DUAL-16 | Add Unit Tests for Configuration and DCQL | Cover dual configuration parsing, invalid configs, generated DCQL credential IDs, required claims, vct values, and credential set requirements. | 1 day |
| DUAL-17 | Add Unit Tests for Trust Resolution | Cover trusted issuer success, unknown issuer, unknown key, bad chain, expired certificate, unsupported algorithm, and missing `x5c` or JWKS material. | 2 days |
| DUAL-18 | Add Unit Tests for Claim Extraction and Matching | Cover disclosed and non-disclosed claims, missing claims, mismatched claims, and successful `firstname`/`lastname` match. | 1 day |
| DUAL-19 | Add Integration Tests for Dual Login | Add end-to-end tests for successful dual presentation, missing PID, missing Tax Advisor credential, mismatched names, invalid PID issuer, and current single wallet login regression. | 3-4 days |
| DUAL-20 | Documentation and Admin Guidance | Document the new flow, configuration examples, trust policy setup, operational key rotation notes, and current limitation that initial matching uses `firstname` and `lastname`. | 1-1.5 days |

## Suggested PR Sequence

### PR 1: Profile Selection and Configuration Skeleton

Includes:

- DUAL-01
- DUAL-02
- DUAL-03
- Initial tests for profile selection and configuration defaults

Expected size: 2-4 days.

### PR 2: Dual DCQL Request Generation

Includes:

- DUAL-05
- DUAL-06
- DCQL tests for two credentials
- Regression tests proving current single wallet login is unchanged

Expected size: 2-3 days.

### PR 3: External PID Trust Foundation

Includes:

- DUAL-07
- DUAL-08
- DUAL-09
- Optional DUAL-10 if pinned JWKS is needed for early testing

Expected size: 5-8 days.

### PR 4: Dual Presentation Verification and Matching

Includes:

- DUAL-11
- DUAL-12
- DUAL-13
- DUAL-14
- DUAL-15

Expected size: 5-6 days.

### PR 5: End-to-End UI and Integration Coverage

Includes:

- DUAL-04
- DUAL-16
- DUAL-17
- DUAL-18
- DUAL-19
- DUAL-20

Expected size: 6-8 days.

## Acceptance Criteria

- Existing wallet login still works without configuration changes.
- New PID login can be started independently from the existing wallet login.
- The authorization request for PID login contains two DCQL credential queries.
- The wallet response is parsed by credential query ID.
- PID credentials from untrusted issuers are rejected.
- Tax Advisor credentials are verified with the existing Keycloak trust path unless configured otherwise.
- Authentication fails if either credential is missing.
- Authentication fails if `firstname` or `lastname` do not match.
- Authentication succeeds only when both credentials verify and configured claims match.
- The Keycloak user is resolved from the Tax Advisor credential.
- Tests cover success, failure, edge cases, and regression of the existing flow.

## Risks and Open Questions

- `firstname` and `lastname` are weak identity-binding claims. The matcher must stay configurable so stronger claims can replace them.
- Trust anchor distribution is an operational decision. The plugin can enforce configured trust, but the organization must decide how PID issuer roots are provisioned and rotated.
- Certificate revocation checking for PID issuer certificates may require OCSP/CRL or a separate operational process.
- Wallet support for returning two SD-JWT VPs under the final `vp_token` map must be verified with the target wallet.
- If the PID issuer uses a different claim naming convention, the mapping must be configurable before pilot.

## Rough Total Estimate

Implementation and test effort: 17-25 engineering days.

This assumes the current SD-JWT verification primitives can be reused and the frontend change is small. The largest uncertainty is external PID issuer trust-chain validation and how the customer provisions trust anchors.
