# PID and Dual Credential Login Implementation Plan

## Purpose

Implement the new flow in two clear stages:

1. Teach the plugin to verify externally issued PID SD-JWT VC credentials through explicit trust configuration.
2. Build the dual credential login flow on top of that foundation by requesting both PID and Tax Advisor credentials and matching them during verification.

This order reduces risk because external PID issuer trust is the hardest part. Once PID verification is reliable, the dual credential flow becomes mostly orchestration: request two credentials, verify each with the correct trust policy, compare configured claims, then authenticate the user from the Tax Advisor credential.

The existing single-credential wallet login must remain unchanged.

The initial matching rule is:

- `PID.firstname == TaxAdvisor.firstname`
- `PID.lastname == TaxAdvisor.lastname`

These claim names are intentionally isolated in configuration because the customer may later choose stronger or different matching claims.

## Goals

- Keep the current wallet login flow working as it does today.
- Add external PID credential verification without weakening current Keycloak-issued credential verification.
- Enforce explicit trust for external PID issuers.
- Add a separate "login with PID" flow after PID verification is proven.
- Request two SD-JWT VC credentials in a single OpenID4VP authorization request for the dual flow.
- Verify each credential against the correct trust policy.
- Match identity claims across PID and Tax Advisor credentials before authenticating the Keycloak user.
- Authenticate the Keycloak user from the Tax Advisor credential, not from the PID.
- Keep the implementation maintainable enough to support future credential types and stronger matching rules.

## Non-Goals

- Do not replace or weaken the existing Keycloak-issued SD-JWT login flow.
- Do not accept arbitrary external PID issuers.
- Do not disable issuer validation as a shortcut for external PID support.
- Do not hard-code customer-specific claim mappings outside a dedicated configuration object.
- Do not implement mdoc support as part of this flow.
- Do not require the frontend PID login button before backend PID verification is working.

## Key Design Decisions

### PID Verification Comes First

Before implementing dual credential login, add a reusable PID verification foundation:

- PID issuer configuration.
- PID trust policy parsing.
- External issuer signing-key resolution.
- X.509 trust-chain validation or explicitly configured pinned keys.
- PID SD-JWT VP verification.
- PID claim extraction for plain and selectively disclosed claims.

This first stage should be testable without changing the current login UI.

### Separate Verification Profile

Introduce a verification profile concept only after or alongside the PID foundation so the same OpenID4VP transport can serve multiple login flows:

- `single_sd_jwt`: current wallet login behavior.
- `pid_sd_jwt`: optional internal/test profile for verifying one PID credential.
- `dual_pid_tax_advisor`: new PID plus Tax Advisor login behavior.

The selected profile must be stored in the authorization context because the wallet response arrives later through the `requestId`.

### Separate Configuration

PID verification and dual credential login must have separate configuration from the existing single credential flow.

PID verification configuration should include:

- PID credential query ID, for example `pid`.
- PID accepted `vct` values.
- PID allowed issuer identifiers.
- PID trust mode, for example `x5c_trust_chain` or `pinned_jwks`.
- PID trust anchors or pinned public keys.
- PID required claims, initially `firstname`, `lastname`.
- PID status/revocation policy.

Dual credential configuration should include:

- Tax Advisor credential query ID, for example `tax_advisor`.
- Tax Advisor accepted `vct` values.
- Tax Advisor issuer trust policy, initially existing Keycloak realm trust.
- Tax Advisor required claims, initially `sub`, `username`, `firstname`, `lastname`.
- Claim matching rules, initially `firstname` and `lastname`.
- Per-credential revocation/status policy.

### Trust Model

The external PID issuer must be trusted through explicit policy. The minimum acceptable trust model is:

- Allow-list the PID issuer identifier.
- Validate the credential signature using issuer keys resolved from a trusted source.
- Validate the issuer key material against configured trust anchors or pinned keys.
- Reject credentials from unknown issuers, unknown keys, expired certificates, unsupported algorithms, or invalid chains.

Prefer X.509 trust anchors for production PID issuer trust. Pinned JWKS can be useful for a first controlled integration, but it is weaker operationally unless key rotation is handled carefully.

### Authentication Source

The Tax Advisor credential remains the source for resolving the Keycloak user. The PID credential only strengthens possession and identity binding by proving that the wallet holder can present a matching externally issued PID.

## Stage 1: PID Credential Verification Flow

The first implementation target is not dual login yet. It is: "Can this plugin verify a PID credential from a configured external issuer?"

Expected behavior:

1. Admin configures trusted PID issuer policy.
2. Plugin receives or tests a PID SD-JWT VP.
3. Plugin validates the PID SD-JWT VP, key binding, issuer, signature, trust chain, `vct`, and required claims.
4. Plugin extracts `firstname` and `lastname`.
5. Plugin rejects untrusted issuers, bad signatures, bad chains, missing claims, and unsupported algorithms.

This stage should produce reusable services for the later dual flow.

## Stage 2: Dual Credential Login Flow

Once PID verification works:

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
| PID-01 | Add PID Verification Configuration Model | Add configuration classes for trusted PID issuer policies, accepted PID `vct` values, required PID claims, trust mode, trust anchors or pinned keys, allowed algorithms, and status validation. This must be separate from the existing single SD-JWT login configuration. | 1-2 days |
| PID-02 | Parse and Validate PID Trust Policy | Add a parser for configured trusted PID issuers. It should validate required fields and fail closed for missing issuer, missing trust material, malformed certificates/JWKs, unsupported trust modes, or empty accepted `vct` values. | 1-1.5 days |
| PID-03 | Implement X.509 Chain Validation | Validate `x5c` chains against configured trust anchors when PID issuer trust is certificate based. Check certificate validity, chain signatures, key usage where available, and supported algorithms. | 2-4 days |
| PID-04 | Implement Optional Pinned JWKS Trust Mode | Optionally support pinned JWKS for controlled test or pilot environments. Require explicit issuer allow-listing and document the operational risk around key rotation. | 1-2 days |
| PID-05 | Implement External PID Issuer Key Resolver | Implement a `TrustedSdJwtIssuer` resolver for configured external PID issuers. It should resolve verifying keys from X.509 chains or pinned JWKS and reject unknown issuer/key combinations. | 2-3 days |
| PID-06 | Implement PID SD-JWT Verification Service | Add a reusable service that verifies a PID SD-JWT VP using PID trust policy, SD-JWT presentation requirements, key-binding requirements, expected `vct`, and required claims. | 2 days |
| PID-07 | Implement Claim Extraction Service | Centralize extraction of plain and selectively disclosed claims from SD-JWT credentials. Support nested paths later, but initially support top-level `firstname` and `lastname`. | 1 day |
| PID-08 | Add PID Verification Tests | Cover trusted PID success, unknown issuer, unknown key, bad chain, expired certificate, missing `x5c` or pinned key, unsupported algorithm, wrong `vct`, missing required claims, and invalid key binding. | 2-3 days |
| DUAL-01 | Introduce Verification Profile Model | Add an enum or value object for verification profiles. Include `single_sd_jwt`, optional `pid_sd_jwt`, and `dual_pid_tax_advisor`. Store the selected profile in `AuthorizationContext` and preserve current behavior as the default. | 0.5-1 day |
| DUAL-02 | Add Profile Selection to Login UI Backend | Extend `OID4VPUserAuthBean` and endpoint startup logic so a new login method can start the dual profile without affecting `login_method=oid4vp`. Use a clear value such as `login_method=dual_pid`. | 1 day |
| DUAL-03 | Build Dual-Credential DCQL Query | Extend or replace `SdJwtCredentialConstrainer` so it can generate a DCQL query with stable credential IDs for `pid` and `tax_advisor`. Each credential entry must include the correct format, vct values, required claims, and credential set requirements. | 1-2 days |
| DUAL-04 | Preserve Query-ID to VP Mapping | Extend `VpTokenCandidateExtractor` or add a new extractor that returns SD-JWT presentations by credential query ID. The dual flow must not collapse all SD-JWT candidates into a single token. | 1 day |
| DUAL-05 | Verify PID and Tax Advisor Presentations Together | Add a dual verification service that accepts the mapped PID and Tax Advisor SD-JWT VPs, applies the correct trust policy to each, and returns verified credential payloads plus disclosures. | 2 days |
| DUAL-06 | Implement Claim Matching Rules | Add a matcher that compares configured claims across PID and Tax Advisor credentials. Start with exact string equality for `firstname` and `lastname`. Normalize only if explicitly agreed later. | 1 day |
| DUAL-07 | Authenticate User from Tax Advisor Credential | Ensure the final Keycloak user lookup uses the verified Tax Advisor credential. Keep current checks for subject, username, enabled user, and username mismatch. | 1 day |
| DUAL-08 | Add Dual Flow Error Handling | Add clear errors for missing PID, missing Tax Advisor credential, unknown issuer, failed trust chain, missing claims, and claim mismatch. Sanitize responses while keeping logs useful. | 1 day |
| DUAL-09 | Add Frontend PID Login Button | Update the client app to show a second button for "login with PID". The button should call the same Keycloak flow with the new login method/profile selector. This is likely in the mock frontend repository, not this plugin repository. | 0.5-1 day |
| DUAL-10 | Add Dual Flow Unit Tests | Cover dual configuration parsing, invalid configs, generated DCQL credential IDs, required claims, vct values, credential set requirements, and query-ID extraction. | 1-2 days |
| DUAL-11 | Add Claim Matching Tests | Cover disclosed and non-disclosed claims, missing claims, mismatched claims, and successful `firstname`/`lastname` match. | 1 day |
| DUAL-12 | Add Integration Tests for Dual Login | Add end-to-end tests for successful dual presentation, missing PID, missing Tax Advisor credential, mismatched names, invalid PID issuer, and current single wallet login regression. | 3-4 days |
| DUAL-13 | Documentation and Admin Guidance | Document the new flow, configuration examples, trust policy setup, operational key rotation notes, and current limitation that initial matching uses `firstname` and `lastname`. | 1-1.5 days |

## Acceptance Criteria

### Stage 1: PID Verification

- PID issuer trust policy can be configured separately from current wallet login.
- PID credentials from configured trusted issuers are accepted.
- PID credentials from untrusted issuers are rejected.
- PID credentials with invalid signatures, invalid trust chains, unsupported algorithms, or wrong `vct` values are rejected.
- Required PID claims are enforced.
- `firstname` and `lastname` can be extracted from plain or selectively disclosed claims.
- Existing wallet login still works without configuration changes.

### Stage 2: Dual Credential Login

- New PID login can be started independently from the existing wallet login.
- The authorization request for PID login contains two DCQL credential queries.
- The wallet response is parsed by credential query ID.
- PID credentials are verified with the external PID trust policy.
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
- Pinned JWKS is useful for controlled integration, but production should prefer a managed trust-chain strategy.

## Rough Total Estimate

This revised estimate is slightly higher because PID verification is treated as its own foundation instead of being hidden inside the dual credential flow. The largest uncertainty remains external PID issuer trust-chain validation and how the customer provisions trust anchors.
