# Multi-Credential OpenID4VP Profiles Implementation Plan

## Goal

Extend the OpenID4VP authentication plugin so a realm can expose multiple wallet authentication profiles. The existing single-credential flow must remain the default and keep working without new configuration. A new profile can request two or more credentials in one OpenID4VP/DCQL request, verify each presented credential, and bind supporting credentials to the primary credential or authenticated user.

## Design

1. Add profile configuration as an additive authenticator config field.
   - Existing flat SD-JWT authenticator settings remain valid.
   - If no profile JSON is configured, a backward-compatible `default` profile is synthesized from the current flat settings.

2. Treat a profile as the security boundary.
   - A request starts with exactly one `profile_id`.
   - The selected profile ID is stored in `AuthorizationContext`.
   - Later endpoints recover the profile from the stored context instead of trusting request parameters.

3. Model credentials inside a profile.
   - One credential has role `primary` and is used for final Keycloak user binding.
   - Supporting credentials are verified individually.
   - Binding rules compare supporting credential claims to primary credential claims or Keycloak user attributes.

4. Keep the login UI profile-driven.
   - The current “Sign in with a wallet” button remains the default profile.
   - Additional enabled profiles render as extra wallet buttons, for example “Sign in with two credentials”.

5. Update DCQL and response handling.
   - Generate one DCQL credential query per configured credential.
   - Require one VP token per credential query.
   - Validate each VP independently.

## Implementation Steps

1. Create profile configuration model and parser.
2. Add `profile_id` to authorization context and request initiation.
3. Generate profile-based DCQL queries.
4. Verify primary credential through the existing Keycloak authenticator path.
5. Verify supporting credentials and apply binding rules.
6. Render multiple wallet login buttons from configured profiles.
7. Add unit tests and focused integration coverage for default and dual-profile behavior.

## Implementation Status

Completed on branch `feature/multi-credential-profiles`.

- Added an additive `profiles` authenticator configuration field. When omitted, the plugin synthesizes the existing single-credential behavior from the legacy flat settings.
- Added profile, credential, trust policy, and binding-rule models under `oid4vp/profile`.
- Added `profile_id` to the authorization context so the selected profile is fixed for the lifetime of the request.
- Updated DCQL generation to emit one credential query per configured credential and require all credentials in the selected profile.
- Kept the primary credential on the existing Keycloak authenticator path for final user binding.
- Added supporting-credential verification and binding checks after the primary user is authenticated.
- Updated the login form model and FreeMarker template so configured profiles render as separate wallet sign-in buttons.
- Added focused tests for profile parsing, multi-credential DCQL, login button rendering, and a dual-profile endpoint flow.

## Current Boundaries

- Supporting-credential trust enforcement currently accepts the existing self-trust model. Other trust policy types are modeled in configuration but fail explicitly until their verifier implementation is added.
- The dual-profile endpoint test uses a self-trusted supporting credential to exercise multi-credential request, response extraction, individual verification, binding, and token redemption without adding an external trust anchor test fixture yet.
