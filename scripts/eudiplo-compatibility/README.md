# EUDIPLO Compatibility Check

This local, read-only check fetches EUDIPLO's latest `main` commit, compares it with a shared baseline, and reports upstream commit subjects, the size and paths of changes under `apps/backend`, and plugin areas and tests to inspect. This gives every developer the same revision-based starting point for spotting changes that may matter. It does not decide compatibility automatically; an engineer reviews the linked source changes and confirms relevance.

## Run

Requirements: Bash, Git, network access to GitHub, and a checkout of this plugin repository. A separate EUDIPLO clone and GitHub MCP connection are not required.

From the plugin repository root:

```sh
bash ./scripts/eudiplo-compatibility/report.sh
```

The report prints to the terminal. It includes a GitHub compare link, upstream commit subjects, an aggregate change size, the changed paths, and candidate plugin areas/tests for review. To save it:

```sh
bash ./scripts/eudiplo-compatibility/report.sh --output eudiplo-impact.md
```

The script fetches the configured EUDIPLO branch into a temporary bare Git repository and removes it when finished. It does not change the developer's EUDIPLO or plugin checkout. The shared comparison baseline is in `baseline.sha`.

Every report records the baseline SHA, the exact EUDIPLO head fetched, the plugin `HEAD`, and the Keycloak version from `pom.xml`. To reproduce a report later, use the reported EUDIPLO head SHA:

```sh
bash ./scripts/eudiplo-compatibility/report.sh \
  --head 86c30b53b20d9c09f41515b4441fb5d36e893152 \
  --output eudiplo-impact.md
```

For comparison with another plugin revision, run from that plugin commit too. The report also notes whether tracked files in the plugin worktree are modified. Output is reproducible for the same baseline, EUDIPLO head, plugin commit/worktree state, and mapping version. The default run intentionally follows the latest EUDIPLO `main`, so its result can change as upstream advances.

## Review Process

1. Review the changed `apps/backend` files and the mapped integration areas in the report.
2. Inspect the source changes; path matches are leads, not compatibility findings.
3. Compare the behavior with the plugin implementation and the Keycloak version recorded in the report.
4. Run relevant tests and record confirmed differences, conditional risks, and areas with no equivalent integration.
5. After the team has reviewed the range, update `baseline.sha` to the reviewed EUDIPLO head. Do not move the baseline before recording the findings; doing so would skip those changes in the next run.

GitHub MCP can perform upstream commit searches and comparisons in a Codex session, but it is optional. The script uses Git directly so the workflow is available to every developer with the same repository and baseline.

## Feasibility Sample

The reporter was checked against EUDIPLO revisions `a18d32f7b0ce1d7bc4bf3b82fa6a26efd066c737` to `86c30b53b20d9c09f41515b4441fb5d36e893152`. That range contains six commits and 39 changed backend files. GitHub MCP independently returned the same head SHA. Manual comparison with the plugin and its pinned Keycloak 26.8.2 integration found:

| EUDIPLO behavior | Plugin/Keycloak counterpart | Assessment |
|---|---|---|
| EUDIPLO accepts presented `x5c`/`x5chain` headers up to 10 certificates. | The plugin's `PKIXVerificationUtil` caps presented chains at 5 and is used for PID SD-JWT, mDoc, and Status List validation. | Conditional compatibility difference: a valid chain of 6-10 certificates may pass EUDIPLO's length check but be rejected by the plugin. Verify whether such chains are expected before changing the plugin's stricter policy. |
| EUDIPLO infers the issuance service type from `LoTEType` when no services in a list have `ServiceTypeIdentifier`. | The plugin's PID trust-list parser requires an explicit service type and skips untyped entries. | Conditional behavior difference: an all-untyped PID-provider list may yield no trusted issuer certificates in the plugin. Check the active trust-list profile/data before treating this as a live failure. |
| EUDIPLO bounds trust-list certificates to 1,000 and certificate-path search to 16 entries/64 signature checks. | The plugin has a stricter presented-chain cap, but no corresponding explicit total-certificate budget for its parsed PID trust list; path construction uses Java PKIX. | Resource-hardening difference to investigate with bounded-input/performance tests; not evidence by itself of an exploitable denial of service. |
| EUDIPLO rejects mDoc and status-list chains containing certificates outside their validity period. | The plugin checks certificate validity during PKIX validation; its Status List fetcher also rejects expired certificates. | No corresponding gap found in the inspected plugin paths. |
| EUDIPLO validates wallet/key-attestation certificate paths from `x5c`. | Keycloak 26.8.2's ABCA authenticator resolves an attester key through configured trust-material providers; it does not consume an `x5c` chain in this flow. | Different trust models; no parity or incompatibility conclusion follows from the feature names alone. |

For PID LoTE profiles, EUDIPLO also excludes services carrying `ServiceStatus`, which that profile forbids. The plugin intentionally ignores this field for PID lists. They behave the same for conforming lists; they differ on non-conforming entries that include a status.

The selected plugin regression tests passed: 85 tests, with no failures or errors. These confirm current plugin behavior, not equivalence; equivalent fixtures for conditional differences are still needed. This sample shows the process can surface meaningful review questions after path classification, while leaving final compatibility judgment to an engineer.

## Mapping and Limits

The reporter maps EUDIPLO trust-list changes to PID trust-list parsing, wallet-attestation changes to Keycloak delegation, certificate-chain changes to plugin trust/mDoc validation, and verifier/status changes to credential and Status List verification. New or unmapped paths are reported for manual review. It does not analyze code semantics, compare OpenAPI documents, or prove compatibility. API contract changes can be checked separately with generated baseline/candidate specs and `oasdiff`; source-level behavior still needs code review and tests.
