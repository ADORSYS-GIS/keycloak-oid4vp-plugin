# EUDIPLO Compatibility Review Prompt

Use this prompt from a checkout of `ADORSYS-GIS/keycloak-oid4vp-plugin` to assess whether recent EUDIPLO backend changes may affect wallet interoperability with the plugin. Review only the upstream changes after the shared baseline; do not perform a general audit of either codebase.

## Inputs

- EUDIPLO repository: <https://github.com/EUDIPLO/eudiplo>
- EUDIPLO branch: `main`
- Shared baseline commit: read the full SHA from `scripts/eudiplo-compatibility/baseline.sha`
- Candidate commit: the latest `main` commit fetched at the start of this review
- EUDIPLO change scope: `apps/backend`
- Plugin under review: the current checkout of this repository

Use GitHub access or Git to retrieve the baseline and candidate revisions. Record both full SHAs. If the baseline cannot be found, is not an ancestor of the candidate, or the relevant source is unavailable, stop the affected analysis and report the limitation; do not silently choose a different range. Do not modify either checkout or advance `baseline.sha`.

## Review Steps

1. Identify commits and changed paths under EUDIPLO `apps/backend` between the baseline and candidate commits. Ignore changes outside that directory for compatibility conclusions.
2. Read the relevant changed code and tests. Summarize the behavioral change, not just commit titles or filenames.
3. Trace only the corresponding plugin implementation, callers, configuration, and tests needed to evaluate that behavior. Check the Keycloak version pinned by the plugin and inspect its relevant integration where available. Do not infer equivalence from similar names alone.
4. Assess whether the change could improve, reduce, or leave unchanged the plugin's interoperability with the affected wallet flow. Consider protocol inputs/outputs, trust and certificate validation, credential issuance/presentation, status checks, and error behavior only where the upstream diff touches them.
5. Support each conclusion with source references: repository, commit, file and line (or symbol if line numbers are unavailable). Separate confirmed behavior differences from conditional risks and unknowns. Do not report a concern without a concrete scenario and evidence.
6. Suggest focused plugin tests or manual checks for material findings. Do not change code, create commits, or update the baseline.

## Impact Score

Assign each finding an impact direction and an integer score from 0 to 5:

- **Negative (compatibility risk):** `1` minor/limited; `2` low; `3` meaningful for a conditional or less common flow; `4` likely to break a commonly used flow; `5` likely to prevent a critical supported wallet flow or create a serious trust/security incompatibility.
- **Positive (compatibility improvement):** use the same scale to describe a concrete improvement in interoperability or compatibility.
- **Neutral:** `0` when the reviewed change has no demonstrated compatibility effect.

Score the supported-flow impact, not code size or perceived importance. State confidence as **High**, **Medium**, or **Low** separately from the score. If evidence is insufficient, say so and do not manufacture a score for an unconfirmed claim; list what evidence is needed.

## Report Format

Return a concise Markdown report. Its first non-empty line must be exactly `# EUDIPLO Compatibility Review`; do not add a preamble before this heading. Apply this rule even when reporting a limitation or incomplete analysis.

After the heading, include:

1. **Range:** EUDIPLO repository/branch, baseline SHA, candidate SHA, number of commits and changed `apps/backend` paths, and a link to the upstream compare view.
2. **Summary:** the most relevant behavioral changes and an overall compatibility direction/score, or `No demonstrated impact` when appropriate.
3. **Findings:** one item per distinct, evidence-backed impact, using this structure:

   `Direction: Negative/Positive/Neutral | Impact: 0-5 | Confidence: High/Medium/Low | Area: ...`

   Explain the changed EUDIPLO behavior, the corresponding plugin/Keycloak behavior, a concrete wallet-flow scenario, evidence references, and a focused validation suggestion.
4. **Uncertainties and checks:** only material unanswered questions or tests needed to confirm conditional risks.

Avoid repeating every changed path in the narrative; link the full compare and cite only paths relevant to findings. If no relevant behavior changed, state that plainly. Never present an unverified possibility as a confirmed incompatibility.

## Cadence

Run this review weekly against the latest EUDIPLO `main`. Keep the baseline unchanged until the team has reviewed and recorded the report. Once the range has been reviewed, update `baseline.sha` to the reviewed candidate SHA in a separate change so the next review starts there.
