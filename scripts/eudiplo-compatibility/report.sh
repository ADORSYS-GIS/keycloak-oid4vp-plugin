#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
  printf 'Usage: %s [--head commit-sha] [--output report-file]\n' "$0" >&2
  printf 'By default, compares the shared baseline with the latest configured EUDIPLO branch.\n' >&2
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
plugin_repo=$(cd -- "$script_dir/../.." && pwd)
baseline_file="$script_dir/baseline.sha"
eudiplo_remote=${EUDIPLO_REMOTE_URL:-https://github.com/EUDIPLO/eudiplo.git}
eudiplo_branch=${EUDIPLO_BRANCH:-main}
head_ref=
output_file=-
while (($#)); do
  case "$1" in
    --head)
      if [[ $# -lt 2 || -z "$2" ]]; then
        usage
        exit 2
      fi
      head_ref=$2
      shift 2
      ;;
    --output)
      if [[ $# -lt 2 || -z "$2" ]]; then
        usage
        exit 2
      fi
      output_file=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ ! -f "$baseline_file" ]]; then
  printf 'Missing baseline file: %s\n' "$baseline_file" >&2
  exit 2
fi
IFS= read -r base_ref < "$baseline_file"
if [[ ! "$base_ref" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'Baseline must contain one full 40-character commit SHA: %s\n' "$baseline_file" >&2
  exit 2
fi

if ! git -C "$plugin_repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  printf 'Plugin repository is not a Git working tree: %s\n' "$plugin_repo" >&2
  exit 2
fi

plugin_commit=$(git -C "$plugin_repo" rev-parse HEAD)
if [[ -n "$(git -C "$plugin_repo" status --porcelain --untracked-files=no)" ]]; then
  plugin_worktree=modified
else
  plugin_worktree=clean
fi
keycloak_version=$(sed -n 's/^[[:space:]]*<keycloak.version>\([^<]*\)<\/keycloak.version>.*/\1/p' "$plugin_repo/pom.xml" | head -n 1)
if [[ -z "$keycloak_version" ]]; then
  keycloak_version=unknown
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
eudiplo_repo="$tmpdir/eudiplo.git"
git clone --quiet --bare --single-branch --filter=blob:none --depth=1 \
  --branch "$eudiplo_branch" "$eudiplo_remote" "$eudiplo_repo"
latest_commit=$(git -C "$eudiplo_repo" rev-parse --verify 'HEAD^{commit}')

if [[ -n "$head_ref" ]]; then
  if ! git -C "$eudiplo_repo" rev-parse --verify "${head_ref}^{commit}" >/dev/null 2>&1; then
    git -C "$eudiplo_repo" fetch --quiet --filter=blob:none --no-tags --depth=1 origin "$head_ref"
  fi
  head_commit=$(git -C "$eudiplo_repo" rev-parse --verify "${head_ref}^{commit}")
else
  head_commit=$latest_commit
fi

if ! git -C "$eudiplo_repo" cat-file -e "${base_ref}^{commit}" 2>/dev/null; then
  git -C "$eudiplo_repo" fetch --quiet --filter=blob:none --no-tags --depth=1 origin "$base_ref"
fi
base_commit=$(git -C "$eudiplo_repo" rev-parse --verify "${base_ref}^{commit}")

# Deepen in bounded increments until the shared baseline is connected to the
# selected head, so the report can include commit subjects for that range.
history_rounds=0
while ! git -C "$eudiplo_repo" merge-base --is-ancestor "$base_commit" "$head_commit"; do
  if ((history_rounds >= 20)); then
    printf 'Could not connect baseline %s to head %s in EUDIPLO %s history.\n' \
      "$base_commit" "$head_commit" "$eudiplo_branch" >&2
    exit 2
  fi
  git -C "$eudiplo_repo" fetch --quiet --filter=blob:none --no-tags --deepen=100 \
    origin "refs/heads/$eudiplo_branch"
  history_rounds=$((history_rounds + 1))
done

change_output=$(git -C "$eudiplo_repo" diff --no-renames --name-status "$base_commit" "$head_commit" -- apps/backend)
commit_subjects=$(git -C "$eudiplo_repo" log --reverse --format='- `%h` %s' \
  "$base_commit..$head_commit" -- apps/backend)
change_summary=$(git -C "$eudiplo_repo" diff --shortstat "$base_commit" "$head_commit" -- apps/backend)
changes=()
if [[ -n "$change_output" ]]; then
  mapfile -t changes <<< "$change_output"
fi

render_report() {
  printf '# EUDIPLO backend change-impact report\n\n'
  printf -- '- Repository: `%s`\n' "$eudiplo_remote"
  printf -- '- Watched branch: `%s`\n' "$eudiplo_branch"
  printf -- '- Baseline: `%s`\n' "$base_commit"
  printf -- '- Compared head: `%s`\n' "$head_commit"
  printf -- '- Latest branch head at fetch: `%s`\n' "$latest_commit"
  printf -- '- Plugin commit: `%s`\n' "$plugin_commit"
  printf -- '- Plugin tracked worktree: `%s`\n' "$plugin_worktree"
  printf -- '- Keycloak version from `pom.xml`: `%s`\n\n' "$keycloak_version"
  printf -- '- [View upstream compare](https://github.com/EUDIPLO/eudiplo/compare/%s...%s)\n\n' \
    "$base_commit" "$head_commit"

  if [[ ${#changes[@]} -eq 0 ]]; then
    printf 'No changes found under `apps/backend` for this revision pair.\n'
    return
  fi

  printf '## Upstream commits affecting `apps/backend`\n\n'
  if [[ -n "$commit_subjects" ]]; then
    printf '%s\n' "$commit_subjects"
  else
    printf 'No non-merge commit subjects found for this range.\n'
  fi
  printf '\n## Change size\n\n```text\n%s\n```\n\n' "$change_summary"

  printf '## Changed files\n\n'
  for entry in "${changes[@]}"; do
    IFS=$'\t' read -r status path <<< "$entry"
    printf -- '- `%s` `%s`\n' "$status" "$path"
  done

  printf '\n## Potential integration areas\n\n'
  trust_mapping_reported=false
  attestation_mapping_reported=false
  certificate_mapping_reported=false
  verifier_mapping_reported=false
  unmapped_paths=()
  for entry in "${changes[@]}"; do
    IFS=$'\t' read -r _ path <<< "$entry"
    mapped=false
    case "$path" in
      apps/backend/src/issuer/trust-list/*|\
      apps/backend/src/trust/adapters/verified-lote-provider.ts|\
      apps/backend/src/trust/application/collect-trusted-entities.*|\
      apps/backend/src/trust/domain/lote-profiles.*|\
      apps/backend/src/trust/lote-parser.service.*|\
      apps/backend/src/trust/trust-store.service.*|\
      apps/backend/src/trust/domain/trust-list-certificate-limit.ts|\
      apps/backend/src/trust/types.ts)
        if [[ "$trust_mapping_reported" == false ]]; then
          printf -- '- **PID trust-list behavior:** Review against `EudiTrustListPayloadParser` and `EudiPidTrustListProvider`; run `./mvnw -Dtest=EudiPidTrustListProviderTest test`. A path match is a review prompt, not proof of incompatibility.\n'
          trust_mapping_reported=true
        fi
        mapped=true
        ;;
    esac
    case "$path" in
      apps/backend/src/issuer/issuance/oid4vci/attestation-proof-trust.util.*|\
      apps/backend/src/trust/domain/attestation-certificate-validity.*|\
      apps/backend/src/trust/wallet-attestation.service.*|\
      apps/backend/test/issuance/wallet-attestation.e2e-spec.ts)
        if [[ "$attestation_mapping_reported" == false ]]; then
          printf -- '- **Wallet-attestation integration:** Review Keycloak delegation in `WalletAttestationValidator` / `AuthorizationChallengeEndpoint`; run `./mvnw -Dtest=InteractiveAuthorizationServerMetadataTest test`. Verify whether the attestation trust model is equivalent before inferring a gap.\n'
          attestation_mapping_reported=true
        fi
        mapped=true
        ;;
    esac
    case "$path" in
      apps/backend/src/shared/utils/certificate-chain-length.*|\
      apps/backend/src/shared/utils/certificate-path.*|\
      apps/backend/src/shared/utils/x509-tolerant-extensions.*|\
      apps/backend/src/trust/domain/attestation-certificate-validity.*|\
      apps/backend/src/trust/domain/trust-list-certificate-limit.ts|\
      apps/backend/src/trust/x509-validation.service.*|\
      apps/backend/src/verifier/presentations/credential/credential-chain-validation.service.*|\
      apps/backend/src/verifier/presentations/mdoc-context.*|\
      apps/backend/test/trust/certificate-chain.fixture.ts)
        if [[ "$certificate_mapping_reported" == false ]]; then
          printf -- '- **Certificate-chain validation:** Compare EUDIPLO limits with `PKIXVerificationUtil`, `EudiCertificateChainValidator`, and `MdocVerificationContext`; run `./mvnw -Dtest=PKIXVerificationUtilTest,EudiCertificateChainValidatorTest,MdocVerificationTest test`.\n'
          certificate_mapping_reported=true
        fi
        mapped=true
        ;;
    esac
    case "$path" in
      apps/backend/src/verifier/presentations/credential/*|\
      apps/backend/src/verifier/presentations/trusted-authorities.service.*|\
      apps/backend/src/verifier/resolver/*)
        if [[ "$verifier_mapping_reported" == false ]]; then
          printf -- '- **Credential verification/status:** Review mDoc, SD-JWT, trusted-authority, and Status List verification; run `./mvnw -Dtest=MdocVerificationTest,TrustedStatusListJwtFetcherTest,EudiPidTrustedSdJwtIssuerTest test`.\n'
          verifier_mapping_reported=true
        fi
        mapped=true
        ;;
    esac
    if [[ "$mapped" == false ]]; then
      unmapped_paths+=("$path")
    fi
  done

  if [[ "$trust_mapping_reported" == false && "$attestation_mapping_reported" == false && "$certificate_mapping_reported" == false && "$verifier_mapping_reported" == false && ${#unmapped_paths[@]} -eq 0 ]]; then
    printf 'No known integration mapping matched these paths.\n'
  fi
  if [[ ${#unmapped_paths[@]} -gt 0 ]]; then
    printf '\nPaths without a known mapping need manual review:\n'
    for path in "${unmapped_paths[@]}"; do
      printf -- '- `%s`\n' "$path"
    done
  fi

  printf '\n## OpenAPI contract check\n\n'
  printf 'This script does not generate historical OpenAPI documents. If you have generated baseline and candidate specs and `oasdiff` installed, compare them with `oasdiff breaking <baseline.json> <candidate.json>`. Contract comparison will not detect behavior changes that leave the API schema unchanged.\n'
}

if [[ "$output_file" == "-" ]]; then
  render_report
else
  render_report > "$output_file"
  printf 'Wrote report to %s\n' "$output_file" >&2
fi
