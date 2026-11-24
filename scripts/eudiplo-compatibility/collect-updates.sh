#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <eudiplo-checkout> <baseline-file> <report-file>" >&2
  exit 2
fi

eudiplo_dir=$1
baseline_file=$2
report_file=$3
baseline=$(tr -d '[:space:]' < "$baseline_file")

if [[ ! "$baseline" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Baseline must contain one full 40-character commit SHA" >&2
  exit 1
fi

git -C "$eudiplo_dir" cat-file -e "${baseline}^{commit}"
head=$(git -C "$eudiplo_dir" rev-parse origin/main^{commit})
if ! git -C "$eudiplo_dir" merge-base --is-ancestor "$baseline" "$head"; then
  echo "Baseline $baseline is not an ancestor of EUDIPLO main ($head)" >&2
  exit 1
fi

commits=$(git -C "$eudiplo_dir" rev-list --count "$baseline..$head" -- apps/backend)
mapfile -t paths < <(git -C "$eudiplo_dir" diff --name-only "$baseline...$head" -- apps/backend)
changed_paths=${#paths[@]}
compare_url="https://github.com/EUDIPLO/eudiplo/compare/${baseline}...${head}"

{
  printf '# EUDIPLO backend update inventory\n\n'
  printf -- '- Baseline: `%s`\n' "$baseline"
  printf -- '- Candidate (`main`): `%s`\n' "$head"
  printf -- '- Commits affecting `apps/backend`: %s\n' "$commits"
  printf -- '- Changed paths under `apps/backend`: %s\n' "$changed_paths"
  printf -- '- Compare: %s\n\n' "$compare_url"

  if (( changed_paths == 0 )); then
    printf 'No changes under `apps/backend` were found in this range.\n'
  else
    printf '## Backend commits\n\n'
    git -C "$eudiplo_dir" log --format='- `%h` %s' "$baseline..$head" -- apps/backend
    printf '\n## Changed paths\n\n```text\n'
    printf '%s\n' "${paths[@]}"
    printf '```\n'
  fi
} > "$report_file"

if (( changed_paths > 0 )); then
  echo "has-updates=true" >> "$GITHUB_OUTPUT"
else
  echo "has-updates=false" >> "$GITHUB_OUTPUT"
fi
