#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
go_mod="$repository_root/go/go.mod"
go_version="${1:-}"

if [[ -z "$go_version" ]]; then
  go_version="$(curl --fail --silent --show-error 'https://go.dev/dl/?mode=json' | jq -r '[.[] | select(.stable == true and (.version | test("^go[0-9]+\\.[0-9]+\\.[0-9]+$")))] | sort_by(.version | sub("^go"; "") | split(".") | map(tonumber)) | last | .version')"
fi

go_version="${go_version#go}"
if [[ ! "$go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'Invalid Go version: %s\n' "$go_version" >&2
  exit 1
fi

if ! grep -Eq '^go [0-9]+\.[0-9]+(\.[0-9]+)?$' "$go_mod"; then
  printf 'Could not find the Go directive in %s\n' "$go_mod" >&2
  exit 1
fi

sed -Ei 's/^go [0-9]+\.[0-9]+(\.[0-9]+)?$/go '"$go_version"'/' "$go_mod"

while IFS= read -r devcontainer_file; do
  sed -Ei '/"ghcr\.io\/devcontainers\/features\/go:1"/{n;s/"version": "[^"]+"/"version": "'"$go_version"'"/;}' "$devcontainer_file"
  if ! grep -q '"ghcr.io/devcontainers/features/go:1"' "$devcontainer_file" || ! grep -q '"version": "'"$go_version"'"' "$devcontainer_file"; then
    printf 'Could not update the Go feature in %s\n' "$devcontainer_file" >&2
    exit 1
  fi
done < <(find "$repository_root/.devcontainer" -name devcontainer.json -type f -print)

printf 'Synchronized Go toolchain references to %s\n' "$go_version"