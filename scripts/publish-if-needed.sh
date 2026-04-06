#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest_path="${1:-$repo_root/Cargo.toml}"

if [[ ! -f "$manifest_path" ]]; then
  echo "Cargo manifest not found: $manifest_path" >&2
  exit 1
fi

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
  echo "CARGO_REGISTRY_TOKEN is required" >&2
  exit 1
fi

package_name="$(awk -F ' = ' '
  /^\[package\]/ { in_package=1; next }
  /^\[/ && $0 != "[package]" { in_package=0 }
  in_package && $1 == "name" { gsub(/"/, "", $2); print $2; exit }
' "$manifest_path")"

package_version="$(awk -F ' = ' '
  /^\[package\]/ { in_package=1; next }
  /^\[/ && $0 != "[package]" { in_package=0 }
  in_package && $1 == "version" { gsub(/"/, "", $2); print $2; exit }
' "$manifest_path")"

if [[ -z "$package_name" || -z "$package_version" ]]; then
  echo "Failed to parse package name/version from $manifest_path" >&2
  exit 1
fi

echo "Publishing ${package_name} ${package_version} if it is not already on crates.io"

publish_log="$(mktemp)"
if cargo publish --locked --manifest-path "$manifest_path" --token "$CARGO_REGISTRY_TOKEN" \
  >"$publish_log" 2>&1; then
  cat "$publish_log"
  rm -f "$publish_log"
  exit 0
fi

cat "$publish_log" >&2
if grep -Eqi "already (uploaded|exists)|previously published|already been uploaded" "$publish_log"; then
  echo "${package_name} ${package_version} is already published; skipping."
  rm -f "$publish_log"
  exit 0
fi

rm -f "$publish_log"
exit 1
