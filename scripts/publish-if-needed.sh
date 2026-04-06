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

crate_url="https://crates.io/api/v1/crates/${package_name}/${package_version}"
http_code="$(curl -sS -o /tmp/peam-ssz-crate-check.json -w '%{http_code}' "$crate_url")"

if [[ "$http_code" == "200" ]]; then
  echo "${package_name} ${package_version} is already published; skipping."
  exit 0
fi

if [[ "$http_code" != "404" ]]; then
  echo "Unexpected crates.io response while checking ${package_name} ${package_version}: HTTP ${http_code}" >&2
  cat /tmp/peam-ssz-crate-check.json >&2 || true
  exit 1
fi

echo "Publishing ${package_name} ${package_version}"
cargo publish --manifest-path "$manifest_path" --token "$CARGO_REGISTRY_TOKEN"
