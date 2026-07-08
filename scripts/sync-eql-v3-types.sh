#!/usr/bin/env bash
#
# Vendor the generated EQL v3 TypeScript payload types from the
# encrypt-query-language repo (eql-bindings crate, ts-rs output) into
# src/eql-v3-types/.
#
# The vendored files are GENERATED — never hand-edit them. To refresh:
#
#   ./scripts/sync-eql-v3-types.sh [path-to-encrypt-query-language]
#
# The source defaults to a sibling checkout of encrypt-query-language.
# Regenerate the ts-rs output there first if needed (`cargo test -p
# eql-bindings` writes crates/eql-bindings/bindings/v3/).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EQL_REPO="${1:-${REPO_ROOT}/../encrypt-query-language}"
SRC="${EQL_REPO}/crates/eql-bindings/bindings/v3"
DEST="${REPO_ROOT}/src/eql-v3-types"

if [ ! -d "${SRC}" ]; then
  echo "error: ${SRC} not found — pass the encrypt-query-language checkout as \$1" >&2
  exit 1
fi

mkdir -p "${DEST}"
rm -f "${DEST}"/*.ts

for file in "${SRC}"/*.ts; do
  name="$(basename "${file}")"
  {
    echo "// @generated — vendored from eql-bindings bindings/v3 (encrypt-query-language)."
    echo "// Do not hand-edit. Refresh with scripts/sync-eql-v3-types.sh."
    cat "${file}"
  } > "${DEST}/${name}"
done

echo "Vendored $(ls "${DEST}" | wc -l | tr -d ' ') files into src/eql-v3-types/"
