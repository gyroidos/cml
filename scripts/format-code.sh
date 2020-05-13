#!/usr/bin/env bash
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
$ROOT_DIR/scripts/clang-format -i -verbose -style=file $(find $ROOT_DIR -type f -regextype sed -regex ".*\(\.c\|\.h\)")
