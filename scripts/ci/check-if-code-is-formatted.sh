#!/usr/bin/env bash
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null 2>&1 && pwd)"
CLANG_FORMAT="${ROOT_DIR}/scripts/clang-format"
FILES=$(find $ROOT_DIR -type f -regextype sed -regex ".*\(\.c\|\.h\)")

echo "Detected clang-format version..."
$CLANG_FORMAT --version

echo "Checking if code is properly formatted..."
diff -u <(cat $FILES) <($CLANG_FORMAT $FILES)
ret=$?

if [ $ret -ne 0 ]; then
    echo ""
    echo "The code is not formatted!"
    echo "Check the above output that shows the wrong (-) and correct (+) formattings."
    echo "You can automatically format your code using the ./scripts/format-code.sh script."
else
    echo "Code is properly formatted."
fi

exit $ret
