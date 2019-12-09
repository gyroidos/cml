#!/usr/bin/env bash
clang-format -i -verbose -style=file $(find . -type f -regextype sed -regex ".*\(\.c\|\.h\)")
