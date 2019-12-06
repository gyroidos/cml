#!/usr/bin/env bash
clang-format -i -verbose -sort-includes -style=file $(find . -type f -regextype sed -regex ".*\(\.c\|\.h\)")
