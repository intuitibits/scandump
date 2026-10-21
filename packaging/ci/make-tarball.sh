#!/bin/sh
# Creates scandump-<version>.tar.gz in DIR (default: current directory) from
# the working tree, laid out like the GitHub tag archive (scandump-<version>/),
# so packaging can be tested before a release is tagged.
set -eu

top=$(cd "$(dirname "$0")/../.." && pwd)
out=$(cd "${1:-.}" && pwd)
version=$(sed -n 's/^#define VERSION "\(.*\)"/\1/p' "$top/scandump.c")

tar -C "$top" -czf "$out/scandump-$version.tar.gz" \
  --exclude=.git --exclude='*.o' --exclude=./scandump --exclude='*.tar.gz' --exclude=./out --exclude=./debian \
  --transform "s,^\.,scandump-$version," .
echo "$out/scandump-$version.tar.gz"
