#!/bin/sh
# Command-line tests that need no wireless interface or privileges: option
# parsing, exit statuses, and that nothing but PCAP data (here: nothing at
# all) reaches standard output on errors.
# Usage: tests/cli.sh path/to/scandump
set -u

scandump=${1:-./scandump}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
# An interface name that doesn't exist, so runs stop before scanning.
noif=scandump-none0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# expect STATUS STDERR-PATTERN ARGS...: runs scandump with ARGS, checks its
# exit status, that stderr matches the pattern and that stdout is empty.
expect() {
  status=$1 pattern=$2
  shift 2
  "$scandump" "$@" > "$tmp/out" 2> "$tmp/err"
  rc=$?
  [ "$rc" -eq "$status" ] || fail "scandump $*: exit $rc, expected $status"
  grep -q -- "$pattern" "$tmp/err" ||
    fail "scandump $*: stderr doesn't match '$pattern': $(cat "$tmp/err")"
  [ ! -s "$tmp/out" ] || fail "scandump $*: wrote to stdout"
}

# Help and version go to stdout and exit 0.
"$scandump" -h > "$tmp/out" 2>&1 || fail "-h exited non-zero"
grep -q -- "-i, --interval" "$tmp/out" || fail "-h doesn't list --interval"
"$scandump" --help > "$tmp/out" 2>&1 || fail "--help exited non-zero"
"$scandump" -V | grep -q "^scandump version [0-9]" || fail "-V output"

# Usage errors exit 1 and print the usage to stderr.
expect 1 "Usage:" "$noif"
expect 1 "Usage:" -x "$noif" out.pcap
expect 1 "Usage:" "$noif" a.pcap extra
expect 1 "Usage:" -i
expect 1 "invalid count" -c -1 "$noif" out.pcap

# Interval values.
for bad in -1 abc 1.5 5s "" 86401 99999999999999999999; do
  expect 1 "invalid interval" -i "$bad" "$noif" "$tmp/x.pcap"
  expect 1 "invalid interval" --interval="$bad" "$noif" "$tmp/x.pcap"
done
[ ! -e "$tmp/x.pcap" ] || fail "output file created on a usage error"

# Valid intervals get as far as the interface lookup, with every existing
# option combination.
for args in "-i 0" "-i 5" "-i 86400" "--interval 5" "--interval=5" \
            "-c 3 -i 2" "--count 10 --interval 5" "-c 1 -i 1 -p" \
            "-i 1 -f 2412,5180" "-p -f 5955 -c 2"; do
  # shellcheck disable=SC2086 # split the options on purpose
  expect 1 "$noif: No such device" $args "$noif" "$tmp/x.pcap"
done
expect 1 "$noif: No such device" -i 1 "$noif" -
[ ! -e "$tmp/x.pcap" ] || fail "output file created for a missing interface"

if [ "$failures" -ne 0 ]; then
  echo "$failures CLI test(s) failed" >&2
  exit 1
fi
echo "all CLI tests passed"
