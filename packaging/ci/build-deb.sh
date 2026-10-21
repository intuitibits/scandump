#!/bin/sh
# Builds and checks the Debian source and binary packages from a clean
# source tarball (which, like a release tarball, has no debian/) plus the
# repository's debian/ directory. Runs as root in a Debian or Ubuntu container from the
# repository root; artifacts are copied to OUT (default: ./out/deb).
set -eu

export DEBIAN_FRONTEND=noninteractive
top=$(pwd)
out=${OUT:-$top/out/deb}
work=$(mktemp -d)

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential debhelper devscripts equivs lintian autopkgtest \
  fakeroot >/dev/null

tarball=$(packaging/ci/make-tarball.sh "$work")
version=$(basename "$tarball" .tar.gz | sed 's/^scandump-//')
mv "$tarball" "$work/scandump_$version.orig.tar.gz"
tar -C "$work" -xzf "$work/scandump_$version.orig.tar.gz"
cp -R "$top/debian" "$work/scandump-$version/"

# Run from outside the source tree: older mk-build-deps leave .buildinfo and
# .changes files in the current directory, which dpkg-source rejects.
cd "$work"
mk-build-deps --install --remove \
  --tool 'apt-get -y -qq --no-install-recommends' \
  "scandump-$version/debian/control" >/dev/null
rm -f scandump-build-deps_*
cd "scandump-$version"

dpkg-buildpackage -us -uc
cd "$work"

echo "--- lintian"
# Older releases' lintian flag a Standards-Version newer than they know, so
# CI relaxes LINTIAN_FAIL_ON there; sid must be warning-free. Ubuntu's
# lintian rejects the changelog's Debian distribution (unstable).
suppress=new-package-should-close-itp-bug
if grep -qx 'ID=ubuntu' /etc/os-release; then
  suppress=$suppress,bad-distribution-in-changes-file
fi
lintian --info --display-info --pedantic --fail-on "${LINTIAN_FAIL_ON:-error,warning}" \
  --suppress-tags "$suppress" \
  ./*.changes

echo "--- install / run / remove"
apt-get install -y -qq "./scandump_${version}-"*.deb >/dev/null
scandump --version
# Check the package contents rather than the installed files: minimized
# Ubuntu images drop man pages and docs at install time.
contents=$(dpkg-deb -c "./scandump_${version}-"*.deb)
echo "$contents" | grep -q " ./usr/share/man/man8/scandump.8.gz$"
echo "$contents" | grep -q " ./usr/share/doc/scandump/examples/sudoers$"
# No privileges granted: nothing under /etc, no setuid/setgid files, no
# maintainer scripts (the only way a .deb could run setcap).
# (Explicit ifs: set -e ignores a failing "! pipeline".)
if echo "$contents" | grep -q " ./etc/"; then
  echo "package installs files under /etc" >&2; exit 1
fi
if echo "$contents" | grep -qE "^-..[sS]|^-.....[sS]"; then
  echo "package contains setuid/setgid files" >&2; exit 1
fi
if dpkg-deb --ctrl-tarfile "./scandump_${version}-"*.deb | tar -t |
   grep -vqE "^\./(control|md5sums)?$"; then
  echo "package has maintainer scripts or conffiles" >&2; exit 1
fi
test ! -e /etc/sudoers.d/scandump
# Exit status 8 means every test passed but all are marked superficial.
rc=0; autopkgtest ./*.changes -- null || rc=$?
[ "$rc" -eq 0 ] || [ "$rc" -eq 8 ]
apt-get purge -y -qq scandump >/dev/null
test ! -e /usr/bin/scandump

mkdir -p "$out"
cp ./*.deb ./*.dsc ./*.tar.* ./*.changes ./*.buildinfo "$out"/
