#!/bin/sh
# Builds and checks the Fedora source and binary RPMs from a clean source
# tarball of the working tree (substituted for the GitHub release archive,
# which may not exist yet). Runs as root in a fedora container from the
# repository root; artifacts are copied to OUT (default: ./out/rpm).
set -eu

export LC_ALL=C.UTF-8

top=$(pwd)
out=${OUT:-$top/out/rpm}
topdir=$(mktemp -d)

dnf -y -q install rpm-build rpmlint dnf-plugins-core libcap >/dev/null
dnf -y -q builddep packaging/fedora/scandump.spec >/dev/null

mkdir -p "$topdir/SOURCES"
packaging/ci/make-tarball.sh "$topdir/SOURCES" >/dev/null

rpmbuild --define "_topdir $topdir" -ba packaging/fedora/scandump.spec

echo "--- rpmlint"
rpmlint -r packaging/fedora/scandump.rpmlintrc packaging/fedora/scandump.spec \
  "$topdir"/SRPMS/*.rpm "$topdir"/RPMS/*/*.rpm

echo "--- install / run / remove"
rpm=$(ls "$topdir"/RPMS/*/scandump-[0-9]*.rpm)
dnf -y -q install "$rpm" >/dev/null
scandump --version
rpm -ql scandump | grep -qx /usr/share/man/man8/scandump.8.gz
rpm -qd scandump | grep -q '/examples/sudoers$\|/sudoers$'
test ! -e /etc/sudoers.d/scandump
if rpm -ql scandump | grep -q '^/etc/'; then
  echo "package installs files under /etc" >&2; exit 1
fi
if [ -n "$(rpm -q --scripts scandump)" ]; then
  echo "package has scriptlets" >&2; exit 1
fi
if rpm -q --qf '[%{FILECAPS}\n]' scandump | grep -q .; then
  echo "package sets file capabilities" >&2; exit 1
fi
if rpm -q --qf '[%{FILEMODES:perms}\n]' scandump | grep -q '[sS]'; then
  echo "package contains setuid/setgid files" >&2; exit 1
fi
dnf -y -q remove scandump >/dev/null
test ! -e /usr/bin/scandump

mkdir -p "$out"
cp "$topdir"/SRPMS/*.rpm "$topdir"/RPMS/*/*.rpm "$out"/
