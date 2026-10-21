#!/bin/sh
# Builds and checks the Arch Linux package from a clean source tarball of the
# working tree (substituted for the GitHub release archive, which may not
# exist yet). Runs as root in an archlinux container from the repository
# root; artifacts are copied to OUT (default: ./out/arch).
set -eu

top=$(pwd)
out=${OUT:-$top/out/arch}
work=$(mktemp -d)

# pacman's download sandbox can't set up seccomp in some container runtimes
# (e.g. under emulation); this is a disposable build container.
sed -i 's/^#DisableSandbox\(Syscalls\)\?$/DisableSandbox\1/' /etc/pacman.conf
pacman -Syu --noconfirm --needed base-devel namcap pacman-contrib libnl libpcap >/dev/null
useradd -m builder 2>/dev/null || true

packaging/ci/make-tarball.sh "$work" >/dev/null
cp packaging/arch/PKGBUILD "$work/"
cd "$work"
sed -i 's|^source=.*|source=("$pkgname-$pkgver.tar.gz")|' PKGBUILD
chown -R builder: "$work"
su builder -c 'updpkgsums && makepkg --noconfirm --cleanbuild && makepkg --printsrcinfo > .SRCINFO'

echo "--- namcap"
pkg=$(ls ./scandump-*.pkg.tar.zst | grep -v -- -debug-)
namcap PKGBUILD
# Not the -debug package: its build-id links point at the main package's
# binary, which namcap reports as dangling.
namcap "$pkg"

echo "--- install / run / remove"
pacman -U --noconfirm "$pkg" >/dev/null
scandump --version
# Check the package contents rather than the installed files: the archlinux
# image's NoExtract drops man pages and docs at install time.
contents=$(bsdtar -tf "$pkg")
echo "$contents" | grep -qx usr/share/man/man8/scandump.8.gz
echo "$contents" | grep -qx usr/share/doc/scandump/examples/sudoers
test ! -e /etc/sudoers.d/scandump
if echo "$contents" | grep -q '^etc/'; then
  echo "package installs files under /etc" >&2; exit 1
fi
if [ -n "$(find $(pacman -Qlq scandump | grep -v /$) -perm /6000 2>/dev/null)" ]; then
  echo "package contains setuid/setgid files" >&2; exit 1
fi
if [ -n "$(getcap /usr/bin/scandump)" ]; then
  echo "binary has file capabilities" >&2; exit 1
fi
if echo "$contents" | grep -q '^\.INSTALL$'; then
  echo "package has an install script" >&2; exit 1
fi
pacman -R --noconfirm scandump >/dev/null
test ! -e /usr/bin/scandump

mkdir -p "$out"
cp ./*.pkg.tar.zst PKGBUILD .SRCINFO "$out"/
