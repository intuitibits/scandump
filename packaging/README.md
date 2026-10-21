# scandump distribution packaging

This directory holds packaging for distributions other than Debian and the
scripts that build and check every package. The Debian packaging is in
[`../debian/`](../debian/) because the Debian tools expect it there.

| Path | Purpose |
| --- | --- |
| `../debian/` | Debian/Ubuntu source package (format `3.0 (quilt)`, debhelper compat 13) |
| `arch/PKGBUILD` | Arch Linux / AUR |
| `fedora/scandump.spec`, `fedora/scandump.rpmlintrc` | Fedora / EPEL |
| `ci/make-tarball.sh` | Release-style source tarball of the working tree, for testing before a tag exists |
| `ci/build-deb.sh`, `ci/build-arch.sh`, `ci/build-rpm.sh` | Build from the tarball, lint, install, run, check for granted privileges, remove |

Upstream changes stay in the source tree (`Makefile`, `scandump.8`, docs).
Nothing under `packaging/` or `debian/` patches the sources.

## Validating locally

Each script runs as root in a disposable container, starting from a clean
tarball, so the checkout itself is never built in. With Docker or Podman:

```shell
docker run --rm -v "$PWD":/src:ro -v "$PWD/out":/out -e OUT=/out -w /src debian:sid  sh packaging/ci/build-deb.sh
docker run --rm -v "$PWD":/src:ro -v "$PWD/out":/out -e OUT=/out -w /src fedora:latest sh packaging/ci/build-rpm.sh
docker run --rm --platform linux/amd64 -v "$PWD":/src:ro -v "$PWD/out":/out -e OUT=/out -w /src archlinux:latest sh packaging/ci/build-arch.sh
```

For Debian/Ubuntu releases older than sid, add `-e LINTIAN_FAIL_ON=error`:
their lintian warns about a `Standards-Version` newer than it knows.

CI (`.github/workflows/ci.yml`) runs the same scripts on every pull request
and push to `main`, plus GCC and Clang builds with `-Werror`, a build from `make dist`
outside the Git checkout, cppcheck, `gcc -fanalyzer` and mandoc lint.
Packages are kept as workflow artifacts and never published.
`.github/workflows/functional.yml` runs real scans against simulated radios
(`mac80211_hwsim` + hostapd) on pull requests that change `scandump.c`, and can be started manually.

