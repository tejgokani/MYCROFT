#!/bin/sh
# Mycroft installer.
#
#   curl --proto '=https' --tlsv1.2 -LsSf \
#     https://raw.githubusercontent.com/tejgokani/MYCROFT/main/install.sh | sh
#
# Downloads a prebuilt `mycroft` binary from the latest GitHub Release, verifies its
# SHA-256, and installs it. Configurable via environment variables:
#   MYCROFT_VERSION      tag to install (default: latest), e.g. v0.1.0
#   MYCROFT_INSTALL_DIR  install directory (default: $HOME/.local/bin)
set -eu

REPO="tejgokani/MYCROFT"
BIN="mycroft"
VERSION="${MYCROFT_VERSION:-latest}"
INSTALL_DIR="${MYCROFT_INSTALL_DIR:-$HOME/.local/bin}"

err() { printf 'error: %s\n' "$1" >&2; exit 1; }
info() { printf '%s\n' "$1" >&2; }

# --- detect platform ---------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Darwin)
    case "$arch" in
      arm64|aarch64) target="aarch64-apple-darwin" ;;
      x86_64)        target="x86_64-apple-darwin" ;;
      *) err "unsupported macOS architecture: $arch" ;;
    esac ;;
  Linux)
    case "$arch" in
      x86_64|amd64)  target="x86_64-unknown-linux-musl" ;;  # static, most portable
      aarch64|arm64) target="aarch64-unknown-linux-gnu" ;;
      *) err "unsupported Linux architecture: $arch" ;;
    esac ;;
  *)
    err "unsupported OS: $os (on Windows, download the .zip from the Releases page)" ;;
esac

archive="${BIN}-${target}.tar.gz"
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

# --- download helper ---------------------------------------------------------
download() { # url dest
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fLsS "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    err "need curl or wget to download"
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "Downloading ${archive} (${VERSION})..."
download "${base}/${archive}" "${tmp}/${archive}" \
  || err "download failed - no prebuilt binary for ${target}? try building from source"

# --- verify checksum (best-effort but preferred) -----------------------------
# Release checksum files are named mycroft-<target>.sha256 (their contents still
# reference the .tar.gz), so download that but keep the local name aligned to the archive.
if download "${base}/${BIN}-${target}.sha256" "${tmp}/${archive}.sha256" 2>/dev/null; then
  ( cd "$tmp"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -c "${archive}.sha256" >/dev/null 2>&1 || err "checksum verification FAILED"
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 -c "${archive}.sha256" >/dev/null 2>&1 || err "checksum verification FAILED"
    else
      info "warning: no sha256 tool found; skipping checksum verification"
    fi )
  info "Checksum verified."
else
  info "warning: no checksum file published; skipping verification"
fi

# --- install -----------------------------------------------------------------
tar -xzf "${tmp}/${archive}" -C "$tmp"
[ -f "${tmp}/${BIN}" ] || err "archive did not contain a ${BIN} binary"

mkdir -p "$INSTALL_DIR"
install -m 0755 "${tmp}/${BIN}" "${INSTALL_DIR}/${BIN}" 2>/dev/null \
  || { mv "${tmp}/${BIN}" "${INSTALL_DIR}/${BIN}"; chmod 0755 "${INSTALL_DIR}/${BIN}"; }

info "Installed ${BIN} to ${INSTALL_DIR}/${BIN}"
"${INSTALL_DIR}/${BIN}" --version 2>/dev/null || true

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) : ;;
  *) info ""
     info "Note: ${INSTALL_DIR} is not on your PATH. Add it, e.g.:"
     info "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.profile && . ~/.profile" ;;
esac
