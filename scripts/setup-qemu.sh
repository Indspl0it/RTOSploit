#!/usr/bin/env bash
# setup-qemu.sh — Build and install QEMU v9.2.0 with ARM softmmu target
#
# Usage:
#   bash scripts/setup-qemu.sh [--prefix PREFIX]
#
# Options:
#   --prefix PREFIX   Installation prefix (default: ~/.local)
#
# Requirements:
#   git, ninja, meson, gcc, libglib2.0-dev, libpixman-1-dev
#
# The binary will be installed as:
#   PREFIX/bin/qemu-system-arm-rtosploit

set -euo pipefail

QEMU_VERSION="v9.2.0"
QEMU_REPO="https://github.com/qemu/qemu"
INSTALL_PREFIX="${HOME}/.local"
BUILD_DIR="${TMPDIR:-/tmp}/qemu-rtosploit-build"
BINARY_NAME="qemu-system-arm-rtosploit"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            INSTALL_PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            INSTALL_PREFIX="${1#--prefix=}"
            shift
            ;;
        --help|-h)
            sed -n '2,15p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

INSTALL_BIN="${INSTALL_PREFIX}/bin"

echo "==> RTOSploit QEMU ${QEMU_VERSION} build script"
echo "    Install prefix: ${INSTALL_PREFIX}"
echo "    Binary name:    ${BINARY_NAME}"
echo ""

# --- Dependency check ---
check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: Required tool '$1' not found." >&2
        echo "       Install with: sudo apt-get install $2" >&2
        return 1
    fi
}

echo "==> Checking dependencies..."
check_dep git git
check_dep ninja ninja-build
check_dep meson meson
check_dep gcc gcc
check_dep pkg-config pkg-config

# Check for required libraries
if ! pkg-config --exists glib-2.0 2>/dev/null; then
    echo "ERROR: libglib2.0-dev not found." >&2
    echo "       Install with: sudo apt-get install libglib2.0-dev" >&2
    exit 1
fi

if ! pkg-config --exists pixman-1 2>/dev/null; then
    echo "ERROR: libpixman-1-dev not found." >&2
    echo "       Install with: sudo apt-get install libpixman-1-dev" >&2
    exit 1
fi

echo "    All dependencies found."
echo ""

# --- Clone QEMU ---
QEMU_SRC="${BUILD_DIR}/qemu"

if [[ -d "${QEMU_SRC}" ]]; then
    echo "==> QEMU source already exists at ${QEMU_SRC}"
    echo "    Checking out ${QEMU_VERSION}..."
    cd "${QEMU_SRC}"
    git fetch --tags --quiet
    git checkout "${QEMU_VERSION}" --quiet
else
    echo "==> Cloning QEMU ${QEMU_VERSION} from ${QEMU_REPO}..."
    mkdir -p "${BUILD_DIR}"
    git clone \
        --branch "${QEMU_VERSION}" \
        --depth 1 \
        --recursive \
        "${QEMU_REPO}" \
        "${QEMU_SRC}"
    cd "${QEMU_SRC}"
fi

# --- Configure ---
QEMU_BUILD="${BUILD_DIR}/build"
echo ""
echo "==> Configuring QEMU (target: arm-softmmu)..."
mkdir -p "${QEMU_BUILD}"

"${QEMU_SRC}/configure" \
    --prefix="${INSTALL_PREFIX}" \
    --target-list=arm-softmmu \
    --disable-werror \
    --enable-system \
    --disable-user \
    --disable-docs \
    --disable-gtk \
    --disable-sdl \
    --disable-opengl \
    --disable-virglrenderer \
    --disable-vnc \
    --audio-drv-list="" \
    --extra-cflags="-O2" \
    2>&1 | tail -20

# --- Build ---
echo ""
echo "==> Building QEMU (this may take 10-20 minutes)..."
CPUS=$(nproc 2>/dev/null || echo 4)
ninja -C "${QEMU_BUILD}" -j "${CPUS}"

# --- Install ---
echo ""
echo "==> Installing QEMU to ${INSTALL_PREFIX}..."
mkdir -p "${INSTALL_BIN}"
ninja -C "${QEMU_BUILD}" install

# Rename binary to avoid conflicts with system QEMU
SRC_BINARY="${INSTALL_BIN}/qemu-system-arm"
DST_BINARY="${INSTALL_BIN}/${BINARY_NAME}"

if [[ -f "${SRC_BINARY}" ]]; then
    cp "${SRC_BINARY}" "${DST_BINARY}"
    echo "    Installed: ${DST_BINARY}"
fi

# --- Verify ---
echo ""
echo "==> Verifying installation..."
if "${DST_BINARY}" --version; then
    echo ""
    echo "==> SUCCESS: QEMU ${QEMU_VERSION} installed as ${BINARY_NAME}"
    echo ""
    echo "    Add to PATH if needed:"
    echo "      export PATH=\"${INSTALL_BIN}:\$PATH\""
    echo ""
    echo "    Or configure rtosploit to use it:"
    echo "      echo 'qemu:' >> .rtosploit.yaml"
    echo "      echo '  binary: ${DST_BINARY}' >> .rtosploit.yaml"
else
    echo "ERROR: Binary verification failed!" >&2
    exit 1
fi
