#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT_DIR/third_party/src"
BUILD_DIR="$ROOT_DIR/third_party/build"
LOCAL_DIR="$ROOT_DIR/third_party/local"
LOCAL_BIN="$LOCAL_DIR/bin"

M4_VERSION="1.4.19"
GMP_VERSION="6.3.0"
PBC_VERSION="0.5.14"

M4_TAR="$SRC_DIR/m4-$M4_VERSION.tar.xz"
GMP_TAR="$SRC_DIR/gmp-$GMP_VERSION.tar.xz"
PBC_TAR="$SRC_DIR/pbc-$PBC_VERSION.tar.gz"
PYPBC_REV="ee629b4863a2d0d5b1d3c5594f6de9c6e7aa2cd6"
PYPBC_ZIP="$SRC_DIR/pypbc-$PYPBC_REV.zip"
PYPBC_BUILD="$BUILD_DIR/pypbc-$PYPBC_REV"

JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
ARCH_NAME="$(uname -m)"

msg() {
  echo "[setup_pypbc] $*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

download_if_missing() {
  local url="$1"
  local out="$2"
  if [[ -f "$out" ]]; then
    msg "Using cached file: $out"
  else
    msg "Downloading: $url"
    curl -L --fail -o "$out" "$url"
  fi
}

extract_if_missing_dir() {
  local archive="$1"
  local target_dir="$2"
  if [[ -d "$target_dir" ]]; then
    msg "Using existing extracted dir: $target_dir"
  else
    msg "Extracting: $archive"
    tar -xf "$archive" -C "$BUILD_DIR"
  fi
}

usable_m4() {
  if ! command -v m4 >/dev/null 2>&1; then
    return 1
  fi
  local out
  if ! out="$(printf "define(\`x',\`1')\nx\n" | m4 2>/dev/null)"; then
    return 1
  fi
  [[ "$out" == "1" ]]
}

ensure_m4() {
  mkdir -p "$SRC_DIR" "$BUILD_DIR" "$LOCAL_DIR"
  if usable_m4; then
    msg "System m4 is usable."
    return
  fi

  if [[ -x "$LOCAL_BIN/m4" ]]; then
    msg "Using local m4 at $LOCAL_BIN/m4"
    return
  fi

  msg "System m4 unavailable; building local GNU m4..."
  download_if_missing "https://ftp.gnu.org/gnu/m4/m4-$M4_VERSION.tar.xz" "$M4_TAR"
  extract_if_missing_dir "$M4_TAR" "$BUILD_DIR/m4-$M4_VERSION"

  (
    cd "$BUILD_DIR/m4-$M4_VERSION"
    ./configure --prefix="$LOCAL_DIR"
    make -j"$JOBS"
    make install
  )
}

ensure_gmp() {
  if [[ -f "$LOCAL_DIR/lib/libgmp.a" && -f "$LOCAL_DIR/include/gmp.h" ]]; then
    msg "GMP already installed in $LOCAL_DIR"
    return
  fi

  msg "Building GMP..."
  download_if_missing "https://gmplib.org/download/gmp/gmp-$GMP_VERSION.tar.xz" "$GMP_TAR"
  extract_if_missing_dir "$GMP_TAR" "$BUILD_DIR/gmp-$GMP_VERSION"

  (
    cd "$BUILD_DIR/gmp-$GMP_VERSION"
    export PATH="$LOCAL_BIN:$PATH"
    M4="$(command -v m4)" ./configure --prefix="$LOCAL_DIR" --enable-cxx
    PATH="$LOCAL_BIN:$PATH" make -j"$JOBS"
    PATH="$LOCAL_BIN:$PATH" make install
  )
}

ensure_pbc() {
  if [[ -f "$LOCAL_DIR/lib/libpbc.a" && -f "$LOCAL_DIR/include/pbc/pbc.h" ]]; then
    msg "PBC already installed in $LOCAL_DIR"
    return
  fi

  msg "Building PBC (static)..."
  download_if_missing "https://crypto.stanford.edu/pbc/files/pbc-$PBC_VERSION.tar.gz" "$PBC_TAR"
  extract_if_missing_dir "$PBC_TAR" "$BUILD_DIR/pbc-$PBC_VERSION"

  (
    cd "$BUILD_DIR/pbc-$PBC_VERSION"
    PATH="$LOCAL_BIN:$PATH" \
    CPPFLAGS="-I$LOCAL_DIR/include" \
    LDFLAGS="-L$LOCAL_DIR/lib" \
    ./configure --prefix="$LOCAL_DIR" --disable-shared --enable-static

    PATH="$LOCAL_BIN:$PATH" make -j"$JOBS"
    PATH="$LOCAL_BIN:$PATH" make install
  )
}

ensure_pypbc() {
  msg "Installing Python build tooling..."
  python3 -m pip install setuptools wheel

  download_if_missing "https://github.com/Jemtaly/pypbc/archive/$PYPBC_REV.zip" "$PYPBC_ZIP"

  msg "Preparing pypbc source..."
  if [[ ! -d "$PYPBC_BUILD" ]]; then
    unzip -q "$PYPBC_ZIP" -d "$BUILD_DIR"
  fi

  # Ensure pypbc links both pbc and gmp.
  python3 - "$PYPBC_BUILD/setup.py" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = 'libraries=["pbc"],'
new = 'libraries=["pbc", "gmp"],'
if old in text:
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")
PY

  msg "Installing pypbc..."
  ARCHFLAGS="-arch $ARCH_NAME" \
  CPPFLAGS="-I$LOCAL_DIR/include" \
  CFLAGS="-I$LOCAL_DIR/include" \
  LDFLAGS="-L$LOCAL_DIR/lib" \
  python3 -m pip install --force-reinstall --no-build-isolation "$PYPBC_BUILD"
}

verify_install() {
  msg "Verifying pypbc import..."
  python3 - <<'PY'
import pypbc
print("pypbc import ok:", pypbc.__file__)
PY
}

main() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This setup script currently targets macOS (Darwin)." >&2
    echo "For Linux/WSL, use the same build idea with package manager equivalents." >&2
    exit 1
  fi
  if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    echo "Activate a Python virtual environment before running this script." >&2
    exit 1
  fi

  need_cmd python3
  need_cmd curl
  need_cmd tar
  need_cmd unzip
  need_cmd make
  need_cmd gcc
  need_cmd flex
  need_cmd bison

  mkdir -p "$SRC_DIR" "$BUILD_DIR" "$LOCAL_DIR"

  ensure_m4
  ensure_gmp
  ensure_pbc
  ensure_pypbc
  verify_install

  msg "Done."
  msg "Then run: python3 run_rwacred_demo.py --profile sigfast"
}

main "$@"

