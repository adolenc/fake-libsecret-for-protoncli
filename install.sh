#!/bin/sh
#
# Builds the fake libsecret and wraps the proton-drive binary so it loads the
# fake instead of the real one.
#
#   ./install.sh [/path/to/proton-drive]
#   ./install.sh --uninstall [/path/to/proton-drive]
#
# With no path given, the proton-drive found on $PATH is used.

set -e

PREFIX="${PREFIX:-$HOME/.local/lib/fakesecret}"
SRCDIR="$(dirname "$(readlink -f "$0")")"
MARKER="fakesecret-wrapper"

UNINSTALL=0
if [ "$1" = "--uninstall" ]; then
    UNINSTALL=1
    shift
fi

# --- locate the target binary ---

TARGET="$1"
if [ -z "$TARGET" ]; then
    TARGET="$(command -v proton-drive 2>/dev/null || true)"
fi
if [ -z "$TARGET" ]; then
    echo "error: proton-drive not found on \$PATH; pass its path explicitly" >&2
    exit 1
fi
TARGET="$(readlink -f "$TARGET")"
if [ ! -e "$TARGET" ]; then
    echo "error: $TARGET does not exist" >&2
    exit 1
fi
REAL="$TARGET.bin"

# --- uninstall ---

if [ "$UNINSTALL" = 1 ]; then
    if grep -q "$MARKER" "$TARGET" 2>/dev/null && [ -f "$REAL" ]; then
        rm -f "$TARGET"
        mv "$REAL" "$TARGET"
        echo "Restored original binary: $TARGET"
    else
        echo "$TARGET is not a wrapper; nothing to restore."
    fi
    rm -rf "$PREFIX"
    echo "Removed $PREFIX"
    echo "Your stored session is still at ~/.local/share/fake-secrets (delete it if you want)."
    exit 0
fi

# --- build and install the shim ---

make -C "$SRCDIR" >/dev/null
mkdir -p "$PREFIX"
cp "$SRCDIR/libsecret-1.so.0" "$PREFIX/libsecret-1.so.0"
cp "$SRCDIR/fakesecret.c" "$PREFIX/fakesecret.c"
chmod 755 "$PREFIX/libsecret-1.so.0"
echo "Built shim -> $PREFIX/libsecret-1.so.0"

# --- install the wrapper ---
#
# Guard against running twice: if the target is already our wrapper, the real
# binary has already been moved aside and must not be overwritten.

if grep -q "$MARKER" "$TARGET" 2>/dev/null; then
    echo "Wrapper already in place at $TARGET (shim rebuilt)."
    exit 0
fi

if [ -e "$REAL" ]; then
    echo "error: $REAL already exists but $TARGET is not a wrapper." >&2
    echo "Refusing to overwrite. Sort this out by hand." >&2
    exit 1
fi

mv "$TARGET" "$REAL"
cat > "$TARGET" <<EOF
#!/bin/sh
# $MARKER
#
# proton-drive uses Bun.secrets, which dlopen()s libsecret-1.so.0 and expects a
# D-Bus Secret Service daemon (org.freedesktop.secrets). On systems without one,
# this puts a plaintext stand-in ahead of the real libsecret on the loader path.
#
# The session token is stored UNENCRYPTED in ~/.local/share/fake-secrets
LD_LIBRARY_PATH="$PREFIX\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}" \\
  exec "\$(dirname "\$(readlink -f "\$0")")/$(basename "$REAL")" "\$@"
EOF
chmod +x "$TARGET"

echo "Original binary moved to $REAL"
echo "Wrapper installed at  $TARGET"
echo
echo "Now run: proton-drive auth login"
