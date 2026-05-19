#!/bin/sh
set -e

PREFIX="${1:-/usr/local}"
BINDIR="$PREFIX/bin"
SRC="${2:-target/release/hako}"

if [ ! -f "$SRC" ]; then
    echo "Binary not found at $SRC" >&2
    echo "Build first: cargo build --release" >&2
    exit 1
fi

install -Dm755 "$SRC" "$BINDIR/hako"
echo "Installed $BINDIR/hako"

for cmd in $("$BINDIR/hako" --list-commands); do
    (cd "$BINDIR" && ln -sf hako "$cmd")
    echo "  $BINDIR/$cmd -> hako"
done
