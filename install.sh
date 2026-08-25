#!/bin/sh
# PassBook — one-command setup.
#
#   ./install.sh
#
# Finds a usable Python, hands over to `passbook install`, and gets out of the
# way. Everything this script decides, it prints.
#
# It does not install anything into a Python the machine already relies on, and
# it does not need root. If no suitable Python exists it says so and stops,
# rather than half-installing and leaving you to find out later.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
minor_floor=9

# A Python that already has `cryptography` is worth more than a newer one
# without it: taking it skips provisioning entirely.
usable() {
    [ -x "$1" ] || command -v "$1" >/dev/null 2>&1 || return 1
    "$1" -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3, $minor_floor) else 1)" >/dev/null 2>&1
}

has_crypto() {
    "$1" -c "import cryptography" >/dev/null 2>&1
}

candidates="${PASSBOOK_PYTHON:-} python3 python3.14 python3.13 python3.12 python3.11 python3.10 python3.9"

chosen=""
for candidate in $candidates; do
    [ -n "$candidate" ] || continue
    resolved=$(command -v "$candidate" 2>/dev/null || true)
    [ -n "$resolved" ] || continue
    usable "$resolved" || continue
    if has_crypto "$resolved"; then
        chosen="$resolved"
        break
    fi
    [ -n "$chosen" ] || chosen="$resolved"
done

# uv can supply a Python on a machine that has none at all.
if [ -z "$chosen" ] && command -v uv >/dev/null 2>&1; then
    echo "no suitable Python found; asking uv for one…"
    uv python install >/dev/null 2>&1 || true
    resolved=$(uv python find 2>/dev/null || true)
    if [ -n "$resolved" ] && usable "$resolved"; then
        chosen="$resolved"
    fi
fi

if [ -z "$chosen" ]; then
    echo "PassBook needs Python 3.$minor_floor or newer, and none was found." >&2
    echo "Install one (https://python.org/downloads, or \`brew install python\`)," >&2
    echo "or set PASSBOOK_PYTHON to the interpreter you want used." >&2
    exit 1
fi

echo "python:    $chosen"
PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}" exec "$chosen" -m passbook_cli install "$@"
