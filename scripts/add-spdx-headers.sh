#!/usr/bin/env bash
# add-spdx-headers.sh
#
# Prepends SPDX license headers to all .rs files in the workspace.
# Safe to run multiple times — skips files that already have the header.
#
# Usage:
#   chmod +x add-spdx-headers.sh
#   ./add-spdx-headers.sh /path/to/workspace

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace-root>"
    exit 1
fi

WORKSPACE="$1"
COPYRIGHT_HOLDER="Jonathan Cormier"
COPYRIGHT_YEAR="2026"

HEADER="// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) ${COPYRIGHT_YEAR} ${COPYRIGHT_HOLDER}
// This file is part of Pesigitg."

MARKER="SPDX-License-Identifier"

COUNT=0
SKIPPED=0

while IFS= read -r -d '' FILE; do
    # Skip files that already have the header
    if head -n 1 "$FILE" | grep -q "$MARKER"; then
        echo "Skip $FILE (already has header)"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # For files starting with #! (shebang) or #![...] (Rust crate attrs),
    # insert the header BEFORE those lines with a blank line after
    FIRST_LINE=$(head -n 1 "$FILE")

    TMPFILE=$(mktemp)
    if [[ "$FIRST_LINE" == "#!"* ]]; then
        # Collect leading #![...] attribute lines
        ATTR_LINES=""
        LINE_NUM=0

        while IFS= read -r LINE; do
            if [[ "$LINE" == "#!"* ]]; then
                ATTR_LINES="${ATTR_LINES}${LINE}"$'\n'
                LINE_NUM=$((LINE_NUM + 1))
            else
                break
            fi
        done < "$FILE"

        # Write: header, blank line, attrs, rest of file
        {
            echo "$HEADER"
            echo ""
            echo -n "$ATTR_LINES"
            tail -n +"$((LINE_NUM + 1))" "$FILE"
        } > "$TMPFILE"
    else
        # Normal file — header at the top, blank line, then original content
        {
            echo "$HEADER"
            echo ""
            cat "$FILE"
        } > "$TMPFILE"
    fi

    mv "$TMPFILE" "$FILE"
    echo "Added $FILE"

    COUNT=$((COUNT + 1))

done < <(find "$WORKSPACE" -name '*.rs' -not -path '*/target/*' -print0)

echo ""
echo "Done. Added headers to $COUNT file(s), skipped $SKIPPED."
