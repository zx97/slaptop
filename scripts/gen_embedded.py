#!/usr/bin/env python3
"""Splice LICENSE and README.md into src/embedded.cpp.

`slaptop --license` and `slaptop --doc` must print the very files the
repository carries.  Keeping two hand-maintained copies is how they drift
apart, so the C++ file is generated from the sources:

    LICENSE     is the licence text
    README.md   is the documentation
    src/embedded.cpp   is GENERATED here and committed

Usage:
    scripts/gen_embedded.py            rewrite src/embedded.cpp
    scripts/gen_embedded.py --check    exit 1 if it is stale

A source containing the raw-string terminator would break the literal, so that
is refused rather than silently producing invalid C++.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "src" / "embedded.cpp"
TERMINATOR = ")EMBED\""

HEADER = """// embedded.cpp
//
// GENERATED FILE - do not edit by hand.  scripts/gen_embedded.py splices
// LICENSE and README.md into the two literals below; `make doc` regenerates
// this file and `make check-doc` fails when it is stale.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "slaptop/embedded.hpp"

namespace slaptop::embedded {

const char* licenseText() {
    return R"EMBED(@LICENSE@)EMBED";
}

const char* documentationText() {
    return R"EMBED(@DOC@)EMBED";
}

}  // namespace slaptop::embedded
"""


def render() -> str:
    text = HEADER
    for token, path in (("@LICENSE@", ROOT / "LICENSE"), ("@DOC@", ROOT / "README.md")):
        body = path.read_text(encoding="utf-8")
        if not body.endswith("\n"):
            body += "\n"          # a literal must not end mid-line
        if TERMINATOR in body:
            sys.exit(f"gen_embedded: {path} contains {TERMINATOR}; it cannot be embedded")
        text = text.replace(token, body)
    return text


def main() -> int:
    wanted = render()
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else None

    if "--check" in sys.argv[1:]:
        if current == wanted:
            print("embedded.cpp is up to date")
            return 0
        print("embedded.cpp is STALE: run scripts/gen_embedded.py", file=sys.stderr)
        return 1

    if current == wanted:
        return 0  # nothing changed: do not touch the timestamp, do not rebuild
    OUTPUT.write_text(wanted, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
