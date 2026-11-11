#!/usr/bin/env python3
"""Print the CHANGELOG section of a version, for a release note.

Usage: changelog-section.py <version> [CHANGELOG.md]

Exits 0 and prints a fallback line when the section is absent.
"""
import re
import sys

version = sys.argv[1].lstrip("v") if len(sys.argv) > 1 else ""
path = sys.argv[2] if len(sys.argv) > 2 else "CHANGELOG.md"
if not version:
    sys.exit("usage: changelog-section.py <version> [CHANGELOG.md]")

with open(path, encoding="utf-8") as handle:
    text = handle.read()

match = re.search(
    rf"^## \[{re.escape(version)}\].*?(?=^## \[|\Z)",
    text,
    re.M | re.S,
)
print(match.group(0).rstrip() if match else f"Release {version}")
