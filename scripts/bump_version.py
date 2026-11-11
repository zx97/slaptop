#!/usr/bin/env python3
"""Propose (or apply) the next version from what changed since the last one.

The version lives in one place, `project(slaptop VERSION x.y.z)` in
CMakeLists.txt.  This script finds the commit that introduced the current
version, reads every commit subject after it (plus the working tree), and
derives the bump from the commit types:

    BREAKING CHANGE or `type!:`   major
    feat                          minor
    everything else               patch
    nothing changed               none ("already up to date")

Usage:
    scripts/bump_version.py                  # dry run: print the decision
    scripts/bump_version.py --apply          # write the new version
    scripts/bump_version.py --level patch    # force a level (this time only)
    scripts/bump_version.py --apply --level minor

Why not a git hook: a version that moves by itself during `git commit` turns a
mistyped subject into a release number, and a rebase replays the bump.  Run it
when you decide to release, then commit the result as `chore(release): x.y.z`.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CMAKE = ROOT / "CMakeLists.txt"
PROJECT_RE = re.compile(r"project\(\s*slaptop\s+VERSION\s+(\d+)\.(\d+)\.(\d+)")
TYPE_RE = re.compile(r"^([a-zA-Z]+)(\([^)]*\))?(!)?:")
BREAKING_RE = re.compile(r"BREAKING[ -]CHANGE:")

LEVELS = ("none", "patch", "minor", "major")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def current_version() -> tuple[int, int, int]:
    text = CMAKE.read_text(encoding="utf-8")
    match = PROJECT_RE.search(text)
    if match is None:
        sys.exit("bump_version: no `project(slaptop VERSION x.y.z)` in CMakeLists.txt")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def version_text(version: tuple[int, int, int]) -> str:
    return "%d.%d.%d" % version


def base_commit(version: tuple[int, int, int]) -> tuple[str, str]:
    """Commit that introduced `version`, and its subject."""
    needle = "VERSION " + version_text(version)
    try:
        out = git("log", "-S", needle, "--format=%H%x1f%s", "--", "CMakeLists.txt")
    except subprocess.CalledProcessError:
        return "", ""
    # `-S` returns every commit whose diff changes the count of `needle`; the
    # oldest is the one that introduced it, the newest is the last bump.
    lines = [line for line in out.splitlines() if line.strip()]
    if not lines:
        return "", ""
    # git log is newest first: the *oldest* entry introduced the string.
    fields = lines[-1].split("\x1f")
    return (fields[0], fields[1] if len(fields) > 1 else "")


def is_dirty() -> bool:
    try:
        return bool(git("status", "--porcelain").strip())
    except subprocess.CalledProcessError:
        return False


def classify(subject: str, body: str) -> str:
    if BREAKING_RE.search(body) or re.match(r"^[a-zA-Z]+(\([^)]*\))?!:", subject):
        return "major"
    match = TYPE_RE.match(subject)
    if match is not None and match.group(1).lower() == "feat":
        return "minor"
    return "patch"


def bump(version: tuple[int, int, int], level: str) -> tuple[int, int, int]:
    major, minor, patch = version
    if level == "major":
        return (major + 1, 0, 0)
    if level == "minor":
        return (major, minor + 1, 0)
    if level == "patch":
        return (major, minor, patch + 1)
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--level",
        choices=("auto", *LEVELS[1:]),
        default="auto",
        help="force a level instead of inferring it from the commits",
    )
    parser.add_argument("--apply", action="store_true", help="write the new version")
    args = parser.parse_args()

    version = current_version()
    base, base_subject = base_commit(version)
    if base:
        subjects = [
            line
            for line in git("log", "--format=%s%x1f%b%x1e", f"{base}..HEAD").split("\x1e")
            if line.strip()
        ]
    else:
        subjects = []

    commits = []
    inferred = "none"
    for record in subjects:
        subject, _, body = record.partition("\x1f")
        subject = subject.strip()
        if not subject:
            continue
        commits.append(subject)
        level = classify(subject, body)
        order = LEVELS.index(level)
        if order > LEVELS.index(inferred):
            inferred = level

    dirty = is_dirty()
    if dirty and inferred == "none":
        # Uncommitted work is still a change; the type is unknown, so the
        # safest release is a patch.
        inferred = "patch"

    level = args.level if args.level != "auto" else inferred
    print("current:   " + version_text(version))
    if base:
        print("base:      %s %s" % (base[:8], base_subject))
    else:
        print("base:      (no commit found for this version; whole history considered)")
    print("changes:   %d commit(s)%s" % (len(commits), " + uncommitted changes" if dirty else ""))
    for subject in commits:
        print("  - " + subject)
    print("inferred:  " + inferred)
    if args.level != "auto":
        print("level:     %s (forced)" % level)
    if level == "none":
        print("next:      nothing to release")
        return 0

    nxt = bump(version, level)
    print("next:      " + version_text(nxt))
    if not args.apply:
        print("(dry run: pass --apply to write CMakeLists.txt)")
        return 0

    text = CMAKE.read_text(encoding="utf-8")
    updated = PROJECT_RE.sub(
        "project(slaptop VERSION %s" % version_text(nxt), text, count=1
    )
    CMAKE.write_text(updated, encoding="utf-8")
    print("wrote:     CMakeLists.txt -> %s" % version_text(nxt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
