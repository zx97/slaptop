#!/usr/bin/env bash
# Publish the current tree to the public mirrors, with one commit per release
# instead of the working history.
#
# The public repositories are a *snapshot series*: each run copies the tracked
# tree (minus .publicignore) on top of what is already published and commits
# once, then pushes the commit and a vX.Y.Z tag to both remotes.  The private
# history never leaves this machine, and the two mirrors stay identical.
#
# Usage: scripts/publish-public.sh [--dry-run] [--no-tag] [--fresh]
#
# --fresh starts a new root commit instead of continuing the published one: it
# is the tool for replacing a repository whose history must not survive.
#
# Remotes, in the order packages are built: "origin" (GitHub, also publishes
# the release) then "gitlab".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DRY_RUN=0
TAG=1
FRESH=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --no-tag) TAG=0 ;;
        --fresh) FRESH=1 ;;
        *) echo "usage: $0 [--dry-run] [--no-tag] [--fresh]" >&2; exit 2 ;;
    esac
done

# The hook can be bypassed (the temp clone has none): check here too.
python3 tools/check_anonymity.py || {
    echo "publish: the tree still carries environment data, nothing was pushed" >&2
    exit 1
}

VERSION="$(scripts/version.sh)"
TAG_NAME="v$VERSION"
ORIGIN="$(git remote get-url origin 2>/dev/null || true)"
GITLAB="$(git remote get-url gitlab 2>/dev/null || true)"
if [ -z "$ORIGIN" ] || [ -z "$GITLAB" ]; then
    echo "publish: remotes 'origin' (GitHub) and 'gitlab' must exist" >&2
    echo "  git remote add origin <url> ; git remote add gitlab <url>" >&2
    exit 1
fi

# Scratch space on tmpfs; the publishable tree is small (sources + docs).
WORK="$(mktemp -d -p /dev/shm slaptop-publish.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

echo "== collecting the publishable tree"
mkdir -p "$WORK/tree"
git ls-files -z | rsync -a --from0 --files-from=- "$ROOT"/ "$WORK/tree"/
if [ -f .publicignore ]; then
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        rm -rf "${WORK:?}/tree/$line"
        echo "   excluded: $line"
    done < .publicignore
fi

echo "== building the public commit"
if [ "$FRESH" = 0 ] && git clone --depth 1 --quiet "$ORIGIN" "$WORK/repo" 2>/dev/null; then
    echo "   continuing the published history"
else
    echo "   first commit"
    mkdir -p "$WORK/repo"
    git -C "$WORK/repo" init --quiet
    git -C "$WORK/repo" remote add origin "$ORIGIN"
fi
# The public tree is replaced wholesale: what is not in this release is not in
# the repository either.
rsync -a --delete --exclude .git "$WORK/tree"/ "$WORK/repo"/

# Provenance without the private history: the commit says which release it is.
git -C "$WORK/repo" add -A
if git -C "$WORK/repo" diff --cached --quiet; then
    echo "   no change since the last publication"
else
    git -C "$WORK/repo" -c user.name="$(git config user.name || echo slaptop)" \
        -c user.email="$(git config user.email || echo slaptop@example.com)" \
        commit --quiet -m "slaptop $VERSION" \
        -m "Snapshot of the $VERSION release: sources, documentation and the CI
that builds the .deb, the .rpm and the portable tarball."
fi

git -C "$WORK/repo" remote set-url --add --push origin "$ORIGIN"
git -C "$WORK/repo" remote set-url --add --push origin "$GITLAB"

# The tag follows the snapshot: a correction published under the same version
# moves it, so both forges build the tree that is actually published.
if [ "$TAG" = 1 ]; then
    git -C "$WORK/repo" tag -f -a "$TAG_NAME" -m "slaptop $VERSION" >/dev/null
fi

if [ "$DRY_RUN" = 1 ]; then
    echo "== dry run, nothing pushed"
    git -C "$WORK/repo" log --oneline -1 --decorate
    echo "   origin -> $ORIGIN"
    echo "   gitlab -> $GITLAB"
    exit 0
fi

echo "== pushing to both mirrors"
if [ "$FRESH" = 1 ]; then
    git -C "$WORK/repo" push --quiet --force origin HEAD:main
else
    git -C "$WORK/repo" push --quiet origin HEAD:main
fi
if [ "$TAG" = 1 ]; then
    git -C "$WORK/repo" push --quiet --force origin "$TAG_NAME"
fi
echo "published $VERSION to $ORIGIN and $GITLAB"
