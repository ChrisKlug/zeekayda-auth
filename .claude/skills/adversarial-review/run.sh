#!/usr/bin/env bash
# Adversarial review of the current branch through the GitHub Copilot CLI.
# Read-only by construction: write, shell and patch tools are denied, and the
# working tree is compared before and after so any change aborts the run loudly.
#
# Usage: run.sh <code|security|architecture> [--base <ref>] [--model <id>] [--effort <level>] [focus text...]
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

lens=""
base="origin/main"
model=""
effort=""
focus=()
while [ $# -gt 0 ]; do
  case "$1" in
    code|security|architecture) lens="$1" ;;
    --base)   base="$2";   shift ;;
    --model)  model="$2";  shift ;;
    --effort) effort="$2"; shift ;;
    *) focus+=("$1") ;;
  esac
  shift
done

if [ -z "$lens" ]; then
  echo "usage: run.sh <code|security|architecture> [--base <ref>] [--model <id>] [--effort <level>] [focus text...]" >&2
  exit 2
fi

# Per-lens defaults. Override per run with --model / --effort.
case "$lens" in
  code)         : "${model:=gpt-5.6-terra}"; : "${effort:=high}" ;;
  security)     : "${model:=gpt-5.6-sol}";   : "${effort:=high}" ;;
  architecture) : "${model:=gpt-5.6-sol}";   : "${effort:=high}" ;;
esac

COPILOT="$(command -v copilot || true)"
if [ -z "$COPILOT" ]; then
  COPILOT="$HOME/AppData/Local/Microsoft/WinGet/Packages/GitHub.Copilot_Microsoft.Winget.Source_8wekyb3d8bbwe/copilot.exe"
fi
if [ ! -x "$COPILOT" ]; then
  echo "copilot CLI not found. Install with: winget install GitHub.Copilot" >&2
  exit 3
fi

merge_base="$(git merge-base HEAD "$base")"
range="$merge_base..HEAD"
commits="$(git log --oneline "$range")"
if [ -z "$commits" ]; then
  echo "nothing to review: HEAD has no commits beyond $base" >&2
  exit 4
fi
branch="$(git branch --show-current || echo HEAD)"
focus_text="${focus[*]:-No extra focus.}"

# The brief lives in the system temp directory, which Copilot may read by default.
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
brief="$work_dir/brief.md"
{
  cat "$SKILL_DIR/prompts/$lens.md"
  echo
  echo "## Review target"
  echo
  echo "- Repository: $REPO_ROOT (the current working directory)"
  echo "- Branch: $branch"
  echo "- Base: $base (merge-base $merge_base)"
  echo "- Commit range: $range"
  echo "- Focus: $focus_text"
  echo
  echo "## Commits under review"
  echo
  echo '```'
  echo "$commits"
  echo '```'
  echo
  echo "## Diff stat"
  echo
  echo '```'
  git diff --stat "$range"
  echo '```'
  echo
  echo "## Diff"
  echo
  echo 'Line numbers in findings refer to the post-change file, not to diff hunks.'
  echo
  echo '```diff'
  git diff --no-color --no-ext-diff "$range"
  echo '```'
} > "$brief"
brief_win="$(cygpath -w "$brief" 2>/dev/null || echo "$brief")"

prompt="You are performing an adversarial code review. Your complete brief, including the diff under review, is in the file $brief_win. Read that file in full with the view tool before doing anything else, then follow it exactly. The repository under review is the current working directory and you may read any file in it. Do not narrate your progress or announce what you are about to do: the first line you emit must be the verdict line, and nothing may follow the last section of the specified output format."

before="$(git status --porcelain)"

echo "adversarial-review: lens=$lens model=$model effort=$effort range=$range" >&2

set +e
"$COPILOT" \
  -s --no-auto-update --no-ask-user --disable-builtin-mcps --no-remote-export \
  --allow-all-tools --deny-tool write --deny-tool shell \
  --excluded-tools apply_patch write_agent task sql session_store_sql \
  --allow-url https://www.rfc-editor.org --allow-url https://openid.net --allow-url https://datatracker.ietf.org \
  --model "$model" --effort "$effort" \
  -p "$prompt"
status=$?
set -e

after="$(git status --porcelain)"
if [ "$before" != "$after" ]; then
  echo >&2
  echo "ADVERSARIAL-REVIEW: the working tree changed during the review. Inspect with 'git status' before doing anything else." >&2
  exit 5
fi

exit "$status"
