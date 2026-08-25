---
name: check-formatting
description: Run everything CI's Format Check job runs — dotnet format and the decision register line cap. Run before opening any PR, and whenever formatting errors are reported by CI or the Stop hook.
allowed-tools:
  - Bash(git rev-parse *)
  - Bash(dotnet format)
  - Bash(dotnet format *)
  - Bash(wc -l *)
---

# Check and Fix Formatting

A Stop hook (`.claude/hooks/scripts/check-format.sh`) enforces formatting at the end of every turn — this skill is the fix-it procedure.

**This skill must run everything CI's `Format Check` job runs.** That job is two checks, not one, and
a branch that passes only the `dotnet format` half still fails the PR. If a step is ever added to
that job in `.github/workflows/ci.yml`, add it here in the same change.

## Steps

1. From the repo root (`git rev-parse --show-toplevel`), check the decision register line cap:

   ```sh
   for f in docs/decisions/*.md; do
     case "$(basename "$f")" in
       README.md|security-sign-offs.md) continue ;;
       [0-9][0-9][0-9][0-9]-*) continue ;;
     esac
     lines=$(wc -l < "$f")
     [ "$lines" -gt 180 ] && echo "$f: $lines lines, over the 180-line cap"
   done
   ```

   Over the cap: cut words or split the topic. **Do not raise the cap** — it exists because a written
   "half a page" target didn't hold the old ADRs, which reached 4,270 lines across 14 documents.

   The cap is **temporarily 180**, not its usual 150, while `signing-keys.md` carries entries for both
   the old signing model and the new key-ring one. #511 deletes the old model and restores 150. Treat
   180 as borrowed, not as the budget.

2. Then run:

   ```sh
   dotnet format ZeeKayDa.Auth.slnx --verify-no-changes
   ```

   The explicit `ZeeKayDa.Auth.slnx` path is required: the repo also carries per-OS solution
   filters (`ZeeKayDa.Auth.{Windows,MacOS,Linux}.slnf`) that `dotnet format`'s auto-discovery
   treats as candidate solution files, so a bare `dotnet format` errors with "Multiple MSBuild
   solution files found" instead of running.

3. If it exits non-zero, run `dotnet format ZeeKayDa.Auth.slnx` to fix the issues, then re-run the verify step.

4. Repeat until both the line cap check prints nothing and `--verify-no-changes` exits 0.
