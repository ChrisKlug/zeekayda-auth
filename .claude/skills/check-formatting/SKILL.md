---
name: check-formatting
description: Run everything CI's Format Check job runs — dotnet format, the decision register line cap, and the sign-off citation check. Run before opening any PR, and whenever formatting errors are reported by CI or the Stop hook.
allowed-tools:
  - Bash(git rev-parse *)
  - Bash(dotnet format)
  - Bash(dotnet format *)
  - Bash(wc -l *)
---

# Check and Fix Formatting

A Stop hook (`.claude/hooks/scripts/check-format.sh`) enforces formatting at the end of every turn — this skill is the fix-it procedure.

**This skill must run everything CI's `Format Check` job runs.** That job is three checks, not one,
and a branch that passes only the `dotnet format` third still fails the PR. If a step is ever added
to that job in `.github/workflows/ci.yml`, add it here in the same change.

## Steps

1. From the repo root (`git rev-parse --show-toplevel`), check the decision register line cap:

   ```sh
   for f in docs/decisions/*.md; do
     case "$(basename "$f")" in
       README.md|security-sign-offs.md) continue ;;
       [0-9][0-9][0-9][0-9]-*) continue ;;
     esac
     lines=$(wc -l < "$f")
     [ "$lines" -gt 150 ] && echo "$f: $lines lines, over the 150-line cap"
   done
   ```

   Over the cap: cut words or split the topic. **Do not raise the cap** — it exists because a written
   "half a page" target didn't hold the old ADRs, which reached 4,270 lines across 14 documents.

   Then check that every test the sign-off register cites still exists:

   ```sh
   bash .github/scripts/check_sign_off_citations.sh .
   ```

   A backticked identifier with an underscore in `docs/decisions/security-sign-offs.md` is a
   test citation, and the check fails when no `tests/**/*.cs` file declares it. A test this
   branch renamed or removed must have its citation repointed at the successor — in the old entry
   too, with a bracketed note — or written without backticks where the old name is only being
   mentioned as superseded.

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
