---
name: check-formatting
description: Verify and fix code formatting with dotnet format. Run before opening any PR, and whenever formatting errors are reported by CI or the Stop hook.
allowed-tools:
  - Bash(git rev-parse *)
  - Bash(dotnet format)
  - Bash(dotnet format *)
---

# Check and Fix Formatting

A Stop hook (`.claude/hooks/scripts/check-format.sh`) enforces formatting at the end of every turn — this skill is the fix-it procedure.

## Steps

1. From the repo root (`git rev-parse --show-toplevel`), run:

   ```sh
   dotnet format ZeeKayDa.Auth.slnx --verify-no-changes
   ```

   The explicit `ZeeKayDa.Auth.slnx` path is required: the repo also carries per-OS solution
   filters (`ZeeKayDa.Auth.{Windows,MacOS,Linux}.slnf`) that `dotnet format`'s auto-discovery
   treats as candidate solution files, so a bare `dotnet format` errors with "Multiple MSBuild
   solution files found" instead of running.

2. If it exits non-zero, run `dotnet format ZeeKayDa.Auth.slnx` to fix the issues, then re-run the verify step.

3. Repeat until `--verify-no-changes` exits 0.
