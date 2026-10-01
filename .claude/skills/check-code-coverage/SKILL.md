---
name: check-code-coverage
description: Compare test coverage on the current branch against main and fail if it regressed. Run before opening any PR — CI enforces a coverage regression gate, and this catches it locally first.
allowed-tools:
  - Bash(dotnet *)
  - Bash(git worktree *)
  - Bash(cd *)
---

# Run code coverage check

To verify that code coverage hasn't dropped too far, do the following

---


## Steps

### 1. Measure current coverage

Measuring the coverage in the current branch can be done by running:

```sh
dotnet restore
dotnet build --no-restore --configuration Release
dotnet test tests/ZeeKayDa.Auth.Tests/ \
  --no-build --configuration Release \
  --collect:"XPlat Code Coverage" --results-directory ./TestResults/pr \
  -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Include="[ZeeKayDa.Auth]*"
dotnet test tests/ZeeKayDa.Auth.AspNetCore.Tests/ \
  --no-build --configuration Release \
  --collect:"XPlat Code Coverage" --results-directory ./TestResults/pr \
  -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Include="[ZeeKayDa.Auth.AspNetCore]*"
dotnet test tests/ZeeKayDa.Auth.AzureKeyVault.Tests/ \
  --no-build --configuration Release \
  --collect:"XPlat Code Coverage" --results-directory ./TestResults/pr \
  -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Include="[ZeeKayDa.Auth.AzureKeyVault]*"
dotnet test tests/ZeeKayDa.Auth.FileSystem.Tests/ \
  --no-build --configuration Release \
  --collect:"XPlat Code Coverage" --results-directory ./TestResults/pr \
  -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Include="[ZeeKayDa.Auth.FileSystem]*"
```

### 2. Get main's coverage

Rather than checking out and rebuilding `main` in a worktree, download the `coverage-Linux` artifact from `main`'s most recent CI run **that produced one** (the same artifact `coverage-regression` itself uses — see `.github/workflows/ci.yml`). This requires the `gh` CLI to be authenticated.

**Not simply the most recent run, and not `gh run list`.** `detect-changes` skips the coverage jobs
on a docs-only push, so a green run can have no artifact, and docs-only merges landing ahead of code
is normal here. And `gh run list` has returned a page missing the newest runs, so a loop over it once
silently took a two-week-old artifact and reported a branch-coverage regression that did not exist.
So walk `main`'s own commits from git, newest first, and take the first one whose CI push run has the
artifact:

```sh
git fetch -q origin main
for sha in $(git rev-list --max-count=30 origin/main); do
  id=$(gh api "repos/ChrisKlug/zeekayda-auth/actions/runs?head_sha=$sha&event=push"     --jq '[.workflow_runs[] | select(.path == ".github/workflows/ci.yml" and .conclusion == "success")][0].id // empty')
  [ -n "$id" ] || continue
  if gh api repos/ChrisKlug/zeekayda-auth/actions/runs/$id/artifacts --jq '[.artifacts[].name] | join(",")' | grep -q coverage-Linux; then
    gh run download --repo ChrisKlug/zeekayda-auth -n coverage-Linux -D ./TestResults/base "$id"
    echo "baseline: run $id, commit ${sha:0:8}, $(git rev-list --count "$sha"..origin/main) newer commit(s) on main without coverage"
    break
  fi
done
```

The commits it skips are ones whose CI produced no coverage — docs-only, or a run still in progress
or failed. A docs-only skip cannot move coverage; if the skipped commits include code, wait for that
run to finish rather than compare against an older one. Regressions in files your branch never
touched mean the baseline is not the `main` you branched from: stop and find out why. If nothing is
found in 30 commits, the artifacts have aged out — fall back to building `main` in a worktree.

Never adjust a threshold or accept a regression to make a stale comparison pass.

### 3. Compare the results

To compare the results, you can run the `check_coverage_regression.cs` file like this

```sh
dotnet run .github/scripts/check_coverage_regression.cs -- ./TestResults/pr ./TestResults/base
```

To see if there are any formatting issues

### 4. Check the output

If the execution returns a 0 exit code, coverage is good enough. If it returns a non-0 result, it is not.

If the coverage is not good enough, the output from the execution will contain the result of the check. This should be possible to use to figure out what tests are missing.

### 5. Clean up

Once the check has been performed, remove the downloaded artifact:

```sh
rm -rf ./TestResults
```
