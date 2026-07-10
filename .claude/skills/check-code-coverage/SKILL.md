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

Rather than checking out and rebuilding `main` in a worktree, download the `coverage-Linux` artifact from `main`'s most recent successful CI run (the same one `coverage-regression` itself now uses — see `.github/workflows/ci.yml`). This requires the `gh` CLI to be authenticated:

```sh
gh run download --repo ChrisKlug/zeekayda-auth \
  -n coverage-Linux \
  -D ./TestResults/base \
  $(gh run list --repo ChrisKlug/zeekayda-auth --workflow ci.yml --branch main --event push --status success --limit 1 --json databaseId --jq '.[0].databaseId')
```

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
