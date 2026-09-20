# Build and CI

## Decisions in force

**One canonical solution; platform packages get thin solution filters.** `ZeeKayDa.Auth.slnx` is
the single solution — build, test, and format against it locally unless there is a specific reason
to scope down. `ZeeKayDa.Auth.Windows.slnf`, `.MacOS.slnf`, and `.Linux.slnf` are solution
*filters* (no duplicated project metadata) that CI uses so each platform-specific package builds
and tests only on its own OS's runner. A filter may exist without a platform package: the macOS
filter runs the OS-agnostic packages' tests on a real macOS runner even though no macOS-specific
package ships.

**An OS-specific TFM is verified empirically before it lands in a `.csproj` or a decision entry.**
The Windows precedent does not generalize: `net10.0-windows` needs no `dotnet workload install`
(its reference assemblies ship via plain NuGet), but `net10.0-macos` requires a workload — and CI
installs none. Check `dotnet workload list` and restore a throwaway project with the candidate TFM
first.

**Coverage collection is opt-in, never automatic.** The four test projects with a
`coverage.runsettings` reference it through a `RunSettingsFilePath` gated on
`Condition="'$(EnableCoverage)' == 'true'"`. A `DataCollector` entry in runsettings enables coverlet
on its own, so an unconditional reference instruments the output assemblies on *every* `dotnet test`
— roughly a third of wall time, and two concurrent runs of the same project overwrite each other's
instrumented DLLs and fail with `BadImageFormatException`. Anything that wants coverage asks for it
explicitly: CI's `build-and-test` job passes `-p:EnableCoverage=true`, while `coverage-regression`
and the `check-code-coverage` skill pass `--collect` and the `Include` filter on the command line
and need no MSBuild property at all.

**Conformance runs on every PR, and the expected-results manifests are the gate.** The OpenID
Foundation suite's config and basic plans both run in CI's `conformance` job and block the merge —
about two minutes warm, cheap enough that a broken login flow is caught by the PR that broke it
rather than by the next night's run. What passes is `conformance/expected/*.json`: the runner fails
on anything they do not account for *and* on an entry that never occurred, so a regression is loud
and a newly-passing module is ratcheted in by deleting its entry. Every entry names the issue that
removes it or the register decision that makes it permanent.

## Tried, didn't work
