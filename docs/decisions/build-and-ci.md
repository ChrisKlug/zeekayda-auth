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

## Tried, didn't work
