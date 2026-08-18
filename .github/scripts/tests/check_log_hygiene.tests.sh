#!/usr/bin/env bash
# Smoke tests for .github/scripts/check_log_hygiene.cs
#
# Builds synthetic single-project fixture repos (a minimal ZeeKayDa.Auth.slnx plus one
# "src/Fixture/Fixture.csproj") and asserts that `dotnet run check_log_hygiene.cs --
# <fixture-dir>` exits 0 when no violation is present (or all are validly justified) and
# exits 1 otherwise.
#
# Unlike its predecessor shell script, the script under test takes the fixture
# repo root as a positional argument rather than an environment-variable search-path
# override, since it discovers projects from the fixture's own ZeeKayDa.Auth.slnx exactly
# as it would the real one.
#
# Invoked from CI and can be run locally:
#   bash .github/scripts/tests/check_log_hygiene.tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CHECKER="${REPO_ROOT}/.github/scripts/check_log_hygiene.cs"

if [[ ! -f "${CHECKER}" ]]; then
    echo "FAIL: cannot find ${CHECKER}" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

# Pass C asserts that ZeeKayDa.Auth.Analyzers.dll is present in the resolved Analyzer
# items, so fixtures that exercise passes A/B (and expect a clean pass overall) need it
# on their own Analyzer item list too — otherwise every fixture would fail on that
# assertion regardless of what it's actually testing. Point at the real, already-built
# DLL rather than adding a ProjectReference, so fixture evaluation doesn't also build the
# analyzer project on every case.
ANALYZER_DLL="${REPO_ROOT}/src/ZeeKayDa.Auth.Analyzers/bin/Debug/netstandard2.0/ZeeKayDa.Auth.Analyzers.dll"
if [[ ! -f "${ANALYZER_DLL}" ]]; then
    dotnet build "${REPO_ROOT}/src/ZeeKayDa.Auth.Analyzers/ZeeKayDa.Auth.Analyzers.csproj" --configuration Debug --nologo -v:quiet
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

write_file() {
    local path="$1"
    mkdir -p "$(dirname "${path}")"
    cat > "${path}"
}

# Every fixture is a single-project repo: ZeeKayDa.Auth.slnx listing exactly one
# "/src/" project at src/Fixture/Fixture.csproj. Individual cases overwrite
# Fixture.csproj, add Directory.Build.props/.targets, .editorconfig, .globalconfig,
# or a ruleset as needed, and write the fixture's .cs source under src/Fixture/.
new_fixture() {
    local dir="$1"
    write_file "${dir}/ZeeKayDa.Auth.slnx" <<'EOF'
<Solution>
  <Folder Name="/src/">
    <Project Path="src/Fixture/Fixture.csproj" />
  </Folder>
</Solution>
EOF
    write_default_csproj "${dir}"
}

write_default_csproj() {
    local dir="$1"
    write_file "${dir}/src/Fixture/Fixture.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <EnableDefaultItems>true</EnableDefaultItems>
  </PropertyGroup>
  <ItemGroup>
    <Analyzer Include="${ANALYZER_DLL}" />
  </ItemGroup>
</Project>
EOF
}

write_source() {
    local dir="$1"
    write_file "${dir}/src/Fixture/Service.cs"
}

run_checker() {
    local fixture_dir="$1"
    (
        cd "${REPO_ROOT}"
        dotnet run "${CHECKER}" -- "${fixture_dir}" >/dev/null 2>&1
    )
}

PASS=0
FAIL=0
record_pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
record_fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1" >&2; }

assert_exit() {
    local name="$1"
    local expected="$2"
    shift 2
    set +e
    "$@"
    local actual=$?
    set -e
    if [[ "${actual}" -eq "${expected}" ]]; then
        record_pass "${name} (exit ${actual})"
    else
        record_fail "${name} (expected ${expected}, got ${actual})"
    fi
}

case_dir() {
    local name="$1"
    local dir="${WORK_DIR}/${name}"
    mkdir -p "${dir}"
    echo "${dir}"
}

# ===========================================================================
# Retained behaviour (ported from the predecessor script's smoke tests)
# ===========================================================================

DIR="$(case_dir case01)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string userId)
    {
        logger.LogInformation("User authenticated successfully for {UserId}", userId);
    }
}
EOF
assert_exit "clean file with no sensitive placeholders passes" 0 run_checker "${DIR}"

DIR="$(case_dir case02)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string token)
    {
        logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok
    }
}
EOF
assert_exit "bare suppression without structured format fails" 1 run_checker "${DIR}"

DIR="$(case_dir case03)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string token)
    {
        logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok: test fixture only (#179)
    }
}
EOF
assert_exit "valid structured suppression with reason and issue ref passes" 0 run_checker "${DIR}"

DIR="$(case_dir case04)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string token)
    {
        logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok: reason without issue ref
    }
}
EOF
assert_exit "suppression missing issue reference fails" 1 run_checker "${DIR}"

DIR="$(case_dir case05)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string token)
    {
        logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok: (#179)
    }
}
EOF
assert_exit "suppression with empty reason fails" 1 run_checker "${DIR}"

DIR="$(case_dir case06)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string token)
    {
        logger.LogInformation("Token: {access_token}", token);
    }
}
EOF
assert_exit "sensitive placeholder with no suppression comment fails" 1 run_checker "${DIR}"

DIR="$(case_dir case07)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string token)
    {
        logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok: test fixture only (#999)
    }
}
EOF
assert_exit "valid structured suppression with alternate issue ref passes" 0 run_checker "${DIR}"

DIR="$(case_dir case08)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string s, string v)
    {
        logger.LogInformation("Secret: {client_secret}", s); // log-hygiene-ok: integration test only (#179)
        logger.LogInformation("Verifier: {code_verifier}", v); // log-hygiene-ok: integration test only (#179)
    }
}
EOF
assert_exit "multiple lines each with valid structured suppressions pass" 0 run_checker "${DIR}"

DIR="$(case_dir case09)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string t, string s)
    {
        logger.LogInformation("Token: {access_token}", t); // log-hygiene-ok: valid (#179)
        logger.LogInformation("Secret: {client_secret}", s); // log-hygiene-ok
    }
}
EOF
assert_exit "mixed file with one bare suppression fails" 1 run_checker "${DIR}"

DIR="$(case_dir case10)"
new_fixture "${DIR}"
assert_exit "project with no cs files passes" 0 run_checker "${DIR}"

DIR="$(case_dir case14)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M()
    {
#pragma warning disable ZEEKAYDA0002 // log-hygiene-ok: composes a constant prefix with another unformatted template (#444)
        System.Console.WriteLine();
#pragma warning restore ZEEKAYDA0002
    }
}
EOF
assert_exit "pragma disable with valid structured suppression passes" 0 run_checker "${DIR}"

DIR="$(case_dir case15)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M()
    {
#pragma warning disable ZEEKAYDA0002
        System.Console.WriteLine();
#pragma warning restore ZEEKAYDA0002
    }
}
EOF
assert_exit "pragma disable without a suppression comment fails" 1 run_checker "${DIR}"

DIR="$(case_dir case16)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "ZEEKAYDA0002")] // log-hygiene-ok: composes a constant prefix with another unformatted template (#444)
    void M() {}
}
EOF
assert_exit "SuppressMessage with valid structured suppression passes" 0 run_checker "${DIR}"

DIR="$(case_dir case17)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "ZEEKAYDA0002")]
    void M() {}
}
EOF
assert_exit "SuppressMessage without a suppression comment fails" 1 run_checker "${DIR}"

# ===========================================================================
# Precision wins (new)
# ===========================================================================

DIR="$(case_dir case_precision01)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    // Mentions access_token here but it's just a comment, not a log template.
    void M(object logger, string userId)
    {
        logger.LogInformation("User {UserId} authenticated", userId);
    }
}
EOF
assert_exit "sensitive name in a comment passes" 0 run_checker "${DIR}"

DIR="$(case_dir case_precision02)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object logger, string userId)
    {
        // Plain text mention, not a {placeholder} — must not be flagged.
        logger.LogInformation("Doing something with access_token here for {UserId}", userId);
    }
}
EOF
assert_exit "sensitive name in a non-template string passes" 0 run_checker "${DIR}"

DIR="$(case_dir case_precision03)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    const string Template = "Token: {access_token}";

    void M(object logger, string token)
    {
        logger.LogInformation(Template, token);
    }
}
EOF
assert_exit "sensitive placeholder in a const string template fails" 1 run_checker "${DIR}"

DIR="$(case_dir case_precision04)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "ZEEKAYDA0002")]
    void M() {}
}
EOF
assert_exit "multi-line SuppressMessage without a suppression comment fails" 1 run_checker "${DIR}"

# ===========================================================================
# Newly-found vectors (must fail; no justification escape hatch)
# ===========================================================================

DIR="$(case_dir case_new01)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M()
    {
#pragma warning disable
        System.Console.WriteLine();
#pragma warning restore
    }
}
EOF
assert_exit "bare pragma warning disable fails" 1 run_checker "${DIR}"

DIR="$(case_dir case_new02)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

class CustomSuppressor : DiagnosticSuppressor
{
}
EOF
assert_exit "DiagnosticSuppressor subclass fails" 1 run_checker "${DIR}"

DIR="$(case_dir case_new03)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
using Microsoft.CodeAnalysis.Diagnostics;

class Descriptors
{
    static readonly SuppressionDescriptor Descriptor =
        new SuppressionDescriptor("SUPP001", "ZEEKAYDA0002", "justification");
}
EOF
assert_exit "SuppressionDescriptor naming a rule ID fails" 1 run_checker "${DIR}"

# ===========================================================================
# Compile-verified bypasses (architect/security review against PR #459)
# ===========================================================================

DIR="$(case_dir bypass_suppressmessage_colon_suffix)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("LogHygiene", "ZEEKAYDA0001:Do not use ILogger directly")]
    void M() {}
}
EOF
assert_exit "SuppressMessage with colon-suffixed checkId fails" 1 run_checker "${DIR}"

DIR="$(case_dir bypass_suppressmessage_named_category)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage(category: "LogHygiene", "ZEEKAYDA0001")]
    void M() {}
}
EOF
assert_exit "SuppressMessage with named category shifting positional checkId fails" 1 run_checker "${DIR}"

DIR="$(case_dir bypass_addwarning_named_code)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    void M(object context, string token)
    {
        context.AddWarning(code: "X", "token {access_token} seen");
    }
}
EOF
assert_exit "AddWarning with named earlier argument shifting the template fails" 1 run_checker "${DIR}"

DIR="$(case_dir bypass_suppressmessage_alias)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
using SM = System.Diagnostics.CodeAnalysis.SuppressMessageAttribute;

class Service
{
    [SM("LogHygiene", "ZEEKAYDA0001")]
    void M() {}
}
EOF
assert_exit "aliased SuppressMessageAttribute fails" 1 run_checker "${DIR}"

DIR="$(case_dir bypass_diagnosticsuppressor_alias)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
using Microsoft.CodeAnalysis;
using DS = Microsoft.CodeAnalysis.Diagnostics.DiagnosticSuppressor;

class CustomSuppressor : DS
{
}
EOF
assert_exit "aliased DiagnosticSuppressor base type fails" 1 run_checker "${DIR}"

# ===========================================================================
# Newly-found vectors (second security re-verification pass): cross-file
# `global using` aliases, and additional SuppressionDescriptor declaration shapes.
# ===========================================================================

DIR="$(case_dir bypass_global_alias_suppressmessage)"
new_fixture "${DIR}"
write_file "${DIR}/src/Fixture/GlobalUsings.cs" <<'EOF'
global using SM = System.Diagnostics.CodeAnalysis.SuppressMessageAttribute;
EOF
write_file "${DIR}/src/Fixture/Service.cs" <<'EOF'
class Service
{
    [SM("LogHygiene", "ZEEKAYDA0001")]
    void M() {}
}
EOF
assert_exit "cross-file global using alias of SuppressMessageAttribute fails" 1 run_checker "${DIR}"

DIR="$(case_dir bypass_global_alias_diagnosticsuppressor)"
new_fixture "${DIR}"
write_file "${DIR}/src/Fixture/GlobalUsings.cs" <<'EOF'
global using DS = Microsoft.CodeAnalysis.Diagnostics.DiagnosticSuppressor;
EOF
write_file "${DIR}/src/Fixture/Service.cs" <<'EOF'
class CustomSuppressor : DS
{
}
EOF
assert_exit "cross-file global using alias of DiagnosticSuppressor fails" 1 run_checker "${DIR}"

DIR="$(case_dir bypass_suppressiondescriptor_arrow_property)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
using Microsoft.CodeAnalysis.Diagnostics;

class Descriptors
{
    static SuppressionDescriptor MyDescriptor => new("SUPP001", "ZEEKAYDA0002", "justification");
}
EOF
assert_exit "arrow-bodied property returning a target-typed SuppressionDescriptor fails" 1 run_checker "${DIR}"

DIR="$(case_dir bypass_suppressiondescriptor_return_statement)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
using Microsoft.CodeAnalysis.Diagnostics;

class Descriptors
{
    static SuppressionDescriptor GetIt()
    {
        return new("SUPP002", "ZEEKAYDA0002", "justification");
    }
}
EOF
assert_exit "return statement of a target-typed SuppressionDescriptor fails" 1 run_checker "${DIR}"

# ===========================================================================
# Newly-found vectors (third security re-verification pass): whitespace/newline
# inside a qualified name defeats string-splitting on the last '.' in ToString().
# ===========================================================================

DIR="$(case_dir bypass_suppressmessage_whitespace_in_qualified_name)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class Service
{
    [System.Diagnostics.CodeAnalysis.
     SuppressMessage("Design", "ZEEKAYDA0002")]
    void M() {}
}
EOF
assert_exit "SuppressMessage with whitespace/newline inside the qualified name fails" 1 run_checker "${DIR}"

DIR="$(case_dir bypass_diagnosticsuppressor_whitespace_in_qualified_name)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
class CustomSuppressor : Microsoft.CodeAnalysis.Diagnostics.
    DiagnosticSuppressor
{
}
EOF
assert_exit "DiagnosticSuppressor base type with whitespace/newline inside the qualified name fails" 1 run_checker "${DIR}"

# ===========================================================================
# Newly-found fix (third security re-verification pass): `return new(...)`
# inside a block-bodied property/indexer accessor.
# ===========================================================================

DIR="$(case_dir bypass_suppressiondescriptor_property_accessor_return)"
new_fixture "${DIR}"
write_source "${DIR}" <<'EOF'
using Microsoft.CodeAnalysis.Diagnostics;

class Descriptors
{
    static SuppressionDescriptor MyDescriptor
    {
        get
        {
            return new("SUPP003", "ZEEKAYDA0002", "justification");
        }
    }
}
EOF
assert_exit "return statement inside a block-bodied property accessor fails" 1 run_checker "${DIR}"

# ===========================================================================
# Pass C — effective severity per project. Each case is its own single-project
# fixture repo since it needs full control over csproj/props/editorconfig content.
# The fixture .cs file is intentionally trivial — pass C never inspects source
# content, only MSBuild-evaluated project state.
# ===========================================================================

write_trivial_source() {
    local dir="$1"
    write_source "${dir}" <<'EOF'
class Fixture {}
EOF
}

# --- The 12 PR #457 vectors -------------------------------------------------

DIR="$(case_dir vector_globalconfig)"
new_fixture "${DIR}"
write_trivial_source "${DIR}"
write_file "${DIR}/src/Fixture/.globalconfig" <<'EOF'
is_global = true
dotnet_diagnostic.ZEEKAYDA0002.severity = none
EOF
assert_exit "vector: .globalconfig override fails" 1 run_checker "${DIR}"

DIR="$(case_dir vector_nowarn_targets)"
new_fixture "${DIR}"
write_trivial_source "${DIR}"
write_file "${DIR}/src/Fixture/Directory.Build.targets" <<'EOF'
<Project>
  <PropertyGroup>
    <NoWarn>$(NoWarn);ZEEKAYDA0001</NoWarn>
  </PropertyGroup>
</Project>
EOF
assert_exit "vector: NoWarn in Directory.Build.targets fails" 1 run_checker "${DIR}"

DIR="$(case_dir vector_category_severity_none)"
new_fixture "${DIR}"
write_trivial_source "${DIR}"
write_file "${DIR}/src/Fixture/.editorconfig" <<'EOF'
root = true
[*.cs]
dotnet_analyzer_diagnostic.category-LogHygiene.severity = none
EOF
assert_exit "vector: category-LogHygiene severity=none fails" 1 run_checker "${DIR}"

DIR="$(case_dir vector_global_severity_none)"
new_fixture "${DIR}"
write_trivial_source "${DIR}"
write_file "${DIR}/src/Fixture/.editorconfig" <<'EOF'
root = true
[*.cs]
dotnet_analyzer_diagnostic.severity = none
EOF
assert_exit "vector: dotnet_analyzer_diagnostic.severity=none fails" 1 run_checker "${DIR}"

DIR="$(case_dir vector_run_analyzers_false)"
write_file "${DIR}/ZeeKayDa.Auth.slnx" <<'EOF'
<Solution>
  <Folder Name="/src/">
    <Project Path="src/Fixture/Fixture.csproj" />
  </Folder>
</Solution>
EOF
write_file "${DIR}/src/Fixture/Fixture.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <RunAnalyzers>false</RunAnalyzers>
  </PropertyGroup>
</Project>
EOF
write_trivial_source "${DIR}"
assert_exit "vector: RunAnalyzers=false fails" 1 run_checker "${DIR}"

DIR="$(case_dir vector_nowarn_multiline)"
write_file "${DIR}/ZeeKayDa.Auth.slnx" <<'EOF'
<Solution>
  <Folder Name="/src/">
    <Project Path="src/Fixture/Fixture.csproj" />
  </Folder>
</Solution>
EOF
write_file "${DIR}/src/Fixture/Fixture.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <NoWarn>
      ZEEKAYDA0001
    </NoWarn>
  </PropertyGroup>
</Project>
EOF
write_trivial_source "${DIR}"
assert_exit "vector: multi-line NoWarn fails" 1 run_checker "${DIR}"

DIR="$(case_dir vector_nowarn_second_entry)"
write_file "${DIR}/ZeeKayDa.Auth.slnx" <<'EOF'
<Solution>
  <Folder Name="/src/">
    <Project Path="src/Fixture/Fixture.csproj" />
  </Folder>
</Solution>
EOF
write_file "${DIR}/src/Fixture/Fixture.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <NoWarn>CS1591;ZEEKAYDA0001</NoWarn>
  </PropertyGroup>
</Project>
EOF
write_trivial_source "${DIR}"
assert_exit "vector: second NoWarn entry after an unrelated one fails" 1 run_checker "${DIR}"

DIR="$(case_dir vector_severity_casing)"
new_fixture "${DIR}"
write_trivial_source "${DIR}"
write_file "${DIR}/src/Fixture/.editorconfig" <<'EOF'
root = true
[*.cs]
dotnet_diagnostic.ZEEKAYDA0002.severity = NoNe
EOF
assert_exit "vector: case-insensitive severity value fails" 1 run_checker "${DIR}"

DIR="$(case_dir vector_nowarn_property_indirection)"
write_file "${DIR}/ZeeKayDa.Auth.slnx" <<'EOF'
<Solution>
  <Folder Name="/src/">
    <Project Path="src/Fixture/Fixture.csproj" />
  </Folder>
</Solution>
EOF
write_file "${DIR}/src/Fixture/Fixture.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <SuppressedRule>ZEEKAYDA0001</SuppressedRule>
    <TargetFramework>net10.0</TargetFramework>
    <NoWarn>$(SuppressedRule)</NoWarn>
  </PropertyGroup>
</Project>
EOF
write_trivial_source "${DIR}"
assert_exit "vector: NoWarn via property indirection fails" 1 run_checker "${DIR}"

DIR="$(case_dir vector_analyzer_removed)"
write_file "${DIR}/ZeeKayDa.Auth.slnx" <<'EOF'
<Solution>
  <Folder Name="/src/">
    <Project Path="src/Fixture/Fixture.csproj" />
  </Folder>
</Solution>
EOF
write_file "${DIR}/src/Fixture/Fixture.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
</Project>
EOF
write_trivial_source "${DIR}"
assert_exit "vector: analyzer reference not present fails" 1 run_checker "${DIR}"

# --- Newly-found vector: ruleset action -------------------------------------

DIR="$(case_dir vector_ruleset_action)"
write_file "${DIR}/ZeeKayDa.Auth.slnx" <<'EOF'
<Solution>
  <Folder Name="/src/">
    <Project Path="src/Fixture/Fixture.csproj" />
  </Folder>
</Solution>
EOF
write_file "${DIR}/src/Fixture/Fixture.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <CodeAnalysisRuleSet>Fixture.ruleset</CodeAnalysisRuleSet>
  </PropertyGroup>
</Project>
EOF
write_file "${DIR}/src/Fixture/Fixture.ruleset" <<'EOF'
<RuleSet Name="Fixture" ToolsVersion="10.0">
  <Rules AnalyzerId="ZeeKayDa.Auth.Analyzers" RuleNamespace="ZeeKayDa.Auth.Analyzers">
    <Rule Id="ZEEKAYDA0002" Action="None" />
  </Rules>
</RuleSet>
EOF
write_trivial_source "${DIR}"
assert_exit "vector: ruleset action downgrades a rule fails" 1 run_checker "${DIR}"

# --- No-hatch cases: project-wide suppression fails even with a comment ----

DIR="$(case_dir no_hatch_nowarn_justified)"
write_file "${DIR}/ZeeKayDa.Auth.slnx" <<'EOF'
<Solution>
  <Folder Name="/src/">
    <Project Path="src/Fixture/Fixture.csproj" />
  </Folder>
</Solution>
EOF
write_file "${DIR}/src/Fixture/Fixture.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <NoWarn>ZEEKAYDA0001</NoWarn> <!-- log-hygiene-ok: generated proxy code, reviewed manually (#454) -->
  </PropertyGroup>
</Project>
EOF
write_trivial_source "${DIR}"
assert_exit "no-hatch: NoWarn with a justification comment still fails" 1 run_checker "${DIR}"

DIR="$(case_dir no_hatch_editorconfig_justified)"
new_fixture "${DIR}"
write_trivial_source "${DIR}"
write_file "${DIR}/src/Fixture/.editorconfig" <<'EOF'
root = true
[*.cs]
; log-hygiene-ok: temporarily relaxed while migrating legacy module (#454)
dotnet_diagnostic.ZEEKAYDA0002.severity = warning
EOF
assert_exit "no-hatch: .editorconfig override with a justification comment still fails" 1 run_checker "${DIR}"

# ===========================================================================
# Summary
# ===========================================================================
echo
echo "Smoke test summary: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
