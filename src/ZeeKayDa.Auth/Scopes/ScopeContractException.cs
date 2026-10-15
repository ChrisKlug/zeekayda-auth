namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// The failure <see cref="ValidatedScopeCatalog"/> raises for a broken <see cref="IScopeRepository"/>; every
/// message is the framework's own.
/// </summary>
/// <remarks>
/// Internal, so catching it separates the catalog's own failures, safe to log, from anything a repository
/// threw, which may carry a connection string and is reported by type only.
/// </remarks>
internal sealed class ScopeContractException : ZeeKayDaConfigurationException
{
    public ScopeContractException(params ZeeKayDaConfigurationFailure[] failures)
        : base(failures)
    {
    }

    /// <summary>Every failure's code and message, safe to log because each is the framework's own text.</summary>
    public string DescribeFailures() =>
        string.Join("; ", AggregatedFailures.Select(failure => $"[{failure.Code}] {failure.Message}"));
}
