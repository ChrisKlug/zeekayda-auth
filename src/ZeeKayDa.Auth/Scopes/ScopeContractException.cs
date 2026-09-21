namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// The failure <see cref="ValidatedScopeCatalog"/> raises when a repository breaks the contract on
/// <see cref="IScopeRepository.GetScopesAsync"/>. Every message it carries is this framework's own.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Internal so that only the catalog can raise it, which is the whole point.</strong>
/// <see cref="ZeeKayDaConfigurationException"/> is public, so a custom
/// <see cref="IScopeRepository"/> is free to throw one itself — wrapping a database or
/// configuration failure, with that layer's raw text in the message. Consumers surface a contract
/// breach by naming the failing rule, which means writing the message to the operator's log; doing
/// that to a repository-thrown exception would launder a connection string or a signed URI through
/// a log line, and the sanitizing logger cannot redact text it has no pattern for.
/// </para>
/// <para>
/// Catching this type instead draws the line by provenance rather than by shape: the catalog's own
/// failures are named and logged, while anything the repository threw — this exception's public
/// base class included — travels on untouched to the generic server-error path, where it is
/// reported by type and never by message.
/// </para>
/// <para>
/// It derives from <see cref="ZeeKayDaConfigurationException"/> because that is what it is: a
/// misconfiguration, carrying <see cref="ZeeKayDaConfigurationException.AggregatedFailures"/> a
/// host can read. Only the narrower catch is the guarantee.
/// </para>
/// </remarks>
internal sealed class ScopeContractException : ZeeKayDaConfigurationException
{
    public ScopeContractException(params ZeeKayDaConfigurationFailure[] failures)
        : base(failures)
    {
    }
}
