using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What an <see cref="ITokenIssuer"/> is told about the issuance it is performing: the client the
/// token is for, and the kind of token being issued.
/// </summary>
/// <param name="Client">
/// The client the token is issued for. Carried as <see cref="IClientMetadata"/>, not the full
/// registration, so the issuance path never holds the client's credentials. An issuer can vary
/// what it issues per client — dispatch by client, or enforce
/// <see cref="IClientMetadata.AllowedSigningAlgorithms"/> — without a repository lookup.
/// </param>
/// <param name="Kind">The kind of token being issued.</param>
/// <remarks>
/// The framework constructs the context at the call site, so widening it later — a tenant, say,
/// if multi-tenancy is ever decided — is an additive change, not a breaking one. That is why it
/// deliberately carries no tenant field today.
/// </remarks>
public readonly record struct TokenIssuanceContext(IClientMetadata Client, TokenKind Kind);
