using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The outcome of redeeming an authorization code: one of four closed cases, each of which a caller must
/// handle, since collapsing them under- or over-revokes.
/// </summary>
internal abstract class AuthorizationCodeRedemptionResult
{
    [ExcludeFromCodeCoverage]
    private AuthorizationCodeRedemptionResult() { }

    /// <summary>Redeemed by its own client; a tombstone now makes a replay <see cref="AlreadyRedeemed"/>.</summary>
    public sealed class Redeemed : AuthorizationCodeRedemptionResult
    {
        /// <summary>The entry stored at issuance, already consumed.</summary>
        public required AuthorizationCodeEntry Entry { get; init; }
    }

    /// <summary>
    /// Bound to another client, and left unconsumed for it; answered <c>invalid_grant</c>, and worth logging
    /// as a possible code injection.
    /// </summary>
    public sealed class ClientMismatch : AuthorizationCodeRedemptionResult { }

    /// <summary>
    /// Already redeemed, a possible replay: revoke <see cref="FamilyId"/>'s family and answer
    /// <c>invalid_grant</c> (RFC 9700 §2.1.1).
    /// </summary>
    public sealed class AlreadyRedeemed : AuthorizationCodeRedemptionResult
    {
        /// <summary>The family committed into the tombstone, in plaintext so a Data Protection key rotation cannot lose it.</summary>
        public required string FamilyId { get; init; }
    }

    /// <summary>Never issued, expired, or malformed; answered <c>invalid_grant</c>, with nothing changed.</summary>
    public sealed class NotFound : AuthorizationCodeRedemptionResult { }
}
