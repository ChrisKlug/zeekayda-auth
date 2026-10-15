using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Stores;

/// <summary>The outcome of consuming a refresh token: one of five closed cases.</summary>
internal abstract class RefreshTokenConsumptionResult
{
    [ExcludeFromCodeCoverage]
    private RefreshTokenConsumptionResult() { }

    /// <summary>Valid and atomically consumed; the entry seeds the rotated token.</summary>
    public sealed class Consumed : RefreshTokenConsumptionResult
    {
        /// <summary>Gets the refresh token entry that was consumed.</summary>
        public required RefreshTokenEntry Entry { get; init; }
    }

    /// <summary>
    /// Bound to another client: rejected with <c>invalid_grant</c>, neither consumed nor revoking, so a stolen
    /// handle alone cannot revoke the user's session.
    /// </summary>
    public sealed class ClientMismatch : RefreshTokenConsumptionResult { }

    /// <summary>Already consumed, so reused: the caller revokes <see cref="FamilyId"/>'s family.</summary>
    public sealed class AlreadyConsumed : RefreshTokenConsumptionResult
    {
        /// <summary>Gets the family identifier of the replayed token chain.</summary>
        public required string FamilyId { get; init; }
    }

    /// <summary>Its family is already revoked; revoking again is safe but unnecessary.</summary>
    public sealed class Revoked : RefreshTokenConsumptionResult
    {
        /// <summary>Gets the family identifier that was revoked.</summary>
        public required string FamilyId { get; init; }
    }

    /// <summary>No token matches the handle; rejected.</summary>
    public sealed class NotFound : RefreshTokenConsumptionResult { }
}
