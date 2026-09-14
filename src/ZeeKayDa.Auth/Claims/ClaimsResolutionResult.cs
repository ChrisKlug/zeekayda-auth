namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// What an <see cref="IClaimsProvider"/> answers: the subject's claims, or that the subject must
/// not receive tokens. The hierarchy is closed, so a consumer handles exactly these two cases.
/// </summary>
/// <remarks>
/// "No claims apply to this grant" is <see cref="Resolved"/> with an empty list, and it is a
/// legitimate answer. <see cref="SubjectInvalid"/> is a distinct type rather than a
/// <see langword="null"/> or empty list, so a provider cannot abort issuance by returning the
/// wrong shape of "nothing" by mistake.
/// </remarks>
public abstract class ClaimsResolutionResult
{
    private ClaimsResolutionResult()
    {
    }

    /// <summary>The subject exists and these are its claims, possibly none.</summary>
    public sealed class Resolved : ClaimsResolutionResult
    {
        private readonly IReadOnlyList<ClaimRecord> _claims = [];

        /// <summary>
        /// The claims, one record per value. Repeated records for one type become one JSON
        /// array when every value is a string, or every value is a number.
        /// </summary>
        /// <exception cref="ArgumentNullException">Set to <see langword="null"/>.</exception>
        public required IReadOnlyList<ClaimRecord> Claims
        {
            get => _claims;
            init => _claims = value ?? throw new ArgumentNullException(nameof(value));
        }
    }

    /// <summary>
    /// The subject must not receive tokens: unknown, disabled, or otherwise not to be served.
    /// The token endpoint answers <c>invalid_grant</c> and issues nothing.
    /// </summary>
    public sealed class SubjectInvalid : ClaimsResolutionResult
    {
    }
}
