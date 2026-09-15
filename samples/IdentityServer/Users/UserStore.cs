using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Users;

/// <summary>A user the sample knows: a subject, a login name and their claims. No password material.</summary>
public sealed record SampleUser(string Subject, string Username, IReadOnlyList<ClaimRecord> Claims);

/// <summary>
/// The sample's user store: in memory, seeded at startup, so every run begins from the same state.
/// The framework never reads it — the login page checks passwords against it, and the claims
/// provider reads claims from it.
/// </summary>
public sealed class UserStore
{
    // The same work factor the framework requires for client secrets (Pbkdf2ClientSecretHasherOptions).
    private const int Iterations = 600_000;

    // Hashed against when the username is unknown, so a miss costs as much as a wrong password and
    // the response time does not reveal which usernames exist.
    private static readonly byte[] UnknownUserSalt = RandomNumberGenerator.GetBytes(16);

    // The password material never leaves the store; callers only ever see the SampleUser.
    private sealed record Account(SampleUser User, byte[] Salt, byte[] PasswordHash);

    private readonly ConcurrentDictionary<string, Account> _byUsername = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, SampleUser> _bySubject = new(StringComparer.Ordinal);

    public UserStore()
    {
        // A fixed subject, so alice is the same user on every run.
        Add("alice", "alice-password", subject: "a1ice000000000000000000000000001",
        [
            new("name", "Alice Example"),
            new("given_name", "Alice"),
            new("family_name", "Example"),
            new("preferred_username", "alice"),
            new("email", "alice@example.com"),
            new("email_verified", true),
            new("phone_number", "+1 555 0100"),
            new("phone_number_verified", true),
            new("address", new AddressClaim
            {
                StreetAddress = "1 Example Street",
                Locality = "Exampleton",
                PostalCode = "12345",
                Country = "SE",
            }),
        ]);
    }

    /// <summary>Adds a user, or returns <see langword="false"/> when the username is taken.</summary>
    public bool Add(string username, string password, IReadOnlyList<ClaimRecord> claims) =>
        Add(username, password, Guid.NewGuid().ToString("N"), claims);

    private bool Add(string username, string password, string subject, IReadOnlyList<ClaimRecord> claims)
    {
        // A copy the store owns, so a caller changing its list afterwards changes nothing here.
        var user = new SampleUser(subject, username, Array.AsReadOnly(claims.ToArray()));
        var salt = RandomNumberGenerator.GetBytes(16);

        if (!_byUsername.TryAdd(username, new Account(user, salt, Hash(password, salt))))
            return false;

        _bySubject[subject] = user;
        return true;
    }

    /// <summary>The user whose password matches, or <see langword="null"/>.</summary>
    public SampleUser? Validate(string username, string password)
    {
        if (!_byUsername.TryGetValue(username, out var account))
        {
            _ = Hash(password, UnknownUserSalt);
            return null;
        }

        return CryptographicOperations.FixedTimeEquals(Hash(password, account.Salt), account.PasswordHash)
            ? account.User
            : null;
    }

    public SampleUser? FindBySubject(string subject) =>
        _bySubject.TryGetValue(subject, out var user) ? user : null;

    private static byte[] Hash(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, 32);
}
