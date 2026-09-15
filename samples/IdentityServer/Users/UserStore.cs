using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Users;

/// <summary>A user the sample knows: a subject, a login name, a password hash and their claims.</summary>
public sealed record SampleUser(string Subject, string Username, byte[] Salt, byte[] PasswordHash, IReadOnlyList<ClaimRecord> Claims);

/// <summary>
/// The sample's user store: in memory, seeded at startup, so every run begins from the same state.
/// The framework never reads it — the login page checks passwords against it, and the claims
/// provider reads claims from it.
/// </summary>
public sealed class UserStore
{
    private const int Iterations = 100_000;

    private readonly ConcurrentDictionary<string, SampleUser> _byUsername = new(StringComparer.OrdinalIgnoreCase);
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
        var salt = RandomNumberGenerator.GetBytes(16);
        var user = new SampleUser(subject, username, salt, Hash(password, salt), claims);

        if (!_byUsername.TryAdd(username, user))
            return false;

        _bySubject[user.Subject] = user;
        return true;
    }

    /// <summary>The user whose password matches, or <see langword="null"/>.</summary>
    public SampleUser? Validate(string username, string password) =>
        _byUsername.TryGetValue(username, out var user)
        && CryptographicOperations.FixedTimeEquals(Hash(password, user.Salt), user.PasswordHash)
            ? user
            : null;

    public SampleUser? FindBySubject(string subject) =>
        _bySubject.TryGetValue(subject, out var user) ? user : null;

    private static byte[] Hash(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, 32);
}
