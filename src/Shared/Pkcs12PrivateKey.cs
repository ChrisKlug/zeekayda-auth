using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace ZeeKayDa.Auth;

/// <summary>
/// Imports a PKCS#12 key bag into an in-memory <see cref="RSA"/> or <see cref="ECDsa"/>, never
/// through an OS-backed certificate, so the private key is not written to a key store on disk.
/// </summary>
internal static class Pkcs12PrivateKey
{
    /// <summary>
    /// Imports <paramref name="keyBag"/>, decrypting it under <paramref name="password"/> if it is
    /// shrouded. Returns <see langword="null"/> when it imports as neither an RSA nor an EC key —
    /// including a shrouded bag <paramref name="password"/> does not decrypt.
    /// </summary>
    public static AsymmetricAlgorithm? Import(Pkcs12SafeBag keyBag, ReadOnlySpan<char> password) =>
        Import(keyBag, password, RSA.Create, ECDsa.Create);

    /// <inheritdoc cref="Import(Pkcs12SafeBag, ReadOnlySpan{char})"/>
    /// <param name="keyBag">A <see cref="Pkcs12KeyBag"/> or <see cref="Pkcs12ShroudedKeyBag"/>.</param>
    /// <param name="password">The password the key bag is shrouded under; ignored for a plain key bag.</param>
    /// <param name="createRsa">Creates the RSA instance the key is imported into.</param>
    /// <param name="createEcdsa">Creates the ECDsa instance the key is imported into, when it is not RSA.</param>
    public static AsymmetricAlgorithm? Import(
        Pkcs12SafeBag keyBag, ReadOnlySpan<char> password, Func<RSA> createRsa, Func<ECDsa> createEcdsa) =>
        TryImport(createRsa(), keyBag, password) ?? TryImport(createEcdsa(), keyBag, password);

    private static AsymmetricAlgorithm? TryImport(AsymmetricAlgorithm key, Pkcs12SafeBag keyBag, ReadOnlySpan<char> password)
    {
        try
        {
            switch (keyBag)
            {
                case Pkcs12KeyBag plain:
                    key.ImportPkcs8PrivateKey(plain.Pkcs8PrivateKey.Span, out _);
                    break;
                case Pkcs12ShroudedKeyBag shrouded:
                    key.ImportEncryptedPkcs8PrivateKey(password, shrouded.EncryptedPkcs8PrivateKey.Span, out _);
                    break;
                default:
                    throw new ArgumentException($"'{keyBag.GetType().Name}' is not a PKCS#12 key bag.", nameof(keyBag));
            }

            return key;
        }
        catch (CryptographicException)
        {
            key.Dispose();
            return null;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }
}
