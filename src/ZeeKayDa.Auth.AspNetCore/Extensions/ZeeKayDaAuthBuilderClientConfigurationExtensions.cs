using Microsoft.Extensions.Configuration;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering in-memory clients from configuration.
/// </summary>
public static class ZeeKayDaAuthBuilderClientConfigurationExtensions
{
    private const string Confidential = "Confidential";
    private const string Public = "Public";

    /// <summary>
    /// Registers an in-memory client repository populated from a configuration section.
    /// </summary>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="section">
    /// A section with a <c>Confidential</c> and a <c>Public</c> child, each keyed by client id. Every
    /// client's keys are bound to <see cref="ConfidentialClientOptions"/> or
    /// <see cref="PublicClientOptions"/>.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="builder"/> or <paramref name="section"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The section does not exist, has a child other than <c>Confidential</c> or <c>Public</c>, or a
    /// client has a key its options type does not have. A misspelt section or key would otherwise be
    /// ignored and leave the server without the client, or the client on a default.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Keyed by client id, a client's secret has a stable path for user secrets or any other
    /// configuration source, for example <c>Clients:Confidential:web-app:Secret</c>:
    /// </para>
    /// <code>
    /// "Clients": {
    ///   "Confidential": {
    ///     "web-app": { "SecretHash": "$2b$12$...", "RedirectUris": [ "https://app.example/signin-oidc" ], "AllowedScopes": [ "openid" ] }
    ///   },
    ///   "Public": {
    ///     "spa": { "RedirectUris": [ "https://spa.example/callback" ], "AllowedScopes": [ "openid" ] }
    ///   }
    /// }
    /// </code>
    /// <para>
    /// The section is read once, when this method is called. Calls are additive with every other
    /// <c>AddInMemoryClients</c> call.
    /// </para>
    /// </remarks>
    public static TBuilder AddInMemoryClients<TBuilder>(this TBuilder builder, IConfiguration section)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(section);

        if (!section.GetChildren().Any())
        {
            throw new InvalidOperationException(
                $"The clients section is missing or empty. It needs a '{Confidential}' or a '{Public}' child, " +
                "each keyed by client id.");
        }

        var unknown = section.GetChildren().FirstOrDefault(child =>
            !string.Equals(child.Key, Confidential, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(child.Key, Public, StringComparison.OrdinalIgnoreCase));
        if (unknown is not null)
        {
            throw new InvalidOperationException(
                $"The clients section has a child '{unknown.Key}'. Only '{Confidential}' and '{Public}' are allowed, " +
                "each keyed by client id.");
        }

        return builder.AddInMemoryClients(clients =>
        {
            foreach (var client in section.GetSection(Confidential).GetChildren())
                clients.AddConfidential(client.Key, options => Bind(client, options));

            foreach (var client in section.GetSection(Public).GetChildren())
                clients.AddPublic(client.Key, options => Bind(client, options));
        });
    }

    private static void Bind(IConfiguration client, ClientOptions options) =>
        client.Bind(options, binder => binder.ErrorOnUnknownConfiguration = true);
}
