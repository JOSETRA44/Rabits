using System.Reflection;
using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;

namespace Rabits.Infrastructure.Auth;

/// <summary>
/// Default password wordlist from an embedded set, optionally replaced by an external file
/// (one password per line, '#' comments). External file, when present and non-empty, wins.
/// </summary>
public sealed class EmbeddedPasswordList : ICredentialWordlist
{
    public IReadOnlyList<string> Passwords { get; }

    public EmbeddedPasswordList(string? externalFilePath, ILogger<EmbeddedPasswordList> logger)
    {
        if (!string.IsNullOrWhiteSpace(externalFilePath) && File.Exists(externalFilePath))
        {
            var external = Clean(File.ReadAllLines(externalFilePath));
            if (external.Count > 0)
            {
                Passwords = external;
                logger.LogInformation("Loaded {Count} passwords from '{Path}'.", external.Count, externalFilePath);
                return;
            }
        }

        Passwords = LoadEmbedded(logger);
    }

    private static IReadOnlyList<string> LoadEmbedded(ILogger logger)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var name = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("passwords.txt", StringComparison.OrdinalIgnoreCase));
        if (name is null)
        {
            logger.LogWarning("Embedded password wordlist not found.");
            return Array.Empty<string>();
        }

        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return Clean(reader.ReadToEnd().Split('\n'));
    }

    private static List<string> Clean(IEnumerable<string> lines)
    {
        var passwords = new List<string>();
        var seen = new HashSet<string>();
        foreach (var raw in lines)
        {
            var value = raw.TrimEnd('\r', '\n');
            if (value.Length == 0 || value.StartsWith('#')) continue;
            if (seen.Add(value)) passwords.Add(value);
        }
        return passwords;
    }
}
