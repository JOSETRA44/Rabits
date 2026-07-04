using System.Reflection;
using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;

namespace Rabits.Infrastructure.Recon;

/// <summary>
/// Subdomain candidate labels from an embedded wordlist, optionally replaced by an external file
/// (one label per line, '#' comments). External file, when present and non-empty, takes precedence.
/// </summary>
public sealed class EmbeddedSubdomainWordlist : ISubdomainWordlist
{
    public IReadOnlyList<string> Labels { get; }

    public EmbeddedSubdomainWordlist(string? externalFilePath, ILogger<EmbeddedSubdomainWordlist> logger)
    {
        if (!string.IsNullOrWhiteSpace(externalFilePath) && File.Exists(externalFilePath))
        {
            var external = Clean(File.ReadAllLines(externalFilePath));
            if (external.Count > 0)
            {
                Labels = external;
                logger.LogInformation("Loaded {Count} subdomain labels from '{Path}'.", external.Count, externalFilePath);
                return;
            }
        }

        Labels = LoadEmbedded(logger);
    }

    private static IReadOnlyList<string> LoadEmbedded(ILogger logger)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var name = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("subdomains.txt", StringComparison.OrdinalIgnoreCase));
        if (name is null)
        {
            logger.LogWarning("Embedded subdomain wordlist not found.");
            return Array.Empty<string>();
        }

        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        var lines = reader.ReadToEnd().Split('\n');
        return Clean(lines);
    }

    private static List<string> Clean(IEnumerable<string> lines)
    {
        var labels = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in lines)
        {
            var label = raw.Trim();
            if (label.Length == 0 || label.StartsWith('#')) continue;
            if (seen.Add(label)) labels.Add(label);
        }
        return labels;
    }
}
