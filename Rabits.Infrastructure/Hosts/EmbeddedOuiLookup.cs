using System.Reflection;
using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;
using Rabits.Domain.Networking;

namespace Rabits.Infrastructure.Hosts;

/// <summary>
/// Offline MAC-vendor resolver. Loads a curated starter set embedded in the assembly, then merges
/// an optional external file (e.g. the full IEEE <c>oui.csv</c> or Wireshark <c>manuf</c>) so
/// coverage can be expanded without a rebuild. Format is tolerant: each line is
/// "&lt;prefix&gt;&lt;sep&gt;&lt;vendor&gt;" where prefix may be AABBCC / AA:BB:CC / AA-BB-CC.
/// </summary>
public sealed class EmbeddedOuiLookup : IOuiVendorLookup
{
    private readonly Dictionary<string, string> _map = new(StringComparer.Ordinal);

    public EmbeddedOuiLookup(string? externalFilePath, ILogger<EmbeddedOuiLookup> logger)
    {
        LoadEmbedded(logger);

        if (!string.IsNullOrWhiteSpace(externalFilePath) && File.Exists(externalFilePath))
        {
            try
            {
                using var reader = new StreamReader(externalFilePath);
                var added = Parse(reader);
                logger.LogInformation("Merged {Count} OUI entries from '{Path}'.", added, externalFilePath);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Could not read external OUI file '{Path}'.", externalFilePath);
            }
        }
    }

    public int EntryCount => _map.Count;

    public string? Lookup(MacAddress mac)
        => _map.TryGetValue(Normalize(mac.Oui), out var vendor) ? vendor : null;

    private void LoadEmbedded(ILogger logger)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("oui.tsv", StringComparison.OrdinalIgnoreCase));

        if (resourceName is null)
        {
            logger.LogWarning("Embedded OUI dataset not found.");
            return;
        }

        using var stream = assembly.GetManifestResourceStream(resourceName)!;
        using var reader = new StreamReader(stream);
        Parse(reader);
    }

    private int Parse(TextReader reader)
    {
        var added = 0;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;

            var separators = new[] { '\t', ',', ';' };
            var splitIndex = trimmed.IndexOfAny(separators);
            string prefixToken, vendor;
            if (splitIndex > 0)
            {
                prefixToken = trimmed[..splitIndex];
                vendor = trimmed[(splitIndex + 1)..].Trim().Trim('"');
            }
            else
            {
                var space = trimmed.IndexOf(' ');
                if (space <= 0) continue;
                prefixToken = trimmed[..space];
                vendor = trimmed[(space + 1)..].Trim();
            }

            var key = Normalize(prefixToken);
            if (key.Length < 6 || vendor.Length == 0) continue;

            key = key[..6];
            if (_map.TryAdd(key, vendor)) added++;
            else _map[key] = vendor; // external file overrides embedded
        }
        return added;
    }

    private static string Normalize(string prefix)
        => prefix.Replace(":", "").Replace("-", "").Replace(".", "").Trim().ToUpperInvariant();
}
