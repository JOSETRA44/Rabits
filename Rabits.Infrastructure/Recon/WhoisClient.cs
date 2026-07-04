using System.Globalization;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using Rabits.Application.Abstractions;
using Rabits.Domain.Recon;

namespace Rabits.Infrastructure.Recon;

/// <summary>
/// WHOIS client over TCP/43. Resolves the authoritative server via IANA referral, then follows the
/// registrar referral once for richer data, and heuristically extracts common fields.
/// </summary>
public sealed class WhoisClient : IWhoisClient
{
    private const string IanaWhois = "whois.iana.org";
    private readonly int _timeoutMs;
    private readonly ILogger<WhoisClient> _logger;

    public WhoisClient(ILogger<WhoisClient> logger, int timeoutMs = 8000)
    {
        _logger = logger;
        _timeoutMs = timeoutMs;
    }

    public async Task<WhoisResult> LookupAsync(string domain, CancellationToken cancellationToken = default)
    {
        var target = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var tld = target.Contains('.') ? target[(target.LastIndexOf('.') + 1)..] : target;

        var referral = await QueryAsync(IanaWhois, tld, cancellationToken);
        var tldServer = ExtractField(referral, "whois:") ?? "whois.verisign-grs.com";

        var raw = await QueryAsync(tldServer, target, cancellationToken);
        var usedServer = tldServer;

        // Follow the registrar's WHOIS server once for fuller records.
        var registrarServer = ExtractField(raw, "Registrar WHOIS Server:");
        if (!string.IsNullOrWhiteSpace(registrarServer) &&
            !registrarServer.Equals(tldServer, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var registrarRaw = await QueryAsync(registrarServer, target, cancellationToken);
                if (registrarRaw.Length > raw.Length)
                {
                    raw = registrarRaw;
                    usedServer = registrarServer;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Registrar WHOIS referral to {Server} failed.", registrarServer);
            }
        }

        return new WhoisResult
        {
            Query = target,
            Server = usedServer,
            Raw = raw,
            Registrar = ExtractField(raw, "Registrar:"),
            CreatedOn = ParseDate(ExtractField(raw, "Creation Date:") ?? ExtractField(raw, "created:")),
            ExpiresOn = ParseDate(ExtractField(raw, "Registry Expiry Date:")
                                  ?? ExtractField(raw, "Expiry Date:") ?? ExtractField(raw, "paid-till:")),
            NameServers = ExtractAll(raw, "Name Server:"),
        };
    }

    private async Task<string> QueryAsync(string server, string query, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_timeoutMs);

        await client.ConnectAsync(server, 43, timeoutCts.Token);
        await using var stream = client.GetStream();

        var request = Encoding.ASCII.GetBytes(query + "\r\n");
        await stream.WriteAsync(request, timeoutCts.Token);

        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync(timeoutCts.Token);
    }

    private static string? ExtractField(string text, string label)
    {
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith(label, StringComparison.OrdinalIgnoreCase))
            {
                var value = trimmed[label.Length..].Trim();
                if (value.Length > 0) return value;
            }
        }
        return null;
    }

    private static IReadOnlyList<string> ExtractAll(string text, string label)
    {
        var values = new List<string>();
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith(label, StringComparison.OrdinalIgnoreCase))
            {
                var value = trimmed[label.Length..].Trim().ToLowerInvariant();
                if (value.Length > 0 && !values.Contains(value)) values.Add(value);
            }
        }
        return values;
    }

    private static DateTimeOffset? ParseDate(string? value)
        => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date)
            ? date
            : null;
}
