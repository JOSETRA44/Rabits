using Rabits.Domain.Networking;

namespace Rabits.Application.Abstractions;

/// <summary>Resolves a hardware vendor from a MAC's OUI, offline.</summary>
public interface IOuiVendorLookup
{
    /// <summary>Vendor name for the address's OUI, or null if unknown.</summary>
    string? Lookup(MacAddress mac);

    /// <summary>Number of OUI prefixes loaded (embedded + any external overrides).</summary>
    int EntryCount { get; }
}
