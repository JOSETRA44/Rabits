namespace Rabits.Domain.Layer7;

/// <summary>A distinct API endpoint discovered during a dynamic session (method + path, query stripped).</summary>
public sealed record ApiEndpoint(string Method, string Host, string Path)
{
    /// <summary>De-duplication key across observed exchanges.</summary>
    public string Key => $"{Method} {Host}{Path}";

    public override string ToString() => Key;
}
