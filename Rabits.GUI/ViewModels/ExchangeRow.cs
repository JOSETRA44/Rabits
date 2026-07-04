using Rabits.Domain.Layer7;

namespace Rabits.GUI.ViewModels;

/// <summary>Display wrapper over a captured <see cref="HttpExchange"/>, adding the in-scope flag.</summary>
public sealed record ExchangeRow(HttpExchange Exchange, bool InScope)
{
    public string Method => Exchange.Method;
    public string Url => Exchange.Url;
    public string Host => Exchange.Host;
    public int StatusCode => Exchange.StatusCode;
    public string Type => Exchange.ResourceType.ToString();
    public long ResponseSize => Exchange.ResponseSize;
    public bool IsApiLike => Exchange.IsApiLike;
    public string Time => Exchange.Timestamp.ToString("HH:mm:ss");
}
