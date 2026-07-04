using Rabits.Domain.Layer7;

namespace Rabits.Tests.Domain;

public class HttpExchangeTests
{
    private static HttpExchange Make(ResourceType type, string mime, string path) => new()
    {
        Method = "GET", Url = $"https://x.test{path}", Host = "x.test", Path = path, ResourceType = type, MimeType = mime,
    };

    [Theory]
    [InlineData(ResourceType.Xhr, "text/html", "/foo", true)]
    [InlineData(ResourceType.Fetch, "text/plain", "/bar", true)]
    [InlineData(ResourceType.Script, "application/json", "/x", true)]     // json mime
    [InlineData(ResourceType.Document, "text/html", "/api/users", true)]  // api path
    [InlineData(ResourceType.Script, "application/javascript", "/static/app.js", false)]
    [InlineData(ResourceType.Image, "image/png", "/logo.png", false)]
    public void IsApiLike_classifies_correctly(ResourceType type, string mime, string path, bool expected)
        => Assert.Equal(expected, Make(type, mime, path).IsApiLike);
}
