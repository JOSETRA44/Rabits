using System.Text.Json;
using Rabits.Mcp;

namespace Rabits.Tests.Mcp;

public class RabitsToolsetTests
{
    private static readonly IReadOnlyList<ToolDefinition> Tools = RabitsToolset.Build();

    [Theory]
    [InlineData("wifi_scan")]
    [InlineData("hosts_discover")]
    [InlineData("web_dns")]
    [InlineData("web_whois")]
    [InlineData("web_subdomains")]
    [InlineData("web_headers")]
    [InlineData("web_secrets")]
    [InlineData("credential_audit")]
    [InlineData("engagement_scope")]
    [InlineData("audit_trail")]
    public void Exposes_the_expected_tool(string name)
        => Assert.Contains(Tools, t => t.Name == name);

    [Fact]
    public void Every_tool_has_a_description_schema_and_handler()
    {
        Assert.All(Tools, t =>
        {
            Assert.False(string.IsNullOrWhiteSpace(t.Description));
            Assert.NotNull(t.InputSchema);
            Assert.NotNull(t.Invoke);
        });
    }

    [Theory]
    [InlineData("hosts_discover", "target")]
    [InlineData("web_dns", "domain")]
    [InlineData("credential_audit", "url")]
    public void Gated_tools_declare_required_arguments(string tool, string requiredArg)
    {
        var schema = JsonSerializer.SerializeToElement(Tools.Single(t => t.Name == tool).InputSchema);
        var required = schema.GetProperty("required").EnumerateArray().Select(e => e.GetString());
        Assert.Contains(requiredArg, required);
    }
}
