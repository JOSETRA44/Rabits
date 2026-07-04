using Rabits.Domain.Layer7;

namespace Rabits.GUI.Layer7;

/// <summary>Receives captured network exchanges and secret findings from the WebView2 bridge.</summary>
public interface IDynamicAnalysisSink
{
    void ReportExchange(HttpExchange exchange);
    void ReportSecret(SecretFinding finding);
}
