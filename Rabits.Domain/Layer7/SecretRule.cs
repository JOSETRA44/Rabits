using System.Text.RegularExpressions;
using Rabits.Domain.Recon;

namespace Rabits.Domain.Layer7;

/// <summary>A named detector: a compiled regex plus how to categorize and rank its matches.</summary>
public sealed record SecretRule(string Name, string Category, SecurityFindingSeverity Severity, Regex Pattern);
