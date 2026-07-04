using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Rabits.Application.Abstractions;
using Rabits.Application.Auth;
using Rabits.Domain.Auth;
using Rabits.Domain.Engagement;

namespace Rabits.GUI.ViewModels;

/// <summary>
/// View model for the Attacks / Audit view: a scope-gated (Intrusive) dictionary credential audit.
/// The handler is awaited on the UI context and reports each attempt via IProgress, so the results
/// grid updates without manual marshalling; the grid is capped to stay bounded.
/// </summary>
public sealed partial class AttackViewModel : ObservableObject
{
    private const int MaxRows = 500;

    private readonly CredentialAuditHandler _handler;
    private readonly ICredentialWordlist _wordlist;
    private CancellationTokenSource? _cts;

    public AttackViewModel(CredentialAuditHandler handler, ICredentialWordlist wordlist)
    {
        _handler = handler;
        _wordlist = wordlist;
    }

    public ObservableCollection<CredentialAttemptResult> Results { get; } = new();
    public IReadOnlyList<string> Protocols { get; } = new[] { "HTTP Form", "HTTP Basic" };

    [ObservableProperty] private string _url = "https://";
    [ObservableProperty] private string _protocol = "HTTP Form";
    [ObservableProperty] private string _username = "admin";
    [ObservableProperty] private string _userField = "username";
    [ObservableProperty] private string _passwordField = "password";
    [ObservableProperty] private string _wordlistPath = string.Empty;
    [ObservableProperty] private string _successStatus = string.Empty;
    [ObservableProperty] private string _failureContains = string.Empty;
    [ObservableProperty] private int _concurrency = 8;
    [ObservableProperty] private bool _stopOnSuccess = true;

    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _statusMessage =
        "Intrusive audit — target must be in scope with maxClassification \"Intrusive\".";

    [ObservableProperty] private int _attempted;
    [ObservableProperty] private int _failures;
    [ObservableProperty] private int _errors;
    [ObservableProperty] private int _found;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task StartAsync()
    {
        if (!TryNormalizeUrl(Url, out var uri))
        {
            StatusMessage = $"Invalid URL: {Url}";
            return;
        }

        var passwords = File.Exists(WordlistPath)
            ? File.ReadAllLines(WordlistPath).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList()
            : _wordlist.Passwords;

        var target = new AuthTarget
        {
            Protocol = Protocol == "HTTP Basic" ? AuthProtocol.HttpBasic : AuthProtocol.HttpForm,
            Url = uri,
            UserField = UserField,
            PasswordField = PasswordField,
            SuccessStatusCodes = int.TryParse(SuccessStatus, out var code) ? new[] { code } : Array.Empty<int>(),
            FailureBodyContains = string.IsNullOrWhiteSpace(FailureContains) ? null : FailureContains,
        };

        var request = new CredentialAuditRequest
        {
            Target = target,
            Usernames = new[] { Username },
            Passwords = passwords,
            Concurrency = Concurrency,
            StopOnSuccess = StopOnSuccess,
        };

        Results.Clear();
        Attempted = Failures = Errors = Found = 0;
        IsRunning = true;
        StatusMessage = $"Auditing {uri.Host} — up to {passwords.Count} credential(s)…";
        _cts = new CancellationTokenSource();

        var progress = new Progress<CredentialAttemptResult>(OnAttempt);

        try
        {
            var summary = await _handler.HandleAsync(request, progress, _cts.Token);
            StatusMessage = summary.AnySuccess
                ? $"✔ {summary.Successes.Count} valid credential(s) found in {summary.Elapsed.TotalSeconds:0.0}s."
                : $"No valid credentials · {summary.Attempted} attempted, {summary.Errors} error(s).";
        }
        catch (OutOfScopeException ex)
        {
            StatusMessage = $"Refused — out of scope: {ex.Message}";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Stopped.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed: {ex.Message}";
        }
        finally
        {
            IsRunning = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanStop))]
    private void Stop() => _cts?.Cancel();

    private void OnAttempt(CredentialAttemptResult result)
    {
        Attempted++;
        switch (result.Result)
        {
            case AuthResult.Success: Found++; break;
            case AuthResult.Error: Errors++; break;
            default: Failures++; break;
        }

        Results.Insert(0, result);
        while (Results.Count > MaxRows) Results.RemoveAt(Results.Count - 1);
    }

    private bool CanStart() => !IsRunning;
    private bool CanStop() => IsRunning;

    partial void OnIsRunningChanged(bool value)
    {
        StartCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
    }

    private static bool TryNormalizeUrl(string url, out Uri uri)
    {
        var candidate = url.Contains("://", StringComparison.Ordinal) ? url : $"https://{url}";
        return Uri.TryCreate(candidate, UriKind.Absolute, out uri!)
               && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
    }
}
