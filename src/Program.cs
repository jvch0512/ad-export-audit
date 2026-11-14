using AdExportAudit;

const string usage = "usage: ad-export-audit <users.csv> [--html] [--today YYYY-MM-DD] [--stale-days N] [--fail-on high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.\n";
if (args.Length == 0 || args[0].StartsWith('-')) { Console.Error.Write(usage); return 2; }
bool html = false; var today = DateTime.UtcNow.Date; int stale = 90; string? failOn = null;
for (int i = 1; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--html": html = true; break;
        case "--today" when i + 1 < args.Length && DateTime.TryParse(args[i + 1], System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var t): today = t; i++; break;
        case "--stale-days" when i + 1 < args.Length && int.TryParse(args[i + 1], out var s) && s > 0: stale = s; i++; break;
        case "--fail-on" when i + 1 < args.Length && args[i + 1] is "high" or "critical": failOn = args[++i]; break;
        default: Console.Error.Write($"error: bad option {args[i]}\n{usage}"); return 2;
    }
}
if (!File.Exists(args[0])) { Console.Error.WriteLine($"error: cannot read {args[0]}"); return 2; }
var accounts = Audit.Load(File.ReadAllText(args[0]));
var findings = Audit.Run(accounts, today, stale);
Console.Out.Write(html ? Audit.Html(findings, accounts.Count) : Audit.Text(findings, accounts.Count));
if (failOn != null && findings.Any(f => f.Severity <= (failOn == "critical" ? Severity.Critical : Severity.High))) return 1;
return 0;
