using System.Globalization;
using System.Net;
using System.Text;

namespace AdExportAudit;

public enum Severity { Critical = 0, High = 1, Medium = 2 }

public sealed record Finding(string Rule, Severity Severity, string Account, string Message);

public sealed class Account
{
    public string Name = "";
    public bool Enabled = true;
    public bool PasswordNeverExpires;
    public DateTime? PasswordLastSet;
    public DateTime? LastLogon;
    public List<string> Groups = new();
    public List<string> Spns = new();
    public int Uac;
    public bool TrustedForDelegation;
    public bool NoPreAuth;
    public bool PasswordNotRequired;
}

public static class Csv
{
    /// <summary>RFC 4180 style: quoted fields, doubled quotes, commas and newlines inside quotes.</summary>
    public static List<List<string>> Parse(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var sb = new StringBuilder();
        bool inQ = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (inQ)
            {
                if (c == '"') { if (i + 1 < text.Length && text[i + 1] == '"') { sb.Append('"'); i++; } else inQ = false; }
                else sb.Append(c);
            }
            else if (c == '"') inQ = true;
            else if (c == ',') { row.Add(sb.ToString()); sb.Clear(); }
            else if (c == '\n' || c == '\r')
            {
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                row.Add(sb.ToString()); sb.Clear();
                if (row.Count > 1 || row[0].Length > 0) rows.Add(row);
                row = new List<string>();
            }
            else sb.Append(c);
        }
        if (sb.Length > 0 || row.Count > 0) { row.Add(sb.ToString()); if (row.Count > 1 || row[0].Length > 0) rows.Add(row); }
        return rows;
    }
}

public static class Audit
{
    public static readonly string[] Privileged = { "domain admins", "enterprise admins", "schema admins", "administrators", "account operators", "backup operators", "server operators", "print operators", "dnsadmins" };

    const int UacPasswdNotReq = 0x20, UacReversible = 0x80, UacDontExpire = 0x10000, UacTrustedDeleg = 0x80000, UacDesOnly = 0x200000, UacNoPreAuth = 0x400000;

    static bool Truthy(string s) => s.Trim().ToLowerInvariant() is "true" or "1" or "yes";

    static DateTime? Date(string s) => DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;

    static List<string> Split(string s) => s.Split(new[] { ';', '|' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    /// <summary>Reads the CSV that Get-ADUser | Export-Csv produces. Column names are matched case-insensitively and missing columns are tolerated.</summary>
    public static List<Account> Load(string csv)
    {
        var rows = Csv.Parse(csv);
        var accounts = new List<Account>();
        if (rows.Count == 0) return accounts;
        var idx = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < rows[0].Count; i++) idx[rows[0][i].Trim()] = i;
        string Get(List<string> r, string col) => idx.TryGetValue(col, out var k) && k < r.Count ? r[k] : "";
        foreach (var r in rows.Skip(1))
        {
            var name = Get(r, "SamAccountName");
            if (name.Length == 0) continue;
            int.TryParse(Get(r, "UserAccountControl"), out var uac);
            var a = new Account
            {
                Name = name,
                Enabled = Get(r, "Enabled").Length == 0 || Truthy(Get(r, "Enabled")),
                PasswordNeverExpires = Truthy(Get(r, "PasswordNeverExpires")) || (uac & UacDontExpire) != 0,
                PasswordLastSet = Date(Get(r, "PasswordLastSet")),
                LastLogon = Date(Get(r, "LastLogonDate")),
                Groups = Split(Get(r, "MemberOf")).Select(g => g.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? g[3..].Split(',')[0] : g).ToList(),
                Spns = Split(Get(r, "ServicePrincipalNames")),
                Uac = uac,
                TrustedForDelegation = Truthy(Get(r, "TrustedForDelegation")) || (uac & UacTrustedDeleg) != 0,
                NoPreAuth = Truthy(Get(r, "DoesNotRequirePreAuth")) || (uac & UacNoPreAuth) != 0,
                PasswordNotRequired = Truthy(Get(r, "PasswordNotRequired")) || (uac & UacPasswdNotReq) != 0,
            };
            accounts.Add(a);
        }
        return accounts;
    }

    public static bool IsPrivileged(Account a) => a.Groups.Any(g => Privileged.Contains(g.Trim().ToLowerInvariant()));

    public static List<Finding> Run(List<Account> accounts, DateTime today, int staleDays = 90, int maxDomainAdmins = 5)
    {
        var f = new List<Finding>();
        foreach (var a in accounts.Where(a => a.Enabled))
        {
            bool priv = IsPrivileged(a);
            if (a.Spns.Count > 0 && !a.Name.Equals("krbtgt", StringComparison.OrdinalIgnoreCase))
                f.Add(new("AD001", priv ? Severity.Critical : Severity.High, a.Name, priv ? "privileged account with an SPN: Kerberoasting it hands over a domain admin password hash" : $"user account with {a.Spns.Count} SPN(s) can be Kerberoasted"));
            if (a.NoPreAuth) f.Add(new("AD002", priv ? Severity.Critical : Severity.High, a.Name, "Kerberos pre-authentication is off: the password hash can be requested without credentials (AS-REP roasting)"));
            if (a.PasswordNotRequired) f.Add(new("AD008", Severity.Critical, a.Name, "PASSWD_NOTREQD is set: the account may have an empty password"));
            if ((a.Uac & UacReversible) != 0) f.Add(new("AD008", Severity.High, a.Name, "reversible password encryption is enabled"));
            if ((a.Uac & UacDesOnly) != 0) f.Add(new("AD008", Severity.High, a.Name, "Kerberos DES-only is enabled"));
            if (a.TrustedForDelegation) f.Add(new("AD006", Severity.High, a.Name, "unconstrained delegation: anyone who compromises it can impersonate any user that authenticates to it"));
            if (priv && a.PasswordNeverExpires) f.Add(new("AD004", Severity.High, a.Name, "privileged account whose password never expires"));
            if (priv && a.PasswordLastSet is { } p && (today - p).TotalDays > 365) f.Add(new("AD007", Severity.Medium, a.Name, $"privileged password not changed for {(int)(today - p).TotalDays} days"));
            if (a.LastLogon is { } l && (today - l).TotalDays > staleDays) f.Add(new("AD005", priv ? Severity.High : Severity.Medium, a.Name, $"enabled but no logon for {(int)(today - l).TotalDays} days{(priv ? " and privileged" : "")}: disable it"));
        }
        int da = accounts.Count(a => a.Enabled && a.Groups.Any(g => g.Trim().Equals("Domain Admins", StringComparison.OrdinalIgnoreCase)));
        if (da > maxDomainAdmins) f.Add(new("AD003", Severity.High, "(domain)", $"{da} enabled Domain Admins (limit {maxDomainAdmins}): every one is a path to full compromise"));
        return f.OrderBy(x => x.Severity).ThenBy(x => x.Rule, StringComparer.Ordinal).ThenBy(x => x.Account, StringComparer.Ordinal).ToList();
    }

    public static string Text(List<Finding> fs, int accounts)
    {
        var sb = new StringBuilder($"{accounts} accounts, {fs.Count} findings\n");
        foreach (var x in fs) sb.Append($"{x.Severity.ToString().ToUpperInvariant(),-9}{x.Rule} {x.Account}\n         {x.Message}\n");
        return sb.ToString();
    }

    public static string Html(List<Finding> fs, int accounts)
    {
        var rows = new StringBuilder();
        foreach (var x in fs) rows.Append($"<tr><td class=\"{x.Severity.ToString().ToLowerInvariant()}\">{x.Severity.ToString().ToLowerInvariant()}</td><td>{x.Rule}</td><td>{WebUtility.HtmlEncode(x.Account)}</td><td>{WebUtility.HtmlEncode(x.Message)}</td></tr>");
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>ad-export-audit</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}.critical{color:#f85149;font-weight:700}.high{color:#f0883e;font-weight:700}.medium{color:#e3b341;font-weight:700}</style></head><body><h1>ad-export-audit</h1>"
            + $"<p class=\"sub\">Active Directory export audit in C#, no dependencies. Synthetic export: {accounts} accounts, {fs.Count} findings.</p><table><tr><th>Severity</th><th>Rule</th><th>Account</th><th>Finding</th></tr>{rows}</table>"
            + "<p class=\"sub\">Works on an export, not on the live directory: it cannot see ACLs, GPOs, trusts or AD CS. Treat it as the first pass of an AD review.</p></body></html>\n";
    }
}
