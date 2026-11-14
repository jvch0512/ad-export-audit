using AdExportAudit;

int n = 0, failed = 0;
void Check(string name, bool ok) { n++; if (!ok) { failed++; Console.WriteLine("FAIL: " + name); } }

var today = new DateTime(2026, 3, 14, 0, 0, 0, DateTimeKind.Utc);
const string Header = "SamAccountName,Enabled,PasswordNeverExpires,PasswordLastSet,LastLogonDate,MemberOf,ServicePrincipalNames,UserAccountControl,DoesNotRequirePreAuth,TrustedForDelegation\n";
List<Finding> Run(string rows) => Audit.Run(Audit.Load(Header + rows), today);
bool Has(List<Finding> f, string rule, string? acct = null) => f.Any(x => x.Rule == rule && (acct == null || x.Account == acct));

// CSV
var csv = Csv.Parse("a,\"b,c\",\"say \"\"hi\"\"\"\r\n1,\"multi\nline\",3\n");
Check("csv: quoted comma", csv[0][1] == "b,c");
Check("csv: doubled quotes", csv[0][2] == "say \"hi\"");
Check("csv: newline inside quotes", csv[1][1] == "multi\nline");
Check("csv: empty input", Csv.Parse("").Count == 0);
Check("csv: no trailing newline", Csv.Parse("a,b").Count == 1);

// rules
Check("clean account has no findings", Run("ana,True,False,2026-01-01,2026-03-10,,,512,False,False\n").Count == 0);
Check("AD001 kerberoastable", Has(Run("svc,True,False,2026-01-01,2026-03-10,,MSSQLSvc/x:1433,512,False,False\n"), "AD001", "svc"));
Check("AD001 privileged SPN is critical", Run("svc,True,False,2026-01-01,2026-03-10,CN=Domain Admins,MSSQLSvc/x,512,False,False\n").First(x => x.Rule == "AD001").Severity == Severity.Critical);
Check("krbtgt SPN is expected", !Has(Run("krbtgt,True,False,2026-01-01,,,kadmin/changepw,514,False,False\n"), "AD001"));
Check("AD002 as-rep roasting from the column", Has(Run("u,True,False,2026-01-01,2026-03-10,,,512,True,False\n"), "AD002"));
Check("AD002 as-rep roasting from the UAC flag", Has(Run("u,True,False,2026-01-01,2026-03-10,,,4194816,False,False\n"), "AD002"));
Check("AD006 unconstrained delegation via UAC", Has(Run("u,True,False,2026-01-01,2026-03-10,,,524800,False,False\n"), "AD006"));
Check("AD008 password not required", Run("u,True,False,2026-01-01,2026-03-10,,,544,False,False\n").First(x => x.Rule == "AD008").Severity == Severity.Critical);
Check("AD008 reversible encryption", Has(Run("u,True,False,2026-01-01,2026-03-10,,,640,False,False\n"), "AD008"));
Check("AD004 non-expiring privileged password", Has(Run("a,True,True,2026-01-01,2026-03-10,CN=Domain Admins,,66048,False,False\n"), "AD004"));
Check("AD004 not for ordinary users", !Has(Run("a,True,True,2026-01-01,2026-03-10,,,66048,False,False\n"), "AD004"));
Check("AD005 stale", Has(Run("a,True,False,2026-01-01,2025-10-01,,,512,False,False\n"), "AD005"));
Check("AD005 stale privileged is high", Run("a,True,False,2026-01-01,2025-10-01,CN=Domain Admins,,512,False,False\n").First(x => x.Rule == "AD005").Severity == Severity.High);
Check("AD005 recent logon is fine", !Has(Run("a,True,False,2026-01-01,2026-03-01,,,512,False,False\n"), "AD005"));
Check("AD007 old privileged password", Has(Run("a,True,False,2023-01-01,2026-03-01,CN=Domain Admins,,512,False,False\n"), "AD007"));
Check("disabled accounts are ignored", Run("a,False,True,2018-01-01,2018-02-01,CN=Domain Admins,MSSQLSvc/x,66048,True,True\n").Count == 0);
Check("AD003 too many domain admins",
    Has(Run(string.Join("", Enumerable.Range(1, 6).Select(i => $"da{i},True,False,2026-01-01,2026-03-10,CN=Domain Admins,,512,False,False\n"))), "AD003"));
Check("AD003 five is acceptable",
    !Has(Run(string.Join("", Enumerable.Range(1, 5).Select(i => $"da{i},True,False,2026-01-01,2026-03-10,CN=Domain Admins,,512,False,False\n"))), "AD003"));
Check("group DNs and plain names both work", Audit.Load(Header + "a,True,False,,,\"CN=Domain Admins,CN=Users,DC=x\",,512,False,False\n")[0].Groups[0] == "Domain Admins");
Check("columns are case-insensitive and optional", Audit.Load("samaccountname,enabled\nbob,true\n").Count == 1);
Check("findings are sorted by severity", Run("a,True,False,2026-01-01,2025-01-01,,MSSQLSvc/x,544,False,False\n")[0].Severity == Severity.Critical);

// output
var evil = new List<Finding> { new("AD001", Severity.High, "<img src=x>", "<script>alert(1)</script>") };
var html = Audit.Html(evil, 1);
Check("html escapes names and messages", !html.Contains("<script>alert") && html.Contains("&lt;script&gt;") && !html.Contains("<img src=x>"));
Check("html has a strict CSP", html.Contains("default-src 'none'"));

// robustness
var rng = new Random(11);
const string Alphabet = "abc,\"\n\r;|=-: 0123456789";
bool ok = true;
for (int i = 0; i < 1500; i++)
{
    var chars = new char[rng.Next(0, 300)];
    for (int j = 0; j < chars.Length; j++) chars[j] = Alphabet[rng.Next(Alphabet.Length)];
    try { Audit.Run(Audit.Load(new string(chars)), today); } catch { ok = false; }
}
Check("fuzz: 1500 random inputs, no exception", ok);

// sample
var path = "examples/users.csv";
if (File.Exists(path))
{
    var accts = Audit.Load(File.ReadAllText(path));
    var fs = Audit.Run(accts, today);
    Check("sample: 15 accounts", accts.Count == 15);
    Check("sample: 12 findings", fs.Count == 12);
    Check("sample: two critical", fs.Count(x => x.Severity == Severity.Critical) == 2);
    Check("sample: the clean users are not flagged", !fs.Any(x => x.Account is "maria.souza" or "joao.lima" or "ex.contractor" or "adm-ana"));
}
else Console.WriteLine("skipped sample tests (run from repo root)");

Console.WriteLine(failed == 0 ? $"all {n} passed" : $"{failed} of {n} failed");
return failed == 0 ? 0 : 1;
