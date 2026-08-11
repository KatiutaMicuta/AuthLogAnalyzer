
string path = "/Users/katia/CompSci/AuthLogAnalyzer/sample-data/auth.log";
string[] lines = File.ReadAllLines(path);

Console.WriteLine($"Read {lines.Length} lines");


int attemptThreshold = 5; //how many failures make it sus
int windowMinutes = 10; // how close together attempts have to be

List<LogEntry> entries = new List<LogEntry>(); //creates the container where we're gonna acummulate evidence



foreach (string line in lines)
{
    LogEntry? entry = LogParser.ParseFailedLogin(line, DateTime.Now.Year); //either a LogEntry, or null if this line wasn't a failed login

    if (entry != null) //only real entries go in the list
    {
        entries.Add(entry); //commit evidence to the list
    }
}

var groups = entries.GroupBy(e => e.SourceIp); //we organize them by IP so we can group attacks
foreach (var g in groups)
{
    Console.WriteLine($"The IP {g.Key} failed {g.Count()} times.");
}

List<BruteForceFinding> findings = BruteForceDetector.DetectBruteAttack(entries, attemptThreshold, windowMinutes);
foreach (BruteForceFinding finding in findings)
{
    Console.WriteLine($"Detected BRUTE FORCE ATTACK: IP - {finding.SourceIp} | Span - {finding.Span} | Failures - {finding.FailureCount}");
}

Console.WriteLine($"So far, {entries.Count} failed IPs have been collected.");