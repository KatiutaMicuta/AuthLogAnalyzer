using System.Globalization;

string path ="/Users/katia/CompSci/AuthLogAnalyzer/sample-data/auth.log";
string [] lines = File.ReadAllLines(path);

Console.WriteLine($"Read {lines.Length} lines");


int attemptThreshold = 5; //how many failures make it sus
int windowMinutes = 10; // how close together attempts have to be

List<LogEntry> entries = new List<LogEntry>(); //creates the container where we're gonna acummulate evidence


// PASS 1 - collect. Hand each line to the parser, keep whatever comes back.
foreach (string line in lines)
{
    LogEntry? entry = LogParser.ParseFailedLogin(line); //either a LogEntry, or null if this line wasn't a failed login

    if (entry != null) //only real entries go in the list
    {
        entries.Add(entry); //commit evidence to the list
    }
}

// PASS 2 - analyse. Runs once, after every line has been seen.
var groups = entries.GroupBy(e => e.SourceIp); //we organize them by IP so we can group attacks
foreach (var g in groups)
{
    Console.WriteLine($"The IP {g.Key} failed {g.Count()} times.");

    List<LogEntry> failures = g.OrderBy(e => e.Timestamp).ToList(); //orders attacks by time and makes the list addressable
                                         // threshold - here it decides how many starting positions exist. ex. Count of failures is 12, so there will be 7 starting positions in groups of 5.
    for (int i = 0; i <= failures.Count - attemptThreshold; i++) //i is the starting position of a run.The last valid start is Count - threshold - for 12 failures and a threshold of 5, that's 7, the number we worked out by hand.
    {
        DateTime firstAttempt = failures[i].Timestamp; //first time log of the run being examined (first attempt of attack)
        DateTime lastAttempt = failures[i + attemptThreshold - 1].Timestamp;//last time log of the attack being examined //threshold - Here it decides how wide each run is - which  item counts as the end
        TimeSpan span = lastAttempt - firstAttempt; //the time between attacks
                            //FromMinutes makes sure that the program knows that windowMinutes = 10 MINUTES, not just 10.
        if (span <= TimeSpan.FromMinutes(windowMinutes)) //TimeSpan.FromMinutes(a TimeSpam meant t represent ten minutes) - we're comparing duration to duration
        {
            Console.WriteLine($"Classified as BRUCE FORCE attack: {g.Key} - {g.Count()} failures total, {attemptThreshold} within {span.TotalSeconds} seconds");
            break;
        }
    }
}

Console.WriteLine($"So far, {entries.Count} failed IPs have been collected.");
