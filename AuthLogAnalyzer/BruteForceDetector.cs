
public class BruteForceDetector
{
    public static List<BruteForceFinding> DetectBruteAttack(List<LogEntry> entries, int attemptThreshold, int windowMinutes)
    {

        List<BruteForceFinding> findings = new List<BruteForceFinding>();

        var groups = entries.GroupBy(e => e.SourceIp); //we organize them by IP so we can group attacks
        foreach (var g in groups)
        {

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
                    BruteForceFinding finding = new BruteForceFinding //assigning the values we found to the class
                    {
                        Span = span,
                        SourceIp = g.Key,
                        FailureCount = g.Count()
                    };
                    findings.Add(finding);
                    break;
                }
            }
        }
        return findings;

    }
}