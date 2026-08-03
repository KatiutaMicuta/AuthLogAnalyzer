string path ="/Users/katia/CompSci/AuthLogAnalyzer/sample-data/auth.log";
string [] lines = File.ReadAllLines(path);

Console.WriteLine($"Read {lines.Length} lines");

int failedCount = 0;

List<LogEntry> entries = new List<LogEntry>();


foreach (string line in lines)
{
    if (line.Contains("Failed password"))
    {
        Console.WriteLine(line);
        failedCount++;

        string[] parts = line.Split(' ');

        int fromIndex = Array.IndexOf(parts, "from");
        int ipPosition = fromIndex + 1;
        string ip = parts[ipPosition];

        string timestamp = $"{parts[0]} {parts[1]} {parts[2]}";

        Console.WriteLine($"The IP is {ip}.");
        LogEntry entry = new LogEntry
{
        TimestampRaw = timestamp,
        SourceIp = ip
};
 entries.Add(entry);
    }
}
            var groups = entries.GroupBy(e => e.SourceIp);
            foreach (var g in groups)
            {
                Console.WriteLine($"The IP {g.Key} failed {g.Count()} times.");
            }

Console.WriteLine($"So far, {entries.Count} failed IPs have been collected.");

