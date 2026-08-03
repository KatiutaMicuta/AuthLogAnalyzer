string path ="/Users/katia/CompSci/AuthLogAnalyzer/sample-data/auth.log";
string [] lines = File.ReadAllLines(path);

Console.WriteLine($"Read {lines.Length} lines");

int failedCount = 0;

List<string> ips = new List<string>();

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

        Console.WriteLine($"The IP is {ip}.");
        ips.Add(ip);

    }
}
            var groups = ips.GroupBy(f => f);
            foreach (var g in groups)
            {
                Console.WriteLine($"The IP {g.Key} failed {g.Count()} times.");
            }

Console.WriteLine($"So far, {ips.Count} failed IPs have been collected.");

