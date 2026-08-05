using System.Globalization;
public class LogParser 
{
    public static LogEntry? ParseFailedLogin(string line) //a method that gives back either a LogEntry (timestamp and IP) or `null`, saying this line isnt a failed login, ignore it
    {
        if (!line.Contains("Failed password"))
        {
            return null;
        }

        string[] parts = line.Split(' '); //turning the lines into addressable fields so we can index each category (ip/date/etc.)

        int fromIndex = Array.IndexOf(parts, "from"); //getting the ip from the index thats after the word "from", so we dont miss IPs in differently formatted lines
        int ipPosition = fromIndex + 1;
        string ip = parts[ipPosition];

        string timestampText = $"{parts[0]} {parts[1]} {parts[2]}"; //combining the date indexes to make an actual date 
        DateTime timestamp = DateTime.ParseExact(timestampText, "MMM d HH:mm:ss", CultureInfo.InvariantCulture); 


        LogEntry entry = new LogEntry {Timestamp = timestamp, SourceIp = ip}; //binding the two facts (time and ip of attack) into one unit so they can move together from now on without losing attributes
        return entry;
    }
}
