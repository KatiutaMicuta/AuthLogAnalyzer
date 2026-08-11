using System.Globalization;
using System.Net;
public class LogParser
{
    public static LogEntry? ParseFailedLogin(string line, int year) //a method that gives back either a LogEntry (timestamp and IP) or `null`, saying this line isnt a failed login, ignore it
    {
        if (!line.Contains("Failed password"))
        {
            return null;
        }

        string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries); //turning the lines into addressable fields so we can index each category (ip/date/etc.)
        string? ip = null;


        foreach (string part in parts)
        {
            if (part.Split('.').Length == 4 && IPAddress.TryParse(part, out _))
            {
                ip = part;
                break;
            }
        }
        if (ip == null)
        {
            return null;
        }


        string timestampText = $"{year} {parts[0]} {parts[1]} {parts[2]}"; //combining the date indexes to make an actual date 
        DateTime timestamp = DateTime.ParseExact(timestampText, "yyyy MMM d HH:mm:ss", CultureInfo.InvariantCulture);


        LogEntry entry = new LogEntry { Timestamp = timestamp, SourceIp = ip }; //binding the two facts (time and ip of attack) into one unit so they can move together from now on without losing attributes
        return entry;
    }
}
