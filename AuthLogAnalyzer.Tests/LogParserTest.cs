namespace AuthLogAnalyzer.Tests;

public class LogParserTest
{
    [Fact]
    public void LogParser_WhenFailedLoginLine_ReturnsCorrectIPAndDate()
    {
        string line = "Mar 15 14:02:11 webserver sshd[1602]: Failed password for root from 203.0.113.42 port 44201 ssh2";
        LogEntry? answer = LogParser.ParseFailedLogin(line);
        Assert.NotNull(answer);
        Assert.Equal("203.0.113.42", answer.SourceIp);
    }

    [Fact]

    public void LogParser_LineIsntFailedLogin()
    {
        string line = "Mar 15 09:01:01 webserver CRON[1198]: pam_unix(cron:session): session opened for user root by (uid=0)";
        LogEntry? answer = LogParser.ParseFailedLogin(line); // its gonna return null because if you go to the method it can return null
        Assert.Null(answer);
        
    }

    [Fact]

    public void LogParser_NoIPLine()
    {
        string line = "Mar 15 10:00:00 webserver sshd[1602]: Failed password";
        LogEntry? answer = LogParser.ParseFailedLogin(line);
        Assert.Null(answer);
    }

        [Fact]

    public void LogParser_OneDateNumber()
    {
        string line = "Mar  5 14:02:11 webserver sshd[1602]: Failed password for root from 203.0.113.42 port 44201 ssh2";
        LogEntry? answer = LogParser.ParseFailedLogin(line);
        Assert.NotNull(answer);
        Assert.Equal("203.0.113.42", answer.SourceIp);
    }
}
