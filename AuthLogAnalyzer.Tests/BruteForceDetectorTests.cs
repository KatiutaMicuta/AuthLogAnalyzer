namespace AuthLogAnalyzer.Tests;

public class BruteForceDetectorTest
{
    [Fact]

    public void BruteForceDetector_AllIsWellTest()
    {

        List<LogEntry> entries = new List<LogEntry>

    {
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 0, 0),  SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 0, 5),  SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 0, 10), SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 0, 15), SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 0, 20), SourceIp = "10.0.0.1" },
    };

        List<BruteForceFinding> findings = BruteForceDetector.DetectBruteAttack(entries, 5, 10);

        Assert.Single(findings);
        Assert.Equal("10.0.0.1", findings[0].SourceIp);
        Assert.Equal(5, findings[0].FailureCount);
        Assert.Equal(TimeSpan.FromSeconds(20), findings[0].Span); //we need to say TimeSpan.FromSeconds(20) because 20 ks int and span is TimeSpan class
    }

    [Fact]

    public void BruteForceDetector_NoAttackTest()
    {
        List<LogEntry> entries = new List<LogEntry>
        {
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 0, 0),  SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 15, 5),  SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 30, 10), SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 45, 15), SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 15, 0, 20), SourceIp = "10.0.0.1" },
        };

        List<BruteForceFinding> findings = BruteForceDetector.DetectBruteAttack(entries, 5, 10);

        Assert.Empty(findings);

    }

   [Fact]

    public void BruteForceDetector_ThresholdLimitTest()
    {
        List<LogEntry> entries = new List<LogEntry>
        {
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 0, 0),  SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 30, 0),  SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 30, 5), SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 30, 10), SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 30, 15), SourceIp = "10.0.0.1" },
        new LogEntry { Timestamp = new DateTime(2024, 3, 15, 14, 30, 20), SourceIp = "10.0.0.1" },
        };

        List<BruteForceFinding> findings = BruteForceDetector.DetectBruteAttack(entries, 5, 10);

        Assert.Single(findings);
        Assert.Equal(TimeSpan.FromSeconds(20), findings[0].Span);


}
}