using Microsoft.Data.SqlClient;

public class FindingRepository
{
    
 public static int SaveFindings(List<BruteForceFinding> findings, string connectionString)
    {
        using SqlConnection connection = new SqlConnection(connectionString);
        connection.Open();

        string sql = @"INSERT INTO Findings (SourceIp, FailureCount, SpanSeconds, AttemptTime)
               SELECT @SourceIp, @FailureCount, @SpanSeconds, @AttemptTime
               WHERE NOT EXISTS (
                   SELECT 1 FROM Findings
                   WHERE SourceIp = @SourceIp AND AttemptTime = @AttemptTime
               )";

        int affectedRows = 0;
        
        foreach (BruteForceFinding finding in findings)
        {
            using SqlCommand command = new SqlCommand(sql, connection);

            command.Parameters.AddWithValue("@SourceIp", finding.SourceIp);
            command.Parameters.AddWithValue("@FailureCount", finding.FailureCount);
            command.Parameters.AddWithValue("@SpanSeconds",(int) finding.Span.TotalSeconds);
            command.Parameters.AddWithValue("@AttemptTime", finding.AttemptTime);

            affectedRows += command.ExecuteNonQuery();
        }
        return affectedRows;

    }  
}