DROP TABLE IF EXISTS Findings;
GO

CREATE TABLE Findings
(
    ID INT IDENTITY(1,1) PRIMARY KEY,
    SourceIp VARCHAR(15) NOT NULL,
    FailureCount INT NOT NULL,
    SpanSeconds INT NOT NULL,
    AttemptTime DATETIME2 NOT NULL,
    CONSTRAINT UQ_Findings_Ip_Time UNIQUE (SourceIp, AttemptTime) --were adding this unique rule so that no two rows can have the same IP and date of attack -
                                                                  --when we rerun a log, without this rule, there would be duplicated, erroring the results
)
GO
