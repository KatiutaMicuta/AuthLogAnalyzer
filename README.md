# AuthLogAnalyzer

Reads a Linux `auth.log` file and reports which IP addresses look like they were
brute-forcing SSH. Written in C# to learn the language.

## The idea

A failed login on its own means nothing. People mistype passwords all the time,
and a server on the internet gets background noise from bots constantly.

What actually matters is the **rate**. Five failures from one IP over a week is
someone forgetting their password. Five failures from one IP in twenty seconds
is an attempted breach.

So the rule is: how many failures from the same IP, and how close together. If a
run of X failures fits inside Y minutes, it gets flagged. That's the same idea
fail2ban uses, where the two settings are called `maxretry` and `findtime`.

Both numbers are set in `Program.cs` - 5 failures in 10 minutes.

## Finding the IP

The obvious approach is to look for the word `from` and take the next word:

```
Failed password for root from 203.0.113.42 port 44201 ssh2
```

That works until the line is truncated, which happens with a full disk or a
crash mid-write. `Array.IndexOf` returns `-1` when it can't find `from`, and
adding 1 to that gives index 0, so the analyzer reported an attack coming from
an IP address called `Mar`. No crash, no warning, just a wrong answer that looks
completely normal in the output.

So instead of looking at *where* the IP sits, it looks for the piece that is
shaped like an IP: four numbers separated by dots, that `IPAddress.TryParse`
accepts. Both checks are needed. `TryParse` on its own accepts `"15"` and turns
it into `0.0.0.15`, so it would have matched the day of the month before it ever
reached the real address.

The nice side effect is that it no longer cares about the surrounding words, so
`Failed password for root from ...` and `Failed password for invalid user admin
from ...` both work without any extra code.

## The year problem

Syslog timestamps have no year in them:

```
Mar 15 14:02:11
```

`DateTime.ParseExact` fills the gap from the system clock, which means the same
log file gives different answers depending on what day you run it, and a log
spanning New Year gets January sorted before December.

So the year is passed in as a parameter instead. `Program.cs` passes
`DateTime.Now.Year`, which is the same behaviour as before, but now it's a
visible decision in the caller rather than something hidden inside `ParseExact`.
It also means the tests can pass a fixed year and assert on the result.

## Storing the findings

Printing to the terminal means the program forgets everything the moment it
exits. You can't ask "has this IP hit us before?" or compare last week to this
week. So the findings go into SQL Server, running locally in Docker.

`sql/schema.sql` holds the table definition, so it's in version control rather
than only inside my container. `FindingRepository.cs` is the only file that
knows a database exists - the parser and the detector never learn about it,
which is why their tests still run in milliseconds with nothing installed.

Three decisions in there worth writing down:

**`TimeSpan` doesn't survive the trip.** SQL Server has no duration type. `TIME`
is a clock time, not an elapsed one. So the span is stored as
`SpanSeconds INT` - `22` instead of `00:00:22` - which keeps "show me the
fastest attacks" answerable as a plain sort. The conversion happens in the
repository, at the moment of the insert, so the C# class keeps its `TimeSpan`
and nothing else in the project has to know about the compromise.

**The values are parameters, not string interpolation.** This program's input is
a file written by attackers - they choose the usernames they try. Building SQL
with `$"...{value}..."` would mean a username like `'; DROP TABLE Findings; --`
stops being data and becomes a command. With `@SourceIp` placeholders the query
and the values travel separately and a value can never be parsed as SQL.

**Running it twice shouldn't duplicate anything.** A finding is the same finding
if it's the same IP at the same time, so there's a
`UNIQUE (SourceIp, AttemptTime)` constraint. That meant `BruteForceFinding`
needed a field it didn't have - it knew how *long* an attack took but not
*when* it happened, so Monday's attack and Friday's were indistinguishable. The
insert also checks `WHERE NOT EXISTS` first, so a re-run inserts nothing instead
of throwing. Both are deliberate: the check keeps the program quiet, the
constraint is what actually guarantees it.

The connection string has the `sa` password in it, and this repo is public, so
it lives in `dotnet user-secrets` - stored outside the project folder entirely,
loaded at runtime. Nothing to remember to gitignore.

## The sample log

macOS has no `/var/log/auth.log`, so `sample-data/auth.log` is a synthetic one
with an attack deliberately planted in it. `sample-data/EXPECTED.md` writes down
the correct answer for that file, so there's something to check the output
against instead of squinting at it.

It has 32 lines, 18 of them failed logins. `203.0.113.42` tries 12 passwords
against 9 different usernames in 78 seconds, then succeeds as `backup` and runs
`sudo` two minutes later. There's also CRON and sudo noise mixed in that has to
be ignored, and a user who mistyped twice and then got in, which shouldn't be
flagged.

## How to run it

```bash
git clone https://github.com/KatiutaMicuta/AuthLogAnalyzer.git
cd AuthLogAnalyzer
```

Start SQL Server. Pick your own password - it needs 8+ characters and three of
uppercase, lowercase, digit, symbol:

```bash
docker run --name authlog-sql --platform linux/amd64 -e 'ACCEPT_EULA=Y' -e 'MSSQL_SA_PASSWORD=<your password>' -p 1433:1433 -d mcr.microsoft.com/mssql/server:2022-latest
```

`--platform linux/amd64` is for Apple Silicon - SQL Server has no ARM build, so
it runs under Rosetta. Leave it out on an Intel machine or on Linux.

Create the database and the table:

```bash
docker exec -i authlog-sql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P '<your password>' -C -Q "CREATE DATABASE AuthLogAnalyzer"
docker exec -i authlog-sql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P '<your password>' -C -d AuthLogAnalyzer < sql/schema.sql
```

Tell the program how to reach it:

```bash
dotnet user-secrets set "ConnectionStrings:AuthLog" "Server=localhost,1433;Database=AuthLogAnalyzer;User Id=sa;Password=<your password>;TrustServerCertificate=True" --project AuthLogAnalyzer
```

Then:

```bash
dotnet run --project AuthLogAnalyzer
```

Output:

```
Read 32 lines
The IP 192.168.1.61 failed 2 times.
The IP 198.51.100.7 failed 3 times.
The IP 203.0.113.42 failed 12 times.
The IP 192.168.1.50 failed 1 times.
Detected BRUTE FORCE ATTACK: IP - 203.0.113.42 | Span - 00:00:22 | Failures - 12 | Time - 15/03/2026 14:02:11
So far, 18 failed IPs have been collected.
Saved 1 new findings to the database.
```

Run it again and the last line says `Saved 0` - the finding is already there.

## Tests

```bash
dotnet test
```

8 tests. Three of them exist because of bugs I actually hit:

- **Space-padded days.** Real syslog writes `Mar  7` with two spaces so the
  columns line up. `Split(' ')` turned that gap into an empty string, every
  index after it shifted by one, and `ParseExact` threw. Fixed with
  `StringSplitOptions.RemoveEmptyEntries`.
- **The last run.** The sliding window checks runs of X consecutive failures.
  The last valid starting position is `Count - X`, so the loop needs `<=`, not
  `<`. With `<` it gives up one run early. The test uses six failures where only
  the *last* possible run is fast enough, so it fails if that ever gets changed
  back.
- **Lines with no IP.** The truncated-line case above.

## Layout

```
AuthLogAnalyzer/LogParser.cs            reads one line, returns a LogEntry or null
AuthLogAnalyzer/LogEntry.cs             one failed login: timestamp + IP
AuthLogAnalyzer/BruteForceDetector.cs   reads many entries, returns the findings
AuthLogAnalyzer/BruteForceFinding.cs    one detection: IP, failure count, span, start time
AuthLogAnalyzer/FindingRepository.cs    writes findings to SQL Server
AuthLogAnalyzer/Program.cs              reads the file, sets the rules, prints, saves
AuthLogAnalyzer.Tests/                  xUnit tests
sample-data/                            the log and its expected result
sql/schema.sql                          the table definition
```

Each class translates between two worlds: `LogParser` between syslog text and
C# objects, `BruteForceDetector` between entries and findings,
`FindingRepository` between findings and SQL rows. None of them read files or
print, except `Program.cs`, which does nothing else. That's mostly so they can
be tested - the detector's tests run with no database and no log file - but it
also means the whole storage layer moving to Azure touches exactly one file.

## How this was built

I wrote this to learn C#, and I used Claude as a tutor the whole way through -
explaining syntax, catching my mistakes, and telling me why something was wrong
rather than just fixing it.

The SQL stage was **heavily guided**. I made the design calls - what identifies
a duplicate finding, what the columns should be, that the span had to be stored
as a number - but the actual SQL, the ADO.NET code in `FindingRepository.cs`,
and the parameterised-query and constraint patterns were written with Claude
walking me through them line by line. I hadn't touched SQL Server or Docker
before this.

The parser and the detector were more mine. The sliding window, the four-dots
rule for finding an IP, and the off-by-one on the last run were things I worked
out and then had checked.

## Next

Put it on Azure.
