# AuthLogAnalyzer

Reads a Linux `auth.log` file and reports which IP addresses look like they were
brute-forcing SSH. Written in C# to learn the language.

## The idea

A failed login on its own means nothing. People mistype passwords all the time,
and a server on the internet gets background noise from bots constantly.

What actually matters is the **rate**. Five failures from one IP over a week is
someone forgetting their password. Five failures from one IP in twenty seconds
is a script working through a wordlist.

So the rule is: how many failures from the same IP, and how close together. If a
run of N failures fits inside M minutes, it gets flagged. That's the same idea
fail2ban uses, where the two settings are called `maxretry` and `findtime`.

Both numbers are set in `Program.cs`, currently 5 failures in 10 minutes.

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
dotnet run --project AuthLogAnalyzer
```

Output:

```
Read 32 lines
The IP 192.168.1.61 failed 2 times.
The IP 198.51.100.7 failed 3 times.
The IP 203.0.113.42 failed 12 times.
The IP 192.168.1.50 failed 1 times.
Detected BRUTE FORCE ATTACK: IP - 203.0.113.42 | Span - 00:00:22 | Failures - 12
So far, 18 failed IPs have been collected.
```

## Tests

```bash
dotnet test
```

8 tests. Three of them exist because of bugs I actually hit:

- **Space-padded days.** Real syslog writes `Mar  7` with two spaces so the
  columns line up. `Split(' ')` turned that gap into an empty string, every
  index after it shifted by one, and `ParseExact` threw. Fixed with
  `StringSplitOptions.RemoveEmptyEntries`.
- **The last run.** The sliding window checks runs of N consecutive failures.
  The last valid starting position is `Count - N`, so the loop needs `<=`, not
  `<`. With `<` it gives up one run early. The test uses six failures where only
  the *last* possible run is fast enough, so it fails if that ever gets changed
  back.
- **Lines with no IP.** The truncated-line case above.

## Layout

```
AuthLogAnalyzer/LogParser.cs            reads one line, returns a LogEntry or null
AuthLogAnalyzer/LogEntry.cs             one failed login: timestamp + IP
AuthLogAnalyzer/BruteForceDetector.cs   reads many entries, returns the findings
AuthLogAnalyzer/BruteForceFinding.cs    one detection: IP, failure count, span
AuthLogAnalyzer/Program.cs              reads the file, sets the rules, prints
AuthLogAnalyzer.Tests/                  xUnit tests
sample-data/                            the log and its expected result
```

The parser and the detector don't read files, don't print anything and don't
store results anywhere. They take what they need as arguments and hand back what
they produced. That's mostly so they can be tested, but it also means swapping
the output for a database later only changes `Program.cs`.

## Next

Store the findings in SQL, then put it on Azure.
