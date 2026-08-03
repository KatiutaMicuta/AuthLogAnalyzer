# Expected results for `auth.log`

This file is synthetic test data with a deliberately planted attack, so the
correct answer is known in advance. If the analyzer disagrees with this, the
analyzer is wrong.

32 lines total. All events are on **Mar 15**.

## Failed logins grouped by IP

| IP | Failures | Time span | Verdict at "5 failures in 10 minutes" |
|---|---|---|---|
| `203.0.113.42` | 12 | 14:02:11 → 14:03:29 (78 seconds) | **BRUTE FORCE** |
| `198.51.100.7` | 3 | 11:47:09 → 13:19:38 (92 minutes) | not an attack — too slow, too few |
| `192.168.1.61` | 2 | 09:23:15 → 09:23:22 (7 seconds) | not an attack — bob mistyped, then succeeded |
| `192.168.1.50` | 1 | 16:44:31 | not an attack |

**Total failed logins: 18. Total successful logins: 6.**

## The attack in detail

`203.0.113.42` tries 12 passwords in 78 seconds against 9 different usernames
(`root`, `admin`, `oracle`, `postgres`, `test`, `ubuntu`, `git`, `jenkins`,
`backup`) — username spraying, a classic brute-force signature.

At **14:03:44 it succeeds** as `backup`, then runs `sudo` two minutes later.
So this log also contains a successful breach, not just failed noise.

## Deliberate parsing challenges

1. **Non-sshd lines must be ignored** — there are `CRON`, `sudo`, and
   `systemd-logind` entries mixed in. 7 of the 32 lines are not sshd.
2. **Two username formats.** `Failed password for root from ...` versus
   `Failed password for invalid user admin from ...`. The word "for" is not
   always followed by the username — sometimes it's followed by
   `invalid user`. The field position shifts.
3. **Two success formats.** `Accepted password` and `Accepted publickey`.
   The publickey lines also have a trailing key fingerprint after `ssh2:`.
4. **Timestamps have no year.** Syslog format is `Mar 15 14:02:11` — the year
   is nowhere in the line. Something has to supply it.

## Not yet covered (add later when hardening)

Real `auth.log` files space-pad single-digit days: `Mar  7 09:15:01` has **two**
spaces, which breaks naive splitting. Every day in this file is `15`, so that
case is not exercised here.
