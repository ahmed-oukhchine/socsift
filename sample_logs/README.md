# Sample logs

All data in this directory is synthetic. IP addresses come from documentation
ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), private
ranges (RFC 1918), and the IPv6 documentation prefix `2001:db8::/32`. Hosts,
users, key fingerprints, and messages are fictional. No real credentials are
present.

The logs contain attack activity without inline labels. Use this key after
trying the parser and rules so the findings stay a useful test.

## `ssh_auth.log`

Classic syslog timestamps omit the year; SOCSift assumes the current UTC year.
The sample is set on 14 November.

| Scenario | Source | Expected rule | Risk in 0.4.0 | Evidence |
| --- | --- | --- | --- | --- |
| Invalid-user enumeration | `192.0.2.66` | `SSH-USER-ENUM-001` | 51 / P3 | Five unknown usernames between 09:10 and 09:11 |
| SSH brute force | `203.0.113.45` | `SSH-BRUTE-001` | 79 / P2 | Six failed passwords plus a maximum-attempts error within two minutes |
| Successful login after failures | `198.51.100.77` | `SSH-SUCCESS-AFTER-FAIL-001` | 100 / P1 | Three failures for `alice`, then an accepted password |
| Direct root login attempt | `203.0.113.99` | `SSH-ROOT-001` | 79 / P2 | One failed root password, then an accepted root public key |
| Benign typo | `10.0.0.22` | none | - | `bob` fails once and succeeds seconds later |
| Benign username typo | `10.0.0.77` | none | - | One invalid user (`alicee`), below the enumeration threshold |
| Scanner noise | `203.0.113.200` | none | - | Disconnect and missing identification string |

The `203.0.113.45` brute force also includes a failed `root` attempt, so
`SSH-ROOT-001` legitimately matches that IP as well with a score of 68 / P2. The
later root login from `203.0.113.99` has only one preceding failure, below the
sequence rule's three-failure threshold; it is a root-login finding, not a
success-after-fail finding.

Cron and sudo lines are intentionally present so ingestion coverage and skipped
line counts are realistic.
