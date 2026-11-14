# Changelog

All notable changes to SOCSift are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-11-14

### Added

- Detection engine for `selection`, `threshold`, and `sequence` rules with
  case-insensitive string matching, list values, grouping, burst collection,
  follow-up windows, and severity filtering.
- Evidence-rich `Alert` model retaining the full rule, matched events, group
  values, time range, source IPs, usernames, and hostnames.
- Working `socsift analyze` command: parses SSH evidence, runs built-in or
  custom rules, renders alert cards with raw-line evidence, writes optional
  plain-text reports, and returns exit code `1` when alerts are produced.
- Working `socsift rules test <ID> -i FILE`: runs one rule against one log,
  shows every match, and returns `1` when the rule fires.
- `--rules` option on `analyze` and `rules test` for custom rule files or
  directories.
- Shared text report renderer with severity counters, ingestion metadata,
  evidence previews, MITRE context, and the first recommended action.
- Clear reserved-option errors for `--enrich`, `--config`, and non-text report
  formats instead of silent no-ops.

### Changed

- Version bumped to `0.3.0`; README documents the detection semantics, report
  output, known limits, and current command surface.
- `rules test` is no longer a reserved command.
- `analyze` defaults to built-in rules and the `low` severity floor.

## [0.2.0] - 2026-11-14

### Added

- Normalized `Event` model with UTC timestamps, stable common fields, and
  parser-specific evidence in `fields`.
- OpenSSH `auth.log` parser supporting classic syslog and ISO timestamps,
  IPv4/IPv6 sources, accepted/failed authentication, invalid users, PAM
  sessions, connection events, timeouts, and maximum-attempt errors.
- `socsift parse` diagnostics command with ingestion coverage, event preview,
  stdin support, and malformed-line reporting.
- Strict YAML rule loader with schema validation, duration parsing, MITRE
  checks, duplicate-ID detection, and escaped user-facing errors.
- Four built-in SSH rules: brute force, success after failures, invalid-user
  enumeration, and direct root login. `rules list`, `rules show`, and
  `rules validate` now work against built-in or custom rule paths.
- Synthetic `sample_logs/ssh_auth.log` with documented attack and benign
  scenarios, using only documentation and private IP ranges.
- `PyYAML` runtime dependency, `types-PyYAML` development dependency, and
  packaged `builtin/*.yaml` rule data.

### Changed

- Version bumped to `0.2.0`; the landing page and `--help` now advertise the
  `parse` command under a Diagnostics panel.
- `rules test` remains reserved until the Phase 3 detection engine lands.
- README documents the current ingestion and rule workflow, the rule schema,
  and the sample-data safety policy.

## [0.1.0] - 2026-11-14

### Added

- Installable `src/` package with a `socsift` console entry point.
- Typer command surface for detection, investigation, case workflow, and
  utility commands.
- Kali-inspired ASCII wordmark, landing screen, and Rich theme.
- Global `-q`, `-v`, `--no-color`, and `--version` switches that work before
  or after a subcommand.
- Stable exit codes: `0` clean, `1` alerts, `2` error, with no tracebacks for
  usage mistakes.
- Reserved-command messages and a professional `--help` surface as the
  foundation for phases 2–12.
