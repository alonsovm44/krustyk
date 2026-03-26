# Changelog
All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-25

Added:
- Initial implementation of `krustyk` CLI wrapper.
- Command failure detection based on exit code.
- Generation of a JSON debug bundle with:
  - Command output (stdout, stderr), exit code.
  - System info (OS, architecture, working directory).
  - Sanitized environment variables.
  - System logs (`journalctl`, `Get-WinEvent`).
  - Git context (branch, commit, status).
  - Project manifest files (`Cargo.toml`, `package.json`, etc.).
- Feature flags: `--zip`, `--red` (network), `--quiet`, `--redact-keywords`.
- Configuration file support via `krustyk.toml` and `krustyk init` command.
