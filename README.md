# Krustyk

**Krustyk is a CLI tool that captures the complete context of command-line failures into a structured, portable debug bundle for AI-driven analysis.**

It wraps any command, and if it fails, it generates a detailed JSON or ZIP file containing everything needed to diagnose the problem, turning ephemeral terminal errors into actionable artifacts.

## The Problem

Diagnosing command-line errors, especially on remote machines or in CI/CD pipelines, is frustrating. Error messages are often cryptic and lack context. You're left wondering:
- What was the exact state of the environment?
- Which version of the code was running?
- Were there any uncommitted changes?
- Was there a network issue?

Relying on incomplete logs or screenshots makes it nearly impossible for you—or an AI assistant—to reliably find the root cause.

## How It Works

`krustyk` simplifies this process into an explicit workflow:

1.  You run a command and it fails: `npm run build`
2.  You prepend `krustyk` to the same command: `krustyk npm run build`
3.  `krustyk` executes your command, and upon failure, generates a `krustyk_bundle_...json` file with the complete execution context.

This bundle can then be given to an AI coding assistant for precise analysis and a suggested fix.

## Usage
```sh
# Basic usage
krustyk <your_command> [args...]

```

### Flags
You can enhance the capture with the following flags:

-   `--red`: Captures network diagnostics (ping, traceroute) to common hosts.
-   `--zip`: Compresses the final JSON bundle into a `.zip` file for easy sharing.
-   `--quiet`: Suppresses `krustyk`'s own output, printing only the final bundle path.
-   `--shell`, `-s`: Executes the command through the system's shell (`cmd /C` or `sh -c`), which is necessary for commands containing pipes (`|`) or redirects (`>`). You **must** quote your command when using this.
-   `--redact-keywords <KEYWORDS>`: Comma-separated list of custom keywords to redact.

**Example:**
```sh
# Run a failing command, capture network info, and zip the result
krustyk --red --zip powershell -c "Invoke-WebRequest 'http://invalid-url'; exit 1"

# Run a command with pipes by using quotes and the --shell flag
krustyk --shell -- "npm run build | tee log.txt"
```

## What's in the Bundle?

Each bundle is a comprehensive snapshot of the failure environment, including:

-   **Execution Details**: The exact command, its arguments, `stdout`, `stderr`, and exit code.
-   **System Context**: Operating System, architecture, and the working directory.
-   **Environment Variables**: A sanitized list of all environment variables.
-   **System Logs**: The last 50 lines from the system's event log (`journalctl`, `Get-WinEvent`).
-   **Git Status**: The current branch, commit hash, and a list of uncommitted changes (`git status --porcelain`).
-   **Project Files**: Contents of key manifest files like `package.json`, `Cargo.toml`, `requirements.txt`, etc.
-   **Network Diagnostics** (optional): Output from `ping` and `traceroute`.

## Vision

The ultimate goal is to create a feedback loop where failures are automatically captured, analyzed by an AI, and potentially fixed without human intervention.

`failure` → `krustyk bundle` → `AI analysis` → `automatic fix`