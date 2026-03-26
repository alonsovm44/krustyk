AI-Powered Terminal Error Capture

I am building a lightweight tool that solves a common and frustrating problem: when a script or command fails on another machine, the error is hard to understand, reproduce, and fix.

Problem

Terminal errors are:

incomplete or cryptic
highly dependent on environment (OS, variables, dependencies)
difficult to transfer across machines
poorly suited for AI-based debugging due to lack of structured context
Solution

A lightweight CLI wrapper tool. The workflow is simple:
1. User runs a command that produces an error.
2. User prepends `krustyk` to the command and runs it again.
3. `krustyk` executes the command, captures the output, and generates a structured bundle.

When wrapping a command, it:
- Detects when the command fails (non-zero exit code)
- Captures the full execution context
- Generates a structured AI Debug Bundle Output

Each failure produces a portable bundle containing:

executed command
full stdout and stderr
exit code
system information (OS, shell, working directory)
relevant environment variables (sanitized)
dependency versions
key project files
Goal

Enable an AI agent to:

diagnose the root cause
explain the error clearly
suggest or generate a fix
optionally reproduce the issue
Key Differentiator

This is not traditional logging.

It transforms terminal errors into structured, machine-readable context that AI systems can actually understand and act on, addressing one of the main limitations of current coding assistants: lack of real execution context.

Real Use Case

A script works on my machine but fails on another.
Instead of relying on screenshots or incomplete logs, I receive a structured bundle that my AI agent can analyze and use to resolve the issue.

Vision

Evolve into self-healing systems where:
failure → bundle → AI analysis → automatic fix

MVP Scope
CLI wrapper implementation
Failure detection
Basic bundle generation
Initial AI integration

In short, this tool turns ephemeral terminal failures into persistent, actionable artifacts that AI can use to diagnose and fix problems.