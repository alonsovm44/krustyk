use std::env;
use std::process::Command;
use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Serialize;

/// Redacts the values of environment variables that appear to be sensitive.
///
/// It checks variable keys against a list of sensitive substrings. If a match is found,
/// the value is replaced with `[REDACTED]`.
fn sanitize_env_vars(vars: HashMap<String, String>) -> HashMap<String, String> {
    let sensitive_keywords = ["KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"];
    // Prefixes of environment variables injected by cargo that we want to strip out
    let ignore_prefixes = ["CARGO_PKG_", "CARGO_MANIFEST_", "RUSTUP_", "RUST_RECURSION_COUNT"];

    vars.into_iter()
        .filter(|(key, _)| !ignore_prefixes.iter().any(|&prefix| key.starts_with(prefix)))
        .map(|(key, value)| {
            let uppercase_key = key.to_uppercase();
            if sensitive_keywords.iter().any(|&s| uppercase_key.contains(s)) {
                (key, "[REDACTED]".to_string())
            } else {
                (key, value)
            }
        })
        .collect()
}

/// Attempts to fetch the last 50 lines of system logs based on the OS.
fn get_system_logs() -> String {
    let (cmd, args) = match env::consts::OS {
        "windows" => ("powershell", vec!["-NoProfile", "-Command", "Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue | Out-String"]),
        "linux" => ("journalctl", vec!["-n", "50", "--no-pager"]),
        "macos" => ("tail", vec!["-n", "50", "/var/log/system.log"]),
        _ => return String::from("System logs capture not supported for this OS."),
    };

    match Command::new(cmd).args(&args).output() {
        Ok(output) if output.status.success() => {
            let logs = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if logs.is_empty() {
                "Log command succeeded but returned no output.".to_string()
            } else {
                logs
            }
        }
        Ok(output) => format!("Log command failed. Stderr: {}", String::from_utf8_lossy(&output.stderr)),
        Err(e) => format!("Failed to execute log command ({}): {}", cmd, e),
    }
}

/// Attempts to fetch the current Git branch and commit hash.
/// Returns None if the current directory is not a Git repository or Git is not installed.
fn get_git_info() -> Option<(String, String)> {
    let branch_output = Command::new("git").args(["rev-parse", "--abbrev-ref", "HEAD"]).output().ok()?;
    if !branch_output.status.success() {
        return None;
    }
    let branch = String::from_utf8_lossy(&branch_output.stdout).trim().to_string();

    let commit_output = Command::new("git").args(["rev-parse", "HEAD"]).output().ok()?;
    if !commit_output.status.success() {
        return None;
    }
    let commit = String::from_utf8_lossy(&commit_output.stdout).trim().to_string();

    Some((branch, commit))
}

// This struct acts as our "frozen environment" container
#[derive(Debug, Serialize)]
struct DebugBundle {
    timestamp: u64,
    command: String,
    args: Vec<String>,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    os: String,
    arch: String,
    working_directory: String,
    env_vars: HashMap<String, String>,
    system_logs: String,
    git_branch: Option<String>,
    git_commit: Option<String>,
}

impl DebugBundle {
    fn capture(command: &str, args: &[String], exit_code: Option<i32>, stdout: String, stderr: String) -> Self {
        let git_info = get_git_info();
        let (git_branch, git_commit) = match git_info {
            Some((b, c)) => (Some(b), Some(c)),
            None => (None, None),
        };

        Self {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            command: command.to_string(),
            args: args.to_vec(),
            exit_code,
            stdout,
            stderr,
            os: env::consts::OS.to_string(),
            arch: env::consts::ARCH.to_string(),
            working_directory: env::current_dir().map(|p| p.display().to_string()).unwrap_or_else(|_| "Unknown".to_string()),
            // Collect and sanitize environment variables
            env_vars: sanitize_env_vars(env::vars().collect()),
            system_logs: get_system_logs(),
            git_branch,
            git_commit,
        }
    }

    fn save_to_file(&self) {
        let filename = format!("krustyk_bundle_{}.json", self.timestamp);
        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                if let Err(e) = fs::write(&filename, json) {
                    eprintln!("[KrustyK] => Error writing bundle to {}: {}", filename, e);
                } else {
                    println!("[KrustyK] => Successfully saved debug bundle to {}", filename);
                }
            }
            Err(e) => eprintln!("[KrustyK] => Error serializing bundle: {}", e),
        }
    }
}

fn main() {
    // The first argument is the path to our program, so we skip it.
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("KrustyK: A tool to capture and diagnose command failures.");
        eprintln!("\nUsage: cargo run -- <command> [args...]");
        eprintln!("   or: krustyk <command> [args...]");
        eprintln!("\nExample (success): cargo run -- git status");
        eprintln!("Example (failure): cargo run -- powershell -c \"Write-Error 'oh no'; exit 1\"");
        return;
    }

    let command_to_run = &args[0];
    let command_args = &args[1..];

    println!("[KrustyK] Executing: {} {}", command_to_run, command_args.join(" "));
    println!("------------------------------------");

    // The actual command execution and output capture
    let output = Command::new(command_to_run).args(command_args).output();

    // After execution, we process the result
    match output {
        Ok(output) => {
            // We stream the original stdout/stderr to make our tool feel transparent
            if !output.stdout.is_empty() {
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
            }

            println!("\n------------------------------------");
            println!("[KrustyK] Exit Code: {}", output.status);

            if !output.status.success() {
                println!("[KrustyK] => Command failed! Generating debug bundle...");
                
                let bundle = DebugBundle::capture(
                    command_to_run,
                    command_args,
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout).into_owned(),
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                );
                
                // Serialize and save the frozen environment state
                bundle.save_to_file();
            } else {
                println!("[KrustyK] => Command executed successfully.");
            }
        }
        Err(e) => {
            // This block handles cases where the command couldn't even start (e.g., not found).
            eprintln!("\n------------------------------------");
            eprintln!("[KrustyK] => Critical Error: Failed to execute command '{}'. Reason: {}", command_to_run, e);
            println!("[KrustyK] => Generating debug bundle for execution failure...");
            
            let bundle = DebugBundle::capture(
                command_to_run, command_args, None, String::new(), e.to_string()
            );
            bundle.save_to_file();
        }
    }
}