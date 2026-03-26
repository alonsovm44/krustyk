use std::env;
use std::process::Command;
use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::Write;
use zip::write::{FileOptions, ZipWriter};
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

/// Scans for common project manifest files in the current directory and reads their content.
fn get_project_files() -> HashMap<String, String> {
    let manifest_files = [
        "Cargo.toml",
        "package.json",
        "requirements.txt",
        "pom.xml",
        "build.gradle",
        "docker-compose.yml",
        "pyproject.toml",
    ];
    let mut found_files = HashMap::new();

    for filename in manifest_files {
        if let Ok(content) = fs::read_to_string(filename) {
            found_files.insert(filename.to_string(), content);
        }
    }

    found_files
}

/// Attempts to fetch the current Git branch, commit hash, and working directory status.
/// Returns None if the current directory is not a Git repository or Git is not installed.
fn get_git_info() -> Option<(String, String, String)> {
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

    let status_output = Command::new("git").args(["status", "--porcelain"]).output().ok()?;
    let status = if status_output.status.success() {
        String::from_utf8_lossy(&status_output.stdout).trim().to_string()
    } else {
        "Failed to get status".to_string()
    };

    Some((branch, commit, status))
}

/// Runs basic network diagnostic commands (ping, traceroute) against common hosts.
fn get_network_diagnostics() -> HashMap<String, String> {
    let mut diagnostics = HashMap::new();
    let targets = [("google_dns", "8.8.8.8"), ("cloudflare_dns", "1.1.1.1")];

    for (name, ip) in &targets {
        // --- PING ---
        let (ping_cmd, ping_args) = if env::consts::OS == "windows" {
            ("ping", vec!["-n", "4", *ip])
        } else {
            ("ping", vec!["-c", "4", *ip])
        };
        let ping_key = format!("ping_{}", name);
        match Command::new(ping_cmd).args(&ping_args).output() {
            Ok(output) => {
                let result = format!(
                    "--- STDOUT ---\n{}\n--- STDERR ---\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                diagnostics.insert(ping_key, result);
            }
            Err(e) => {
                diagnostics.insert(ping_key, format!("Failed to execute command '{}': {}", ping_cmd, e));
            }
        }

        // --- TRACEROUTE ---
        let (trace_cmd, _trace_args) = if env::consts::OS == "windows" {
            ("tracert", vec![*ip])
        } else {
            ("traceroute", vec![*ip])
        };
        let trace_key = format!("trace_{}", name);
        match Command::new(trace_cmd).args(&[ip]).output() {
            Ok(output) => diagnostics.insert(trace_key, String::from_utf8_lossy(&output.stdout).into_owned()),
            Err(e) => diagnostics.insert(trace_key, format!("Failed to execute command '{}': {}", trace_cmd, e)),
        };
    }
    diagnostics
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
    git_status: Option<String>,
    project_files: HashMap<String, String>,
    network_diagnostics: Option<HashMap<String, String>>,
}

impl DebugBundle {
    fn capture(
        command: &str,
        args: &[String],
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
        network_diagnostics: Option<HashMap<String, String>>,
    ) -> Self {
        let git_info = get_git_info();
        let (git_branch, git_commit, git_status) = match git_info {
            Some((b, c, s)) => (Some(b), Some(c), Some(s)),
            None => (None, None, None),
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
            git_status,
            project_files: get_project_files(),
            network_diagnostics,
        }
    }

    fn save_to_file(&self, zip_bundle: bool) {
        let json = match serde_json::to_string_pretty(self) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[KrustyK] => Error serializing bundle: {}", e);
                return;
            }
        };

        if zip_bundle {
            self.save_as_zip(&json);
        } else {
            self.save_as_json(&json);
        }
    }

    fn save_as_json(&self, json_content: &str) {
        let filename = format!("krustyk_bundle_{}.json", self.timestamp);
        if let Err(e) = fs::write(&filename, json_content) {
            eprintln!("[KrustyK] => Error writing bundle to {}: {}", filename, e);
        } else {
            println!("[KrustyK] => Successfully saved debug bundle to {}", filename);
        }
    }

    fn save_as_zip(&self, json_content: &str) {
        let filename = format!("krustyk_bundle_{}.zip", self.timestamp);
        let file = match fs::File::create(&filename) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[KrustyK] => Error creating zip file {}: {}", filename, e);
                return;
            }
        };

        let mut zip = ZipWriter::new(file);
        let options: FileOptions<'_, ()> = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        if let Err(e) = zip.start_file("bundle.json", options) {
            eprintln!("[KrustyK] => Error creating file in zip: {}", e);
            return;
        }
        if let Err(e) = zip.write_all(json_content.as_bytes()) {
            eprintln!("[KrustyK] => Error writing to zip file: {}", e);
            return;
        }
        if let Err(e) = zip.finish() {
            eprintln!("[KrustyK] => Error finishing zip archive: {}", e);
            return;
        }

        println!("[KrustyK] => Successfully saved debug bundle to {}", filename);
    }
}

fn generate_bundle(
    command: &str,
    args: &[String],
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    run_network_diagnostics: bool,
    zip_bundle: bool,
) {
    let net_diags = if run_network_diagnostics {
        println!("[KrustyK] => Running network diagnostics...");
        Some(get_network_diagnostics())
    } else {
        None
    };

    let bundle = DebugBundle::capture(
        command,
        args,
        exit_code,
        stdout,
        stderr,
        net_diags,
    );

    bundle.save_to_file(zip_bundle);
}

fn main() {
    // The first argument is the path to our program, so we skip it.
    let all_args: Vec<String> = env::args().skip(1).collect();
    let mut run_network_diagnostics = false;
    let mut zip_bundle = false;

    let command_args_filtered: Vec<String> = all_args.into_iter().filter(|arg| {
        if arg == "--red" {
            run_network_diagnostics = true;
            false // Exclude the flag from the command args
        } else if arg == "--zip" {
            zip_bundle = true;
            false
        } else {
            true // Keep the argument
        }
    }).collect();

    if command_args_filtered.is_empty() {
        eprintln!("KrustyK: A tool to capture and diagnose command failures.");
        eprintln!("\nUsage: krustyk [--red] [--zip] <command> [args...]");
        eprintln!("   or: cargo run -- [--red] [--zip] <command> [args...]");
        eprintln!("\nFlags:");
        eprintln!("  --red   Run network diagnostics (ping, traceroute) and include them in the bundle.");
        eprintln!("  --zip   Compress the output bundle into a .zip file.");
        eprintln!("\nExample (success): cargo run -- git status");
        eprintln!("Example (failure): cargo run -- powershell -c \"Write-Error 'oh no'; exit 1\"");
        eprintln!("Example (with network diagnostics): cargo run -- --red cargo build");
        return;
    }

    let command_to_run = &command_args_filtered[0];
    let command_args = &command_args_filtered[1..];

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
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                generate_bundle(
                    command_to_run,
                    command_args,
                    output.status.code(),
                    stdout,
                    stderr,
                    run_network_diagnostics,
                    zip_bundle,
                );
            } else {
                println!("[KrustyK] => Command executed successfully.");
            }
        }
        Err(e) => {
            eprintln!("\n------------------------------------");
            eprintln!("[KrustyK] => Critical Error: Failed to execute command '{}'. Reason: {}", command_to_run, e);
            println!("[KrustyK] => Generating debug bundle for execution failure...");
            generate_bundle(command_to_run, command_args, None, String::new(), e.to_string(), run_network_diagnostics, zip_bundle);
        }
    }
}