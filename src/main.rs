use std::env;
use std::process::Command;
use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::Write;
use zip::write::{FileOptions, ZipWriter};
use zip::result::ZipError;
use serde::{Deserialize, Serialize};

/// Redacts the values of environment variables that appear to be sensitive.
///
/// It checks variable keys against a list of sensitive substrings. If a match is found,
/// the value is replaced with `[REDACTED]`.
fn sanitize_env_vars(vars: HashMap<String, String>, custom_keywords: &Option<Vec<String>>) -> HashMap<String, String> {
    let default_keywords = vec!["KEY".to_string(), "TOKEN".to_string(), "SECRET".to_string(), "PASSWORD".to_string(), "AUTH".to_string()];
    let keywords = custom_keywords.as_ref().unwrap_or(&default_keywords);
    // Prefixes of environment variables injected by cargo that we want to strip out
    let ignore_prefixes = ["CARGO_PKG_", "CARGO_MANIFEST_", "RUSTUP_", "RUST_RECURSION_COUNT"];

    vars.into_iter()
        .filter(|(key, _)| !ignore_prefixes.iter().any(|&prefix| key.starts_with(prefix)))
        .map(|(key, value)| {
            let uppercase_key = key.to_uppercase();
            if keywords.iter().any(|s| uppercase_key.contains(s)) {
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

fn handle_init_command() {
    let config_filename = "krustyk.toml";
    if std::path::Path::new(config_filename).exists() {
        println!("[KrustyK] `krustyk.toml` already exists in this directory.");
        return;
    }

    let default_config_content = r#"# Default configuration for krustyk.
# Uncomment and set values to override default behavior for this project.

# Compress the output bundle into a .zip file. (default: false)
# zip = false

# Suppress all console output from krustyk, printing only the final bundle path. (default: false)
# quiet = false

# Execute commands through the system shell (cmd /C on Windows, sh -c on Unix). (default: false)
# shell = false

# Capture network diagnostics (ping, traceroute). (default: false)
# red = false

# Custom keywords to redact from environment variables.
# By default, krustyk redacts: ["KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"]
# redact-keywords = ["API_KEY", "SESSION_ID", "DATABASE_URL"]
"#;

    match fs::write(config_filename, default_config_content) {
        Ok(_) => println!("[KrustyK] Successfully created `krustyk.toml`."),
        Err(e) => eprintln!("[KrustyK] Error: Failed to create `krustyk.toml`: {}", e),
    }
}

#[derive(Deserialize, Default)]
struct Config {
    zip: Option<bool>,
    quiet: Option<bool>,
    red: Option<bool>,
    shell: Option<bool>,
    #[serde(rename = "redact-keywords")]
    redact_keywords: Option<Vec<String>>,
}

/// Loads configuration from a `krustyk.toml` file in the current directory.
/// If the file doesn't exist or fails to parse, it returns a default config.
fn load_config() -> Config {
    if let Ok(contents) = fs::read_to_string("krustyk.toml") {
        match toml::from_str(&contents) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("[KrustyK] Warning: Failed to parse krustyk.toml: {}", e);
                Config::default()
            }
        }
    } else {
        Config::default()
    }
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
        redact_keywords: &Option<Vec<String>>,
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
            env_vars: sanitize_env_vars(env::vars().collect(), redact_keywords),
            system_logs: get_system_logs(),
            git_branch,
            git_commit,
            git_status,
            project_files: get_project_files(),
            network_diagnostics,
        }
    }

    fn save_to_file(&self, zip_bundle: bool, is_quiet: bool) -> Option<String> {
        let json = match serde_json::to_string_pretty(self) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[KrustyK] => Error serializing bundle: {}", e);
                return None;
            }
        };

        if zip_bundle {
            self.save_as_zip(&json, is_quiet)
        } else {
            self.save_as_json(&json, is_quiet)
        }
    }

    fn save_as_json(&self, json_content: &str, is_quiet: bool) -> Option<String> {
        let filename = format!("krustyk_bundle_{}.json", self.timestamp);
        if let Err(e) = fs::write(&filename, json_content) {
            if !is_quiet {
                eprintln!("[KrustyK] => Error writing bundle to {}: {}", filename, e);
            }
            None
        } else {
            if !is_quiet {
                println!("[KrustyK] => Successfully saved debug bundle to {}", filename);
            }
            Some(filename)
        }
    }

    fn save_as_zip(&self, json_content: &str, is_quiet: bool) -> Option<String> {
    let filename = format!("krustyk_bundle_{}.zip", self.timestamp);
    let file = match fs::File::create(&filename) {
        Ok(f) => f,
        Err(e) => {
            if !is_quiet {
                eprintln!("[KrustyK] => Error creating zip file {}: {}", filename, e);
            }
            return None;
        }
    };

    let mut zip = ZipWriter::new(file);
    let options: FileOptions<'_, ()> = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // Chain the zip operations and handle errors gracefully.
    let result = zip.start_file("bundle.json", options)
        .and_then(|_| {
            zip.write_all(json_content.as_bytes()).map_err(ZipError::from)
        })
        .and_then(|_| zip.finish());

    if let Err(e) = result {
        if !is_quiet {
            eprintln!("[KrustyK] => Error writing to zip archive: {}", e);
        }
        return None;
    }

    if !is_quiet {
        println!("[KrustyK] => Successfully saved debug bundle to {}", filename);
    }
    Some(filename)
}
}

fn print_help() {
    println!("KrustyK: A tool to capture and diagnose command failures.");
    println!("\nUSAGE: krustyk <COMMAND>");
    println!("\nCOMMANDS:");
    println!("    init                    Creates a default krustyk.toml configuration file.");
    println!("    help                    Prints help information.");
    println!("    version                 Prints version information.");
    println!("    <command> [args...]     Runs a command and captures its context on failure. Use '--' to separate flags.");
    println!("\nFLAGS (for running commands):");
    println!("    -h, --help              Prints help information.");
    println!("    -V, --version           Prints version information.");
    println!("    --red                   Run network diagnostics (ping, traceroute).");
    println!("    --zip                   Compress the output bundle into a .zip file.");
    println!("    --quiet                 Suppress all output except for the final bundle path.");
    println!("    -s, --shell             Execute the command through the system shell (cmd /C or sh -c).");
    println!("    --redact-keywords <KW>  Comma-separated list of custom keywords to redact.");
    println!("\nConfiguration:");
    println!("  Default flags can be set in a `krustyk.toml` file in the current directory.");
    println!("\nEXAMPLE:");
    println!("    krustyk --zip -- npm run build");
}

fn main() {
    let config = load_config();
    let all_args: Vec<String> = env::args().skip(1).collect();

    if let Some(first_arg) = all_args.get(0) {
        if first_arg == "init" {
            handle_init_command();
            return;
        } else if first_arg == "help" {
            print_help();
            return;
        } else if first_arg == "version" {
            println!("krustyk {}", env!("CARGO_PKG_VERSION"));
            return;
        }
    }

    let mut run_network_diagnostics = config.red.unwrap_or(false);
    let mut zip_bundle = config.zip.unwrap_or(false);
    let mut is_quiet = config.quiet.unwrap_or(false);
    let mut use_shell = config.shell.unwrap_or(false);
    let mut custom_redact_keywords: Option<Vec<String>> = config.redact_keywords;

    let mut command_args_filtered: Vec<String> = Vec::new();
    let mut args_iter = all_args.into_iter();

    while let Some(arg) = args_iter.next() {
        if arg == "--" {
            command_args_filtered.extend(args_iter);
            break;
        }

        if arg == "--help" || arg == "-h" {
            print_help();
            return;
        } else if arg == "--version" || arg == "-V" {
            println!("krustyk {}", env!("CARGO_PKG_VERSION"));
            return;
        } else if arg == "--red" {
            run_network_diagnostics = true;
        } else if arg == "--zip" {
            zip_bundle = true;
        } else if arg == "--quiet" {
            is_quiet = true;
        } else if arg == "--shell" || arg == "-s" {
            use_shell = true;
        } else if arg == "--redact-keywords" {
            if let Some(value) = args_iter.next() {
                custom_redact_keywords = Some(value.split(',').map(|s| s.trim().to_uppercase()).collect());
            } else {
                eprintln!("[KrustyK] Error: --redact-keywords flag requires a comma-separated list of keywords.");
                return;
            }
        } else {
            // First argument that isn't a krustyk flag is the start of the command
            command_args_filtered.push(arg);
            command_args_filtered.extend(args_iter);
            break;
        }
    }

    if command_args_filtered.is_empty() {
        print_help();
        return;
    }

    let display_cmd = command_args_filtered[0].clone();
    let display_args = command_args_filtered[1..].to_vec();

    let (exec_cmd, exec_args) = if use_shell {
        let shell = if env::consts::OS == "windows" { "cmd" } else { "sh" };
        let shell_flag = if env::consts::OS == "windows" { "/C" } else { "-c" };
        let full_command = command_args_filtered.join(" ");
        (shell.to_string(), vec![shell_flag.to_string(), full_command])
    } else {
        (display_cmd.clone(), display_args.clone())
    };

    if !is_quiet {
        if use_shell {
            println!("[KrustyK] Executing via shell: {}", command_args_filtered.join(" "));
        } else {
            println!("[KrustyK] Executing: {} {}", exec_cmd, exec_args.join(" "));
        }
        println!("------------------------------------");
    }

    // The actual command execution and output capture
    let output = Command::new(&exec_cmd).args(&exec_args).output();

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

            if !is_quiet {
                println!("\n------------------------------------");
                println!("[KrustyK] Exit Code: {}", output.status);
            }

            if !output.status.success() {
                if !is_quiet {
                    println!("[KrustyK] => Command failed! Generating debug bundle...");
                }
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                
                let net_diags = if run_network_diagnostics {
                    if !is_quiet {
                        println!("[KrustyK] => Running network diagnostics...");
                    }
                    Some(get_network_diagnostics())
                } else {
                    None
                };

                let bundle = DebugBundle::capture(
                    &display_cmd,
                    &display_args,
                    output.status.code(),
                    stdout,
                    stderr,
                    net_diags,
                    &custom_redact_keywords,
                );

                if let Some(path) = bundle.save_to_file(zip_bundle, is_quiet) {
                    if is_quiet {
                        println!("{}", path);
                    }
                }
            } else {
                if !is_quiet {
                    println!("[KrustyK] => Command executed successfully.");
                }
            }
        }
        Err(e) => {
            if !is_quiet {
                eprintln!("\n------------------------------------");
                eprintln!("[KrustyK] => Critical Error: Failed to execute command '{}'. Reason: {}", exec_cmd, e);
                println!("[KrustyK] => Generating debug bundle for execution failure...");
            }
            let bundle = DebugBundle::capture(&display_cmd, &display_args, None, String::new(), e.to_string(), None, &custom_redact_keywords);
            if let Some(path) = bundle.save_to_file(zip_bundle, is_quiet) {
                if is_quiet {
                    println!("{}", path);
                }
            }
        }
    }
}