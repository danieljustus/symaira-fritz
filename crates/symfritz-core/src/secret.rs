#![deny(unsafe_code)]

//! Secret and credential resolution for symfritz.
//!
//! Resolution order (highest priority first):
//! 1. Explicit environment variable (`SYMFRITZ_PASSWORD`)
//! 2. `symvault` reference (invokes `symvault get <ref> --print`)
//! 3. macOS Keychain (invokes `security find-generic-password`)
//! 4. Plaintext value from config file
//!
//! Configured backends fail closed: an error from a configured backend
//! terminates resolution immediately rather than silently falling back
//! to less secure options.
//!
//! Subprocess commands receive secret values exclusively through standard input
//! and never in command-line arguments to prevent leakage in process tables (`ps aux`).

use std::{
    io::{Read, Write},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

/// Service name used for macOS Keychain entries.
pub const KEYCHAIN_SERVICE: &str = "symfritz";

/// Label identifying where a resolved credential originated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    #[serde(rename = "env")]
    Env,
    #[serde(rename = "symvault")]
    Symvault,
    #[serde(rename = "keychain")]
    Keychain,
    #[serde(rename = "config")]
    Config,
    #[serde(rename = "none")]
    None,
}

impl std::fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env => write!(f, "env"),
            Self::Symvault => write!(f, "symvault"),
            Self::Keychain => write!(f, "keychain"),
            Self::Config => write!(f, "config"),
            Self::None => write!(f, "none"),
        }
    }
}

/// Options configuring credential resolution.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretOptions {
    /// Environment variable name to check first (e.g. `SYMFRITZ_PASSWORD`).
    pub env_var: Option<String>,
    /// `symvault` reference path (e.g. `fritz.password`).
    pub password_ref: Option<String>,
    /// Whether to consult the macOS Keychain.
    pub keychain: bool,
    /// Account name for Keychain lookup (defaults to box host when empty).
    pub keychain_account: Option<String>,
    /// Plaintext fallback password from config file.
    pub plaintext: Option<String>,
}

impl std::fmt::Debug for SecretOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretOptions")
            .field("env_var", &self.env_var)
            .field("password_ref", &self.password_ref)
            .field("keychain", &self.keychain)
            .field("keychain_account", &self.keychain_account)
            .field("plaintext", &self.plaintext.as_ref().map(|_| "REDACTED"))
            .finish()
    }
}

impl From<&crate::config::BoxConfig> for SecretOptions {
    fn from(box_cfg: &crate::config::BoxConfig) -> Self {
        let account = if box_cfg.keychain_account.is_empty() {
            if box_cfg.host.is_empty() {
                None
            } else {
                Some(box_cfg.host.clone())
            }
        } else {
            Some(box_cfg.keychain_account.clone())
        };

        Self {
            env_var: Some("SYMFRITZ_PASSWORD".to_string()),
            password_ref: if box_cfg.password_ref.is_empty() {
                None
            } else {
                Some(box_cfg.password_ref.clone())
            },
            keychain: box_cfg.keychain,
            keychain_account: account,
            plaintext: if box_cfg.password.is_empty() {
                None
            } else {
                Some(box_cfg.password.clone())
            },
        }
    }
}

/// A resolved credential value and its origin.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretResult {
    pub password: String,
    pub source: CredentialSource,
}

impl std::fmt::Debug for SecretResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretResult")
            .field("password", &"REDACTED")
            .field("source", &self.source)
            .finish()
    }
}

/// Errors occurring during credential resolution or backend operations.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    NotInstalled(String),
    Symvault(String),
    Keychain(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled(msg) => write!(f, "backend CLI not installed: {}", msg),
            Self::Symvault(msg) => write!(f, "{}", msg),
            Self::Keychain(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SecretError {}

/// Abstract interface for secret backends, allowing stubbing in tests.
pub trait SecretBackend {
    fn symvault_get(&self, reference: &str) -> Result<String, SecretError>;
    fn keychain_get(&self, service: &str, account: Option<&str>) -> Result<String, SecretError>;
}

/// Default system implementation that invokes external CLIs.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSecretBackend;

impl SecretBackend for SystemSecretBackend {
    fn symvault_get(&self, reference: &str) -> Result<String, SecretError> {
        symvault_get(reference)
    }

    fn keychain_get(&self, service: &str, account: Option<&str>) -> Result<String, SecretError> {
        keychain_get(service, account)
    }
}

/// Resolves password with injected backend and environment lookup.
///
/// Credential priority:
/// 1. Environment variable (`opts.env_var`)
/// 2. `symvault` (`opts.password_ref`)
/// 3. Keychain (`opts.keychain`)
/// 4. Plaintext (`opts.plaintext`)
///
/// A failing configured backend terminates resolution and returns an error.
pub fn resolve_with_backend<B: SecretBackend, E: Fn(&str) -> Option<String>>(
    opts: &SecretOptions,
    backend: &B,
    get_env: E,
) -> Result<SecretResult, SecretError> {
    if let Some(val) = opts
        .env_var
        .as_deref()
        .filter(|key| !key.is_empty())
        .and_then(get_env)
        .filter(|value| !value.is_empty())
    {
        return Ok(SecretResult {
            password: val,
            source: CredentialSource::Env,
        });
    }

    if let Some(reference) = opts
        .password_ref
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        let val = backend.symvault_get(reference).map_err(|err| {
            SecretError::Symvault(format!("symvault get {:?}: {}", reference, err))
        })?;
        return Ok(SecretResult {
            password: val,
            source: CredentialSource::Symvault,
        });
    }

    if opts.keychain {
        let account = opts.keychain_account.as_deref();
        let val = backend
            .keychain_get(KEYCHAIN_SERVICE, account)
            .map_err(|err| SecretError::Keychain(format!("keychain lookup: {}", err)))?;
        return Ok(SecretResult {
            password: val,
            source: CredentialSource::Keychain,
        });
    }

    if let Some(plain) = opts.plaintext.as_deref().filter(|value| !value.is_empty()) {
        return Ok(SecretResult {
            password: plain.to_owned(),
            source: CredentialSource::Config,
        });
    }

    Ok(SecretResult {
        password: String::new(),
        source: CredentialSource::None,
    })
}

/// Resolves credentials using system backends and process environment.
pub fn resolve(opts: &SecretOptions) -> Result<SecretResult, SecretError> {
    resolve_with_backend(opts, &SystemSecretBackend, |k| std::env::var(k).ok())
}

/// Subprocess argument and stdin formatting contracts.
pub struct SymvaultCommand;

impl SymvaultCommand {
    #[must_use]
    pub fn get_args(reference: &str) -> Vec<String> {
        vec![
            "get".to_string(),
            reference.to_string(),
            "--print".to_string(),
        ]
    }

    #[must_use]
    pub fn set_args(reference: &str) -> Vec<String> {
        vec![
            "set".to_owned(),
            reference.to_owned(),
            "--stdin-value".to_owned(),
        ]
    }

    #[must_use]
    pub fn set_stdin_payload(value: &str) -> String {
        format!("{}\n", value)
    }
}

/// macOS Keychain subprocess argument and stdin formatting contracts.
pub struct KeychainCommand;

impl KeychainCommand {
    #[must_use]
    pub fn get_args(service: &str, account: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "find-generic-password".to_string(),
            "-s".to_string(),
            service.to_string(),
            "-w".to_string(),
        ];
        if let Some(acc) = account.filter(|value| !value.is_empty()) {
            args.push("-a".to_string());
            args.push(acc.to_string());
        }
        args
    }

    #[must_use]
    pub fn set_args() -> Vec<String> {
        vec!["-i".to_owned(), "-q".to_owned()]
    }

    #[must_use]
    pub fn set_stdin_payload(service: &str, account: Option<&str>, value: &str) -> String {
        let mut command = format!(
            "add-generic-password -U -s {}",
            security_interactive_quote(service)
        );
        if let Some(account) = account.filter(|value| !value.is_empty()) {
            command.push_str(" -a ");
            command.push_str(&security_interactive_quote(account));
        }
        format!("{command} -X {}\n", hex::encode(value))
    }
}

struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum CommandError {
    Spawn(String),
    Io(String),
    Wait(String),
    Timeout,
}

const SECRET_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(unix)]
fn terminate_descendants(pid: u32) {
    let _ = Command::new("pkill")
        .args(["-TERM", "-P", &pid.to_string()])
        .status();
}

#[cfg(not(unix))]
fn terminate_descendants(_pid: u32) {}

fn run_command(
    program: &str,
    args: &[String],
    stdin_payload: Option<&[u8]>,
    timeout: Duration,
) -> Result<CommandOutput, CommandError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin_payload.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CommandError::Spawn(error.to_string()))?;

    if let Some(payload) = stdin_payload
        && let Some(mut stdin) = child.stdin.take()
        && let Err(error) = stdin.write_all(payload)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CommandError::Io(error.to_string()));
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CommandError::Io("missing stdout pipe".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CommandError::Io("missing stderr pipe".to_owned()))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(1024 * 1024).read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(1024 * 1024).read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    });

    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if started.elapsed() >= timeout => {
                terminate_descendants(child.id());
                let _ = child.kill();
                let status = child
                    .wait()
                    .map_err(|error| CommandError::Wait(error.to_string()))?;
                break (status, true);
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                terminate_descendants(child.id());
                let _ = child.kill();
                let _ = child.wait();
                return Err(CommandError::Wait(error.to_string()));
            }
        }
    };
    if timed_out {
        // Do not wait on a descendant that inherited stdout/stderr. The
        // process itself is killed above and the reader threads are bounded by
        // the one-megabyte capture limit.
        return Err(CommandError::Timeout);
    }
    let stdout = stdout_reader
        .join()
        .map_err(|_| CommandError::Io("stdout reader panicked".to_owned()))?
        .map_err(|error| CommandError::Io(error.to_string()))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| CommandError::Io("stderr reader panicked".to_owned()))?
        .map_err(|error| CommandError::Io(error.to_string()))?;

    if started.elapsed() >= timeout && status.success() {
        // A process that exits exactly at the deadline is still successful.
        return Ok(CommandOutput {
            status,
            stdout,
            stderr,
        });
    }
    if started.elapsed() >= timeout {
        return Err(CommandError::Timeout);
    }
    Ok(CommandOutput {
        status,
        stdout,
        stderr,
    })
}

/// Reads password from `symvault get <ref> --print`.
pub fn symvault_get(reference: &str) -> Result<String, SecretError> {
    let args = SymvaultCommand::get_args(reference);
    let output =
        run_command("symvault", &args, None, SECRET_COMMAND_TIMEOUT).map_err(
            |error| match error {
                CommandError::Spawn(message) => {
                    SecretError::NotInstalled(format!("symvault: {message}"))
                }
                CommandError::Timeout => {
                    SecretError::Symvault("symvault command timed out".to_owned())
                }
                CommandError::Io(message) | CommandError::Wait(message) => {
                    SecretError::Symvault(format!("symvault error: {message}"))
                }
            },
        )?;

    if !output.status.success() {
        let stdout_value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let msg = redact_secret_output(
            String::from_utf8_lossy(&output.stderr).trim(),
            &stdout_value,
        );
        let err_msg = if msg.is_empty() {
            format!("exit status {}", output.status)
        } else {
            msg
        };
        return Err(SecretError::Symvault(err_msg));
    }

    let val = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(&['\r', '\n'][..])
        .to_string();

    if val.is_empty() {
        return Err(SecretError::Symvault(format!(
            "symvault returned an empty value for {:?}",
            reference
        )));
    }

    Ok(val)
}

/// Stores password into `symvault set <ref>` over stdin.
/// Secret value is NEVER included in argv.
pub fn symvault_set(reference: &str, value: &str) -> Result<(), SecretError> {
    let args = SymvaultCommand::set_args(reference);
    let payload = SymvaultCommand::set_stdin_payload(value);
    let output = run_command(
        "symvault",
        &args,
        Some(payload.as_bytes()),
        SECRET_COMMAND_TIMEOUT,
    )
    .map_err(|error| match error {
        CommandError::Spawn(message) => SecretError::NotInstalled(format!("symvault: {message}")),
        CommandError::Timeout => SecretError::Symvault("symvault command timed out".to_owned()),
        CommandError::Io(message) | CommandError::Wait(message) => {
            SecretError::Symvault(format!("symvault error: {message}"))
        }
    })?;

    if !output.status.success() {
        let msg = redact_secret_output(String::from_utf8_lossy(&output.stderr).trim(), value);
        let err_msg = if msg.is_empty() {
            format!("exit status {}", output.status)
        } else {
            msg
        };
        return Err(SecretError::Symvault(format!(
            "symvault set {:?}: {}",
            reference, err_msg
        )));
    }

    Ok(())
}

/// Reads password from macOS Keychain.
pub fn keychain_get(service: &str, account: Option<&str>) -> Result<String, SecretError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, account);
        Err(SecretError::NotInstalled(
            "keychain is macOS-only".to_string(),
        ))
    }

    #[cfg(target_os = "macos")]
    {
        let args = KeychainCommand::get_args(service, account);
        let output =
            run_command("security", &args, None, SECRET_COMMAND_TIMEOUT).map_err(|error| {
                match error {
                    CommandError::Spawn(message) => {
                        SecretError::NotInstalled(format!("security: {message}"))
                    }
                    CommandError::Timeout => {
                        SecretError::Keychain("keychain command timed out".to_owned())
                    }
                    CommandError::Io(message) | CommandError::Wait(message) => {
                        SecretError::Keychain(format!("keychain error: {message}"))
                    }
                }
            })?;

        if !output.status.success() {
            return Err(SecretError::Keychain(format!(
                "keychain entry not found (service {:?} account {:?})",
                service,
                account.unwrap_or("")
            )));
        }

        let val = String::from_utf8_lossy(&output.stdout)
            .trim_end_matches(&['\r', '\n'][..])
            .to_string();

        Ok(val)
    }
}

/// Stores a hex-encoded password through `security` interactive stdin.
/// The secret value is never included in process arguments.
pub fn keychain_set(service: &str, account: Option<&str>, value: &str) -> Result<(), SecretError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, account, value);
        Err(SecretError::NotInstalled(
            "keychain is macOS-only".to_string(),
        ))
    }

    #[cfg(target_os = "macos")]
    {
        let args = KeychainCommand::set_args();
        let payload = KeychainCommand::set_stdin_payload(service, account, value);
        let output = run_command(
            "security",
            &args,
            Some(payload.as_bytes()),
            SECRET_COMMAND_TIMEOUT,
        )
        .map_err(|error| match error {
            CommandError::Spawn(message) => {
                SecretError::NotInstalled(format!("security: {message}"))
            }
            CommandError::Timeout => SecretError::Keychain("keychain command timed out".to_owned()),
            CommandError::Io(message) | CommandError::Wait(message) => {
                SecretError::Keychain(format!("keychain error: {message}"))
            }
        })?;

        if !output.status.success() {
            let msg = redact_secret_output(String::from_utf8_lossy(&output.stderr).trim(), value);
            let err_msg = if msg.is_empty() {
                format!("exit status {}", output.status)
            } else {
                msg
            };
            return Err(SecretError::Keychain(format!(
                "keychain store failed: {}",
                err_msg
            )));
        }

        Ok(())
    }
}

/// Checks if `symvault` binary is in PATH.
#[must_use]
pub fn symvault_available() -> bool {
    which_binary("symvault")
}

/// Checks if macOS `security` binary is available.
#[must_use]
pub fn keychain_available() -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
    #[cfg(target_os = "macos")]
    {
        which_binary("security")
    }
}

fn which_binary(name: &str) -> bool {
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for candidate in binary_names(name) {
                if is_executable(&dir.join(candidate)) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(not(windows))]
fn binary_names(name: &str) -> Vec<String> {
    vec![name.to_owned()]
}

#[cfg(windows)]
fn binary_names(name: &str) -> Vec<String> {
    if std::path::Path::new(name).extension().is_some() {
        return vec![name.to_owned()];
    }
    let extensions = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned());
    extensions
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(|extension| format!("{name}{extension}"))
        .collect()
}

#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &std::path::Path) -> bool {
    path.is_file()
}

fn security_interactive_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn redact_secret_output(message: &str, secret: &str) -> String {
    if secret.is_empty() {
        return message.to_owned();
    }
    let hex_secret = hex::encode(secret);
    message
        .replace(secret, "REDACTED")
        .replace(&hex_secret, "REDACTED")
        .replace(&hex_secret.to_ascii_uppercase(), "REDACTED")
}

#[cfg(test)]
mod tests {
    use super::{redact_secret_output, security_interactive_quote};

    #[test]
    fn interactive_values_escape_quotes_and_backslashes() {
        assert_eq!(
            security_interactive_quote("router\\\"admin"),
            "\"router\\\\\\\"admin\""
        );
    }

    #[test]
    fn subprocess_errors_redact_plaintext_and_hex_secret_material() {
        let secret = "sensitive-test-value";
        let encoded = hex::encode(secret);
        let message = format!(
            "plain={secret} hex={encoded} upper={}",
            encoded.to_ascii_uppercase()
        );
        let redacted = redact_secret_output(&message, secret);
        assert_eq!(redacted, "plain=REDACTED hex=REDACTED upper=REDACTED");
        assert!(!redacted.contains(secret));
    }

    #[cfg(unix)]
    #[test]
    fn hanging_backend_is_killed_within_injected_deadline_without_error_output() {
        let result = super::run_command(
            "/bin/sh",
            &[
                "-c".to_owned(),
                "printf super-secret >&2; sleep 10".to_owned(),
            ],
            None,
            std::time::Duration::from_millis(50),
        );
        assert!(matches!(result, Err(super::CommandError::Timeout)));
    }

    #[cfg(unix)]
    #[test]
    fn executable_check_rejects_plain_files() {
        use std::os::unix::fs::PermissionsExt;

        let path =
            std::env::temp_dir().join(format!("symfritz-executable-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"test").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!super::is_executable(&path));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(super::is_executable(&path));
        std::fs::remove_file(path).unwrap();
    }
}
