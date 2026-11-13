use anyhow::{Context, Result};
use std::process::Command;
use which::which;

use crate::models::{CommandResult, Platform};

pub struct CommandRunner;

impl CommandRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn run(&self, command: &[&str]) -> Result<CommandResult> {
        if command.is_empty() {
            return Ok(CommandResult {
                returncode: 1,
                stdout: String::new(),
                stderr: "Empty command".to_string(),
            });
        }

        let mut cmd = Command::new(command[0]);
        if command.len() > 1 {
            cmd.args(&command[1..]);
        }

        let output = cmd
            .output()
            .with_context(|| format!("Failed to execute command: {:?}", command))?;

        Ok(CommandResult {
            returncode: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    pub fn run_shell(&self, command: &str) -> Result<CommandResult> {
        let (shell, flag) = if Platform::detect() == Platform::Windows {
            ("cmd", "/C")
        } else {
            ("sh", "-c")
        };

        self.run(&[shell, flag, command])
    }

    pub fn exists(&self, executable: &str) -> bool {
        which(executable).is_ok()
    }

    pub fn run_with_input(&self, command: &[&str], input: &str) -> Result<CommandResult> {
        if command.is_empty() {
            return Ok(CommandResult {
                returncode: 1,
                stdout: String::new(),
                stderr: "Empty command".to_string(),
            });
        }

        let mut cmd = Command::new(command[0]);
        if command.len() > 1 {
            cmd.args(&command[1..]);
        }

        use std::io::Write;
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to spawn command: {:?}", command))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(input.as_bytes())?;
        }

        let output = child.wait_with_output()?;

        Ok(CommandResult {
            returncode: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

impl Default for CommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_runner_exists() {
        let runner = CommandRunner::new();
        assert!(runner.exists("echo"));
        assert!(!runner.exists("this_command_does_not_exist_12345"));
    }

    #[test]
    fn test_run_echo() {
        let runner = CommandRunner::new();
        let result = runner.run(&["echo", "hello"]).unwrap();
        assert_eq!(result.returncode, 0);
        assert_eq!(result.stdout, "hello");
    }
}