//! Infrastructure for variable kinds of execution modes (including
//! mocking for testing).

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use crate::command_util::CombinedString;

pub enum ExecutorStatus {
    Success,
    ExitCode(i32),
    Signal(i32),
    ExecFailure(std::io::Error),
}

pub struct ExecutorResult {
    pub status: ExecutorStatus,
    pub combined_output: String,
}
impl ExecutorResult {
    pub fn is_success(&self) -> bool {
        match &self.status {
            ExecutorStatus::Success => true,
            ExecutorStatus::ExitCode(_) => false,
            ExecutorStatus::Signal(_) => false,
            ExecutorStatus::ExecFailure(_) => false,
        }
    }
    pub fn code(&self) -> Option<i32> {
        match &self.status {
            ExecutorStatus::Success => None, // ?
            ExecutorStatus::ExitCode(code) => Some(*code),
            ExecutorStatus::Signal(_) => None,
            ExecutorStatus::ExecFailure(_) => None,
        }
    }
    pub fn signal(&self) -> Option<i32> {
        match &self.status {
            ExecutorStatus::Success => None,
            ExecutorStatus::ExitCode(_) => None,
            ExecutorStatus::Signal(n) => Some(*n),
            ExecutorStatus::ExecFailure(_) => None,
        }
    }
}

pub trait Executor {
    fn execute(&mut self, cmd: &[String]) -> ExecutorResult;
}

pub struct DryExecutor;
impl Executor for DryExecutor {
    fn execute(&mut self, _cmd: &[String]) -> ExecutorResult {
        ExecutorResult {
            status: ExecutorStatus::Success,
            combined_output: "".into(),
        }
    }
}

pub struct RealExecutor;
impl Executor for RealExecutor {
    fn execute(&mut self, cmd: &[String]) -> ExecutorResult {
        let mut command = Command::new(&cmd[0]);
        command.args(&cmd[1..]);
        match command.output() {
            Ok(output) => {
                let status = if output.status.success() {
                    ExecutorStatus::Success
                } else {
                    match output.status.code() {
                        Some(code) => ExecutorStatus::ExitCode(code),
                        None => ExecutorStatus::Signal(output.status.signal().unwrap()),
                    }
                };
                ExecutorResult {
                    status,
                    combined_output: output.combined_string(),
                }
            }
            Err(e) => ExecutorResult {
                status: ExecutorStatus::ExecFailure(e),
                combined_output: "".into(),
            },
        }
    }
}
