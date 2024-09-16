//! Infrastructure for variable kinds of execution modes (including
//! mocking for testing).

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use anyhow::bail;

use crate::command_util::CombinedString;
use crate::shell_quote::shell_quote_many;

pub enum ExecutorStatus {
    Success,
    ExitCode(i32),
    Signal(i32),
    ExecFailure(std::io::Error),
}

pub struct ExecutorResult<'t> {
    pub cmd: &'t [String],
    pub status: ExecutorStatus,
    pub combined_output: String,
}
impl<'t> ExecutorResult<'t> {
    pub fn to_anyhow(&self, msg: Option<&str>) -> anyhow::Result<()> {
        let _msg = if let Some(msg) = msg {
            let mut s = String::from(" ");
            s.push_str(msg);
            s
        } else {
            "".into()
        };
        match &self.status {
            ExecutorStatus::Success => Ok(()),
            ExecutorStatus::ExitCode(code) => bail!(
                "command `{}` exited with code {code}{_msg}: {}",
                shell_quote_many(&self.cmd),
                self.combined_output
            ),
            ExecutorStatus::Signal(sig) => bail!(
                "command `{}` was killed by signal {sig:?}{_msg}: {}",
                shell_quote_many(&self.cmd),
                self.combined_output
            ),
            ExecutorStatus::ExecFailure(e) => bail!(
                "command `{}` could not be started{_msg}: {e}",
                shell_quote_many(&self.cmd),
            ),
        }
    }
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
    fn execute<'t>(&mut self, cmd: &'t [String]) -> ExecutorResult<'t>;
}

pub struct DryExecutor;
impl Executor for DryExecutor {
    fn execute<'t>(&mut self, cmd: &'t [String]) -> ExecutorResult<'t> {
        ExecutorResult {
            cmd,
            status: ExecutorStatus::Success,
            combined_output: "".into(),
        }
    }
}

pub struct RealExecutor;
impl Executor for RealExecutor {
    fn execute<'t>(&mut self, cmd: &'t [String]) -> ExecutorResult<'t> {
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
                    cmd,
                    status,
                    combined_output: output.combined_string(),
                }
            }
            Err(e) => ExecutorResult {
                cmd,
                status: ExecutorStatus::ExecFailure(e),
                combined_output: "".into(),
            },
        }
    }
}
