use anyhow::{anyhow, bail, Result};
use std::fmt::{Debug, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use crate::command_util::CombinedString;

pub fn write_str(out: &mut String, s: &str) {
    out.write_str(s).unwrap(); // can't ever fail, no?
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    // enumn::N, PartialOrd, Ord,
    strum::EnumCount,
    strum::EnumString,
    strum::IntoStaticStr,
)]
pub enum Table {
    #[strum(serialize = "filter")]
    Filter,
    #[strum(serialize = "nat")]
    Nat,
    #[strum(serialize = "mangle")]
    Mangle,
    #[strum(serialize = "raw")]
    Raw,
    #[strum(serialize = "security")]
    Security,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    // enumn::N, PartialOrd, Ord,
    strum::EnumCount,
    strum::EnumString,
    strum::IntoStaticStr,
)]
pub enum Action {
    Append,
    Delete,
    /// Insert is holding a 1-based index
    Insert(u32),
    Check,
    NewChain,
    DeleteChain,
    Flush,
}
impl Action {
    /// For collecting the arguments for the iptables command.
    pub fn push_args(&self, chain_name: String, out: &mut Vec<String>) {
        let normal = |name: &str| {
            out.push(name.into());
            out.push(chain_name);
        };
        match self {
            Action::Append => normal("-A"),
            Action::Delete => normal("-D"),
            Action::Insert(n) => {
                normal("-I");
                out.push(format!("{n}"));
            }
            Action::Check => normal("-C"),
            Action::NewChain => normal("-N"),
            Action::DeleteChain => normal("-X"),
            Action::Flush => normal("-F"),
        }
    }

    /// The sequence of actions that are *removing* the original
    /// action. `None` if the action is not one that creates
    /// something.
    pub fn deletion_sequence(&self) -> Option<&[Action]> {
        match self {
            Action::Append => Some(&[Action::Delete]),
            Action::Delete => None,
            Action::Insert(_) => Some(&[Action::Delete]),
            Action::Check => None,
            Action::NewChain => Some(&[Action::Flush, Action::DeleteChain]),
            Action::DeleteChain => None,
            Action::Flush => None,
        }
    }

    pub fn is_creation(&self) -> bool {
        self.deletion_sequence().is_some()
    }
}

pub trait TablechainTrait {
    fn chain_name(&self) -> String;
    fn table_and_chain_names(&self) -> (String, String);

    /// For collecting the arguments for the iptables command.
    fn push_args(&self, action: Action, out: &mut Vec<String>) {
        let (table_name, chain_name) = self.table_and_chain_names();
        out.push("-t".into());
        out.push(table_name.into());
        action.push_args(chain_name, out);
    }
}

macro_rules! def_chain {
    { $typename:tt } => {
        impl TablechainTrait for $typename {
            fn chain_name(&self) -> String {
                let name: &'static str = self.into();
                match self {
                    $typename::Custom(s) => s.into(),
                    _ => name.into()
                }
            }
            fn table_and_chain_names(&self) -> (String, String) {
                (
                    String::from(stringify!($typename)).to_lowercase(),
                    self.chain_name()
                )
            }
        }
        impl From<$typename> for TablechainEnum {
            fn from(value: $typename) -> Self {
                TablechainEnum::$typename(value)
            }
        }
    }
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    // enumn::N, PartialOrd, Ord,
    strum::EnumCount,
    strum::EnumString,
    strum::IntoStaticStr,
)]
pub enum Filter {
    INPUT,
    FORWARD,
    OUTPUT,
    Custom(String),
}
def_chain!(Filter);

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    // enumn::N, PartialOrd, Ord,
    strum::EnumCount,
    strum::EnumString,
    strum::IntoStaticStr,
)]
pub enum Nat {
    PREROUTING,
    INPUT,
    OUTPUT,
    POSTROUTING,
    Custom(String),
}
def_chain!(Nat);

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    // enumn::N, PartialOrd, Ord,
    strum::EnumCount,
    strum::EnumString,
    strum::IntoStaticStr,
)]
pub enum Mangle {
    PREROUTING,
    INPUT,
    OUTPUT,
    FORWARD,
    POSTROUTING,
    Custom(String),
}
def_chain!(Mangle);

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    // enumn::N, PartialOrd, Ord,
    strum::EnumCount,
    strum::EnumString,
    strum::IntoStaticStr,
)]
pub enum Raw {
    PREROUTING,
    OUTPUT,
    Custom(String),
}
def_chain!(Raw);

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    // enumn::N, PartialOrd, Ord,
    strum::EnumCount,
    strum::EnumString,
    strum::IntoStaticStr,
)]
pub enum Security {
    INPUT,
    OUTPUT,
    FORWARD,
    Custom(String),
}
def_chain!(Security);

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TablechainEnum {
    Filter(Filter),
    Nat(Nat),
    Mangle(Mangle),
    Raw(Raw),
    Security(Security),
}

impl TablechainEnum {
    pub fn table_and_chain_names(&self) -> (String, String) {
        match self {
            TablechainEnum::Filter(c) => c.table_and_chain_names(),
            TablechainEnum::Nat(c) => c.table_and_chain_names(),
            TablechainEnum::Mangle(c) => c.table_and_chain_names(),
            TablechainEnum::Raw(c) => c.table_and_chain_names(),
            TablechainEnum::Security(c) => c.table_and_chain_names(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Restriction {
    Interface(String),
    Protocol(&'static str), // ?
    DestinationPort(u16),
}

impl Restriction {
    fn push_args(&self, out: &mut Vec<String>) {
        match self {
            Restriction::Interface(s) => {
                out.push("-i".into());
                out.push(s.into());
            }
            Restriction::Protocol(s) => {
                out.push("-p".into());
                out.push((*s).into());
            }
            Restriction::DestinationPort(n) => {
                out.push("--dport".into());
                out.push(n.to_string());
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RuleAction<C: TablechainTrait> {
    None,
    Return,
    Drop,
    Reject,
    Goto(C),
}

impl<C: TablechainTrait> RuleAction<C> {
    fn push_args(&self, out: &mut Vec<String>) {
        match self {
            RuleAction::Return => {
                out.push("-j".into());
                out.push("RETURN".into());
            }
            RuleAction::Drop => {
                out.push("-j".into());
                out.push("DROP".into());
            }
            RuleAction::Reject => {
                out.push("-j".into());
                out.push("REJECT".into());
            }
            RuleAction::Goto(c) => {
                out.push("-j".into());
                out.push(c.chain_name());
            }
            RuleAction::None => {}
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Rule<C: TablechainTrait> {
    pub chain: C,
    pub restrictions: Vec<Restriction>,
    pub rule_action: RuleAction<C>,
}

impl<C: TablechainTrait> Rule<C> {
    pub fn cmd_args(&self, action: Action) -> Vec<String> {
        let mut out = Vec::new();
        self.chain.push_args(action, &mut out);
        for r in &self.restrictions {
            r.push_args(&mut out);
        }
        self.rule_action.push_args(&mut out);
        out
    }
}

pub trait RuleTrait {
    fn cmd_args(&self, action: Action) -> Vec<String>;
}

impl<C: TablechainTrait> RuleTrait for Rule<C> {
    fn cmd_args(&self, action: Action) -> Vec<String> {
        self.cmd_args(action)
    }
}

pub struct IptablesWriter {
    iptables_cmd: Vec<String>,
    actions: Vec<(Action, Box<dyn RuleTrait>, RecreatingMode)>,
}

/// What end result you want: Deletion inverts the result of an
/// action. Recreation first deletes then creates. Creation just runs
/// the originally specified action (rarely what you want).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Creation,
    Recreation,
    Deletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecreatingMode {
    Owned,
    TryCreationNoDeletion,
}

impl IptablesWriter {
    pub fn new(iptables_cmd: Vec<String>) -> Self {
        Self {
            iptables_cmd,
            actions: Vec::new(),
        }
    }

    /// Pushes the rule with the corresponding action regardless of
    /// whether the action is creative or other. You usually don't
    /// want to use this, but rather `push` instead.
    pub fn _push<T: TablechainTrait + 'static>(
        &mut self,
        action: Action,
        rule: Rule<T>,
        recreating_mode: RecreatingMode,
    ) {
        self.actions.push((action, Box::new(rule), recreating_mode));
    }

    /// Pushes the rule, but accepts only creative actions. Because
    /// deleting actions are usually done via running `execute` with
    /// an Effect that deletes (including recreation), they are
    /// automatically derived there. Also, deleting `Effect`s lead to
    /// the reversal of the order of rule application; hence call
    /// `push` always in the order appropriate for the creation of
    /// rules.
    pub fn push<T: TablechainTrait + 'static>(
        &mut self,
        action: Action,
        rule: Rule<T>,
        recreating_mode: RecreatingMode,
    ) -> Result<()> {
        if action.is_creation() {
            self._push(action, rule, recreating_mode);
            Ok(())
        } else {
            bail!(
                "warning: push_wanting called for an action that doesn't \
                 create anything: {action:?}"
            )
        }
    }

    /// For a dry_run; don't use as shell code, use execute (that can
    /// use cmd_args directly)! -- todo: needs to be updated with an
    /// Effect
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        for (action, rule, _) in &self.actions {
            for arg in rule.cmd_args(*action) {
                write_str(&mut out, " ");
                write_str(&mut out, &arg);
            }
            write_str(&mut out, "\n");
        }
        out
    }

    fn exitcode_is_ok_for_deletions(code: i32) -> bool {
        // It appears that iptables exits with code 1 *or* 2 when
        // chain doesn't exist, 1 for rule that doesn't exist, 4 when
        // not running as root or when "Device or resource busy"
        // because a chain, while empty, is still referenced.
        code == 1 || code == 2
    }

    /// Turn the pushed rules into rules for actual execution
    /// according to the wanted Effect. Execute for real if true is
    /// given.
    pub fn execute(&self, want: Effect, verbose: bool, for_real: bool) -> Result<()> {
        let mut cmd = self.iptables_cmd.clone().into_iter();
        let command_path = cmd
            .next()
            .ok_or_else(|| anyhow!("iptables_cmd value is empty"))?;
        let command_base_args: Vec<String> = cmd.collect();

        let run = |creation: bool| -> Result<()> {
            let actions: Box<dyn Iterator<Item = _>> = if creation {
                Box::new(self.actions.iter())
            } else {
                Box::new(self.actions.iter().rev())
            };

            for (action, rule, recreating_mode) in actions {
                match recreating_mode {
                    RecreatingMode::Owned => {}
                    RecreatingMode::TryCreationNoDeletion => {
                        if !creation {
                            continue;
                        }
                    }
                }
                let _actions = &[*action];
                let actions = if creation {
                    _actions
                } else {
                    action.deletion_sequence().expect(
                        "should not have non-creating actions when using deleting \
                                 `Effect`s, apparently you used `_push`?",
                    )
                };
                for action in actions {
                    let mut args = rule.cmd_args(*action);
                    let mut all_args = command_base_args.clone();
                    all_args.append(&mut args);
                    let mut command = Command::new(command_path.clone());
                    command.args(&all_args);
                    if verbose {
                        eprintln!("+ {command:?}");
                    }
                    if for_real {
                        let output = command.output()?;
                        let status = output.status;
                        if !status.success() {
                            match status.code() {
                                Some(code) if Self::exitcode_is_ok_for_deletions(code) => {
                                    if !action.is_creation() {
                                        ()
                                    } else {
                                        match recreating_mode {
                                            RecreatingMode::Owned => bail!(
                                                "command {command:?} exited with code {code} \
                                             for non-deleting action {action:?}: {}",
                                                output.combined_string()
                                            ),
                                            RecreatingMode::TryCreationNoDeletion => {}
                                        }
                                    }
                                }
                                Some(code) => bail!(
                                    "command {command:?} exited with code {code}: {}",
                                    output.combined_string()
                                ),
                                None => bail!(
                                    "command {command:?} was killed by signal {:?}",
                                    status.signal()
                                ),
                            }
                        }
                    }
                }
            }
            Ok(())
        };

        match want {
            Effect::Creation => run(true)?,
            Effect::Recreation => {
                run(false)?;
                run(true)?;
            }
            Effect::Deletion => run(false)?,
        }
        Ok(())
    }
}
