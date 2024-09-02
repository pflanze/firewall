use anyhow::{anyhow, bail, Result};
use std::fmt::{Debug, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

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
    // The following are only for `iptables`-running mode
    Delete,
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
    /// The sequence of actions that have to be taken for getting the
    /// effect of the original action on an empty table. `None` if the
    /// action is not one that creates something.
    pub fn recreation_sequence(&self) -> Option<Vec<Action>> {
        match self {
            Action::Append => Some(vec![Action::Delete, self.clone()]),
            Action::Delete => None,
            Action::Insert(_) => Some(vec![Action::Delete, self.clone()]),
            Action::Check => None,
            Action::NewChain => Some(vec![Action::Flush, Action::DeleteChain, self.clone()]),
            Action::DeleteChain => None,
            Action::Flush => None,
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

macro_rules! def_chain {
    { $typename:tt } => {
        impl $typename {
            pub fn chain_name(&self) -> String {
                let name: &'static str = self.into();
                match self {
                    $typename::Custom(s) => s.into(),
                    _ => name.into()
                }
            }
            pub fn chain_name_for_same_table_as(&self, _other: &$typename) -> String {
                self.chain_name()
            }
        }
        impl From<$typename> for Chain {
            fn from(value: $typename) -> Self {
                Chain::$typename(value)
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
pub enum Chain {
    Filter(Filter),
    Nat(Nat),
    Mangle(Mangle),
    Raw(Raw),
    Security(Security),
}

impl Chain {
    pub fn table_and_chain_names(&self) -> (&'static str, String) {
        match self {
            Chain::Filter(c) => ("filter", c.chain_name()),
            Chain::Nat(c) => ("nat", c.chain_name()),
            Chain::Mangle(c) => ("mangle", c.chain_name()),
            Chain::Raw(c) => ("raw", c.chain_name()),
            Chain::Security(c) => ("security", c.chain_name()),
        }
    }
    /// For collecting the arguments for the iptables command.
    pub fn push_args(&self, action: Action, out: &mut Vec<String>) {
        let (table_name, chain_name) = self.table_and_chain_names();
        out.push("-t".into());
        out.push(table_name.into());
        action.push_args(chain_name, out);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Code(Vec<String>);

impl From<&str> for Code {
    fn from(value: &str) -> Self {
        Self(value.split_whitespace().map(|s| s.into()).collect())
    }
}

impl From<String> for Code {
    fn from(value: String) -> Self {
        (&*value).into()
    }
}

impl From<&[&str]> for Code {
    fn from(value: &[&str]) -> Self {
        Self(value.iter().map(|s| (*s).into()).collect())
    }
}

impl Code {
    pub fn args(&self) -> &[String] {
        &self.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Rule {
    pub chain: Chain,
    pub code: Code,
}

impl Rule {
    pub fn cmd_args(&self, action: Action) -> Vec<String> {
        let mut out = Vec::new();
        self.chain.push_args(action, &mut out);
        for arg in self.code.args() {
            out.push(arg.clone());
        }
        out
    }
}

pub struct IptablesWriter {
    iptables_cmd: Vec<String>,
    actions: Vec<(Action, Rule)>,
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

impl IptablesWriter {
    pub fn new(iptables_cmd: Vec<String>) -> Self {
        Self {
            iptables_cmd,
            actions: Vec::new(),
        }
    }

    /// Pushes the rule to be carried out using the exact given
    /// action.
    pub fn push(&mut self, action: Action, rule: Rule) {
        self.actions.push((action, rule));
    }

    /// Pushes the rule but depending on `want`, will push (also)
    /// other actions than the given one to achieve what is wanted
    /// (e.g. chain creation leads to chain flush, delete, creation
    /// when Effect::Recreation is given). If `action` is not a
    /// creative action, warns and runs just `action` when creating or
    /// nothing if Effect::Delete is wanted.
    pub fn push_wanting(&mut self, want: Effect, action: Action, rule: Rule) {
        let mut run = |maybe_seq: Option<&[Action]>, run_orig_as_fallback| {
            if let Some(seq) = maybe_seq {
                for action in seq {
                    self.actions.push((*action, rule.clone()));
                }
            } else {
                eprintln!(
                    "warning: push_wanting called for an action that doesn't \
                     create anything: {action:?}"
                );
                if run_orig_as_fallback {
                    self.actions.push((action, rule.clone()));
                }
            }
        };
        match want {
            Effect::Creation => run(
                Some(&vec![action]),
                false, // branch never taken anyway
            ),
            Effect::Recreation => run(action.recreation_sequence().as_deref(), true),
            Effect::Deletion => run(action.deletion_sequence(), false),
        }
    }

    /// For a dry_run; don't use as shell code, use execute (that can
    /// use cmd_args directly)!
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        for (action, rule) in &self.actions {
            for arg in rule.cmd_args(*action) {
                write_str(&mut out, " ");
                write_str(&mut out, &arg);
            }
            write_str(&mut out, "\n");
        }
        out
    }

    /// Execute for real if true is given.
    pub fn execute(&self, verbose: bool, for_real: bool) -> Result<()> {
        let mut cmd = self.iptables_cmd.clone().into_iter();
        let command_path = cmd
            .next()
            .ok_or_else(|| anyhow!("iptables_cmd value is empty"))?;
        let command_base_args: Vec<String> = cmd.collect();
        for (action, rule) in &self.actions {
            let mut args = rule.cmd_args(*action);
            let mut all_args = command_base_args.clone();
            all_args.append(&mut args);
            let mut command = Command::new(command_path.clone());
            command.args(&all_args);
            if verbose {
                eprintln!("+ {command:?}");
            }
            if for_real {
                let status = command.status()?;
                if !status.success() {
                    match status.code() {
                        Some(1) => {
                            if !action.is_creation() {
                                // XX is it correct to assume that the
                                // commands exits with code 1 for match
                                // failures?
                                ()
                            } else {
                                bail!(
                                    "command {command_path:?} exited with code 1 \
                                   for non-deleting action {action:?}"
                                )
                            }
                        }
                        Some(code) => bail!("command {command_path:?} exited with code {:?}", code),
                        None => bail!(
                            "command {command_path:?} was killed by signal {:?}",
                            status.signal()
                        ),
                    }
                }
            }
        }
        Ok(())
    }
}
