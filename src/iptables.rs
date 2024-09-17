use anyhow::Result;
use ipnet::Ipv4Net;
use std::fmt::Debug;

use crate::executor::{Executor, ExecutorResult, ExecutorStatus};
use crate::shell_quote::shell_quote_many;
use string_enum_macro::{lc_string_enum, uc_string_enum};

#[lc_string_enum]
#[derive(Copy)]
pub enum Table {
    Filter,
    Nat,
    Mangle,
    Raw,
    Security,
}

#[lc_string_enum]
#[derive(Copy)]
pub enum Action {
    Append,
    /// Insert is holding a 1-based index
    Insert(u32),
    NewChain,
}

impl From<Action> for AnyAction {
    fn from(value: Action) -> Self {
        AnyAction::Creation(value)
    }
}

#[lc_string_enum]
#[derive(Copy)]
pub enum DeletionAction {
    Delete,
    DeleteChain,
    Flush,
}

impl From<DeletionAction> for AnyAction {
    fn from(value: DeletionAction) -> Self {
        AnyAction::Deletion(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyAction {
    Check,
    Creation(Action),
    Deletion(DeletionAction),
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
            Action::Insert(n) => {
                normal("-I");
                out.push(format!("{n}"));
            }
            Action::NewChain => normal("-N"),
        }
    }

    /// The sequence of actions that are *removing* the original
    /// action.
    pub fn deletion_sequence(&self) -> &[DeletionAction] {
        match self {
            Action::Append => &[DeletionAction::Delete],
            Action::Insert(_) => &[DeletionAction::Delete],
            Action::NewChain => &[DeletionAction::Flush, DeletionAction::DeleteChain],
        }
    }
}

impl DeletionAction {
    /// For collecting the arguments for the iptables command.
    pub fn push_args(&self, chain_name: String, out: &mut Vec<String>) {
        let normal = |name: &str| {
            out.push(name.into());
            out.push(chain_name);
        };
        match self {
            DeletionAction::Delete => normal("-D"),
            DeletionAction::DeleteChain => normal("-X"),
            DeletionAction::Flush => normal("-F"),
        }
    }
}

impl AnyAction {
    /// For collecting the arguments for the iptables command.
    pub fn push_args(&self, chain_name: String, out: &mut Vec<String>) {
        let mut normal = |name: &str| {
            out.push(name.into());
            out.push(chain_name.clone());
        };
        match self {
            AnyAction::Check => normal("-C"),
            AnyAction::Creation(a) => a.push_args(chain_name, out),
            AnyAction::Deletion(a) => a.push_args(chain_name, out),
        }
    }

    fn is_creation(&self) -> bool {
        match self {
            AnyAction::Check => false,
            AnyAction::Creation(_) => true,
            AnyAction::Deletion(_) => false,
        }
    }
}

pub trait TablechainTrait {
    fn chain_name(&self) -> String;
    fn table_and_chain_names(&self) -> (String, String);

    /// For collecting the arguments for the iptables command.
    fn push_args(&self, action: AnyAction, out: &mut Vec<String>) {
        let (table_name, chain_name) = self.table_and_chain_names();
        out.push("-t".into());
        out.push(table_name.into());
        action.push_args(chain_name, out);
    }
}

// TODO: find out how to implement the same without using a macro.
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

#[uc_string_enum]
pub enum Filter {
    INPUT,
    FORWARD,
    OUTPUT,
    Custom(String),
}
def_chain!(Filter);

#[uc_string_enum]
pub enum Nat {
    PREROUTING,
    INPUT,
    OUTPUT,
    POSTROUTING,
    Custom(String),
}
def_chain!(Nat);

#[uc_string_enum]
pub enum Mangle {
    PREROUTING,
    INPUT,
    OUTPUT,
    FORWARD,
    POSTROUTING,
    Custom(String),
}
def_chain!(Mangle);

#[uc_string_enum]
pub enum Raw {
    PREROUTING,
    OUTPUT,
    Custom(String),
}
def_chain!(Raw);

#[uc_string_enum]
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

#[lc_string_enum]
pub enum Protocol {
    All,
    Tcp,
    Udp,
    Udplite,
    Icmp,
    Icmpv6,
    Esp,
    Ah,
    Sctp,
    Mh,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Negatable {
    Is,
    IsNot,
}

impl Negatable {
    fn push_args(&self, out: &mut Vec<String>) {
        match self {
            Negatable::Is => (),
            Negatable::IsNot => out.push("!".into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Restriction {
    Interface(Negatable, String),
    Protocol(Negatable, Protocol),
    SourceAddress(Negatable, Ipv4Net),
    DestinationAddress(Negatable, Ipv4Net),
    SourcePort(Negatable, u16),
    DestinationPort(Negatable, u16),
    Custom(Vec<String>),
}

impl Restriction {
    fn push_args(&self, out: &mut Vec<String>) {
        match self {
            Restriction::Interface(neg, s) => {
                out.push("-i".into());
                neg.push_args(out);
                out.push(s.into());
            }
            Restriction::Protocol(neg, s) => {
                out.push("-p".into());
                neg.push_args(out);
                out.push(s.into());
            }
            Restriction::SourceAddress(neg, net) => {
                out.push("-s".into());
                neg.push_args(out);
                out.push(net.to_string()); // XX ?
            }
            Restriction::DestinationAddress(neg, net) => {
                out.push("-d".into());
                neg.push_args(out);
                out.push(net.to_string()); // XX ?
            }
            Restriction::SourcePort(neg, n) => {
                out.push("--sport".into());
                neg.push_args(out);
                out.push(n.to_string());
            }
            Restriction::DestinationPort(neg, n) => {
                out.push("--dport".into());
                neg.push_args(out);
                out.push(n.to_string());
            }
            Restriction::Custom(conditions) => {
                for condition in conditions {
                    out.push(condition.into());
                }
            }
        }
    }
}

#[macro_export]
macro_rules! restrictions {
    { $($exprs:tt)* } => {
        {
            use firewall::iptables::Restriction::*;
            use firewall::iptables::Negatable::*;
            use firewall::iptables::Protocol::*;
            vec![
                $($exprs)*
            ]
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RuleAction<C: TablechainTrait> {
    None,
    Return,
    Drop,
    Reject,
    Jump(C),
    Goto(C),
}

impl<C: TablechainTrait> RuleAction<C> {
    fn push_args(&self, out: &mut Vec<String>) {
        match self {
            RuleAction::None => {}
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
            RuleAction::Jump(c) => {
                out.push("-j".into());
                out.push(c.chain_name());
            }
            RuleAction::Goto(c) => {
                out.push("-g".into());
                out.push(c.chain_name());
            }
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
    pub fn cmd_args(&self, action: AnyAction) -> Vec<String> {
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
    fn cmd_args(&self, action: AnyAction) -> Vec<String>;
}

impl<C: TablechainTrait> RuleTrait for Rule<C> {
    fn cmd_args(&self, action: AnyAction) -> Vec<String> {
        self.cmd_args(action)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultInterpretation {
    /// Undoubtable success.
    Ok,
    /// Error that happens when a rule that should be deleted doesn't
    /// exist.
    OkForDeletions,
    /// A chain couldn't be deleted because it is in use
    ChainInUse,
    /// A chain couldn't be created because it already exists
    ChainAlreadyExists,
    /// Unrecoverable error
    Err,
}

impl<'t> From<&ExecutorResult<'t>> for ResultInterpretation {
    fn from(result: &ExecutorResult<'t>) -> Self {
        match result.status {
            ExecutorStatus::Success => Self::Ok,
            ExecutorStatus::ExitCode(code) => {
                if code == 4
                    && result
                        .combined_output
                        .contains("CHAIN_DEL failed (Device or resource busy)")
                {
                    Self::ChainInUse
                } else if code == 1 && result.combined_output.contains("Chain already exists") {
                    Self::ChainAlreadyExists
                }
                // It appears that iptables exits with code 1 *or* 2 when
                // chain doesn't exist, 1 for rule that doesn't exist, 4 when
                // not running as root or when "Device or resource busy"
                // because a chain, while empty, is still referenced.
                else if code == 1 || code == 2 {
                    Self::OkForDeletions
                } else {
                    Self::Err
                }
            }
            ExecutorStatus::Signal(_) => Self::Err,
            ExecutorStatus::ExecFailure(_) => Self::Err,
        }
    }
}

pub struct IptablesWriter {
    iptables_cmd: Vec<String>,
    actions: Vec<(AnyAction, Box<dyn RuleTrait>, RecreatingMode)>,
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
        action: AnyAction,
        rule: Rule<T>,
        recreating_mode: RecreatingMode,
    ) {
        self.actions.push((action, Box::new(rule), recreating_mode));
    }

    /// Push a rule with creative action. Because deleting actions are
    /// usually done via running `execute` with an Effect that deletes
    /// (including recreation), they are automatically derived
    /// there. Also, deleting `Effect`s lead to the reversal of the
    /// order of rule application; hence call `push` always in the
    /// order appropriate for the creation of rules.
    pub fn push<T: TablechainTrait + 'static>(
        &mut self,
        action: Action,
        rule: Rule<T>,
        recreating_mode: RecreatingMode,
    ) {
        self._push(action.into(), rule, recreating_mode);
    }

    /// For a dry_run; don't use as shell code, use execute (that can
    /// use cmd_args directly)! -- todo: needs to be updated with an
    /// Effect
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        for (action, rule, _) in &self.actions {
            for arg in rule.cmd_args(*action) {
                out.push_str(" ");
                out.push_str(&arg);
            }
            out.push_str("\n");
        }
        out
    }

    /// Turn the pushed rules into rules for actual execution
    /// according to the wanted Effect. Execute for real if true is
    /// given.
    pub fn execute<O: std::io::Write>(
        &self,
        want: Effect,
        mut verbose_output: Option<O>,
        executor: &mut dyn Executor<AnyAction>,
    ) -> Result<()> {
        let mut run = |creation: bool| -> Result<()> {
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
                let creation_action = match action {
                    AnyAction::Creation(a) => a,
                    _ => panic!(
                        "should not have non-creating actions when using deleting \
                                 `Effect`s, apparently you used `_push`?",
                    ),
                };
                let actions = if creation {
                    vec![*action]
                } else {
                    creation_action
                        .deletion_sequence()
                        .iter()
                        .copied()
                        .map(AnyAction::from)
                        .collect()
                };
                for action in actions {
                    let mut cmd = self.iptables_cmd.clone();
                    let mut args = rule.cmd_args(action);
                    cmd.append(&mut args);
                    let result = executor.execute(action, &cmd);
                    if let Some(out) = verbose_output.as_mut() {
                        writeln!(out, "{} {}", result.to_str(), shell_quote_many(&cmd))?;
                    }
                    match ResultInterpretation::from(&result) {
                        ResultInterpretation::Ok => (),
                        ResultInterpretation::OkForDeletions => {
                            if action.is_creation() {
                                result.to_anyhow(Some(&format!(
                                    "for non-deleting action {action:?}"
                                )))?
                            }
                        }
                        ResultInterpretation::ChainInUse => {
                            if action.is_creation() {
                                result.to_anyhow(Some(&format!(
                                    "because chain is in use, for non-deleting action {action:?}"
                                )))?
                            } else {
                                // Mark so that error in creation part
                                // below can be more strictly checked?
                            }
                        }
                        ResultInterpretation::ChainAlreadyExists => {
                            if action == Action::NewChain.into() {
                                // Only ignore this error if
                                // previously there was the ChainInUse
                                // error above on the same rule?
                            } else {
                                result.to_anyhow(Some(&format!(
                                    "got 'chain already exists' error even though action \
                                     is not chain creation, but {action:?}"
                                )))?
                            }
                        }
                        ResultInterpretation::Err => result.to_anyhow(None)?,
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
