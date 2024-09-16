use anyhow::{bail, Result};
use ipnet::Ipv4Net;
use std::fmt::Debug;

use crate::executor::Executor;
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
                out.push_str(" ");
                out.push_str(&arg);
            }
            out.push_str("\n");
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
    pub fn execute<O: std::io::Write>(
        &self,
        want: Effect,
        mut verbose_output: Option<O>,
        executor: &mut dyn Executor<Action>,
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
                    let mut cmd = self.iptables_cmd.clone();
                    let mut args = rule.cmd_args(*action);
                    cmd.append(&mut args);
                    let result = executor.execute(*action, &cmd);
                    if let Some(out) = verbose_output.as_mut() {
                        writeln!(out, "{} {}", result.to_str(), shell_quote_many(&cmd))?;
                    }
                    if !result.is_success() {
                        match result.code() {
                            Some(code) if Self::exitcode_is_ok_for_deletions(code) => {
                                if !action.is_creation() {
                                    ()
                                } else {
                                    match recreating_mode {
                                        RecreatingMode::Owned => result.to_anyhow(Some(
                                            &format!("for non-deleting action {action:?}"),
                                        ))?,
                                        RecreatingMode::TryCreationNoDeletion => (),
                                    }
                                }
                            }
                            _ => result.to_anyhow(None)?,
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
