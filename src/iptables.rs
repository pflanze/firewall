use std::fmt::{Debug, Write};

use anyhow::Result;

pub fn write_str(out: &mut String, s: &str) {
    out.write_str(s).unwrap(); // can't ever fail, no?
}


#[derive(Debug, PartialEq, Eq, Clone, Copy,
         // enumn::N, PartialOrd, Ord, 
         strum::EnumCount, strum::EnumString, strum::IntoStaticStr)]
pub enum Table {
    #[strum(serialize="filter")]
    Filter,
    #[strum(serialize="nat")]
    Nat,
    #[strum(serialize="mangle")]
    Mangle,
    #[strum(serialize="raw")]
    Raw,
    #[strum(serialize="security")]
    Security,
}


#[derive(Debug, PartialEq, Eq, Clone, Copy,
         // enumn::N, PartialOrd, Ord, 
         strum::EnumCount, strum::EnumString, strum::IntoStaticStr)]
pub enum Action {
    A,
    // The following are only for `iptables`-running mode
    D,
    I(u32),
    Check,
}
impl Action {
    pub fn push_args(&self, chain_name: String, out: &mut Vec<String>) {
        let normal = |name: &str| {
            out.push(name.into());
            out.push(chain_name);
        };
        match self {
            Action::A => normal("-A"),
            Action::D => normal("-D"),
            Action::I(n) => {
                normal("-I");
                out.push(format!("{n}"));
            }
            Action::Check => normal("-C"),
        }
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
        }
        impl From<$typename> for Chain {
            fn from(value: $typename) -> Self {
                Chain::$typename(value)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone,
         // enumn::N, PartialOrd, Ord, 
         strum::EnumCount, strum::EnumString, strum::IntoStaticStr)]
pub enum Filter {
    INPUT,
    FORWARD,
    OUTPUT,
    Custom(String),
}
def_chain!(Filter);


#[derive(Debug, PartialEq, Eq, Clone,
         // enumn::N, PartialOrd, Ord, 
         strum::EnumCount, strum::EnumString, strum::IntoStaticStr)]
pub enum Nat {
    PREROUTING,
    INPUT,
    OUTPUT,
    POSTROUTING,
    Custom(String),
}
def_chain!(Nat);


#[derive(Debug, PartialEq, Eq, Clone,
         // enumn::N, PartialOrd, Ord, 
         strum::EnumCount, strum::EnumString, strum::IntoStaticStr)]
pub enum Mangle {
    PREROUTING,
    INPUT,
    OUTPUT,
    FORWARD,
    POSTROUTING,
    Custom(String),
}
def_chain!(Mangle);

#[derive(Debug, PartialEq, Eq, Clone,
         // enumn::N, PartialOrd, Ord, 
         strum::EnumCount, strum::EnumString, strum::IntoStaticStr)]
pub enum Raw {
    PREROUTING,
    OUTPUT,
    Custom(String),
}
def_chain!(Raw);


#[derive(Debug, PartialEq, Eq, Clone,
         // enumn::N, PartialOrd, Ord, 
         strum::EnumCount, strum::EnumString, strum::IntoStaticStr)]
pub enum Security {
    INPUT,
    OUTPUT,
    FORWARD,
    Custom(String),
}
def_chain!(Security);


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
    pub fn push_args(&self, action: Action, out: &mut Vec<String>) {
        let (table_name, chain_name) = self.table_and_chain_names();
        out.push("-t".into());
        out.push(table_name.into());
        action.push_args(chain_name, out);
    }
}

pub struct Code(Vec<String>);

impl From<&str> for Code {
    fn from(value: &str) -> Self {
        Self(value.split_whitespace().map(|s| s.into()).collect())
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
    actions: Vec<(Action, Rule)>,
}

impl IptablesWriter {
    pub fn new() -> Self {
        Self {
            actions: Vec::new()
        }
    }
    pub fn push(&mut self, action: Action, rule: Rule) {
        self.actions.push((action, rule));
    }

    /// For a dry_run; don't use as shell code, use execute (that can
    /// use cmd_args directly)!
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        for (action, rule) in &self.actions {
            write_str(&mut out, "iptables");
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
        for (action, rule) in &self.actions {
            let args = rule.cmd_args(*action);
            if verbose {
                eprintln!("+ iptables {args:?}");
            }
            if for_real {
                todo!()
            }
        }
        Ok(())
    }
}
