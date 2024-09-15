//! Clean but safe (I hope) shell-quoting for generating code
//! representing literals in Bash scripts.

// Unlike https://crates.io/crates/shell-quote which produces ugly to
// read output.

use std::borrow::{Borrow, Cow};

// besides ascii_alphanumeric
const SAFE_CHARS: &[char] = &['_', '=', '-', '/', '+', '%', '.', ',', ':'];

pub fn is_quote_safe(c: char) -> bool {
    c.is_ascii_alphanumeric() || SAFE_CHARS.contains(&c)
}

// internal function, only ever call with strings not containing a
// singlequote character!
fn shell_quote_without_singlequote(s: &str) -> Cow<str> {
    if s.chars().all(is_quote_safe) {
        Cow::Borrowed(s)
    } else {
        let mut out = String::new();
        out.push('\'');
        out.push_str(s);
        out.push('\'');
        Cow::Owned(out)
    }
}

pub fn shell_quote(s: &str) -> Cow<str> {
    if s.is_empty() {
        return Cow::Borrowed("''");
    }
    let mut parts = s.split('\'').map(shell_quote_without_singlequote);
    let part0 = parts
        .next()
        .expect("always there because we checked s is not empty");
    let rest: Vec<Cow<str>> = parts.collect();
    if rest.is_empty() {
        return part0;
    }
    let mut out = part0.to_string(); // XX *is* that how Cow::Owned helps?
    for part in rest {
        out.push('\\');
        out.push('\'');
        out.push_str(&part);
    }
    Cow::Owned(out)
}

/// Note: the empty input slice will yield an empty string!
pub fn shell_quote_many<S: AsRef<str>>(ss: &[S]) -> String {
    let mut out = String::new();
    let mut is_first = true;
    for s in ss.into_iter().map(|s| shell_quote((*s).as_ref())) {
        if is_first {
            is_first = false
        } else {
            out.push(' ');
        }
        out.push_str(s.borrow());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_shell_quote() {
        assert_eq!(shell_quote("1"), "1");
        assert_eq!(shell_quote("1,2"), "1,2");
        assert_eq!(shell_quote("_"), "_");
        assert_eq!(shell_quote("foo.txt"), "foo.txt");
        assert_eq!(shell_quote("foo=10+2/3-3:4"), "foo=10+2/3-3:4");
        assert_eq!(shell_quote("foo=10*2"), "\'foo=10*2\'");
        assert_eq!(shell_quote("ä"), "'ä'");
        assert_eq!(shell_quote(""), "\'\'");
        assert_eq!(shell_quote("ab'foo*2"), "ab\\''foo*2'");
    }

    #[test]
    fn t_shell_quote_many() {
        assert_eq!(
            shell_quote_many(&["foo", "bar baz", "3*2", "4'5"]),
            "foo 'bar baz' '3*2' 4\\'5"
        );
        assert_eq!(shell_quote_many::<&str>(&[]), "");
        assert_eq!(shell_quote_many::<String>(&[]), "");
        assert_eq!(shell_quote_many(&[String::from("foo")]), "foo");
    }
}
