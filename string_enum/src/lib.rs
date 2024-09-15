//! Once more, simplify enums that have a string representation.

/// Conversion to lower-case strings.
pub trait ToLcString {
    fn to_lc_string(&self) -> String;
}
