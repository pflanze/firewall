//! Once more, simplify enums that have a string representation.

/// Define an enum with the given members, that implements Display and
/// conversion to String, emitting the lower-case representation of
/// the member names.
#[macro_export]
macro_rules! with_lcstring_conversion {
    { PUB( $($pub:tt)* ) enum $type_name:ident { $($members:tt)* } } => {
        #[derive(Debug, PartialEq, Eq, Clone, Copy, strum_macros::IntoStaticStr)]
        $($pub)* enum $type_name {
            $($members)*
        }
        impl From<&$type_name> for String {
            fn from(value: &$type_name) -> Self {
                let name: &'static str = value.into();
                name.to_ascii_lowercase()
            }
        }
    };
    { enum $($rest:tt)* } => {
        with_lcstring_conversion!{ PUB() enum $($rest)* }
    };
    { pub enum $($rest:tt)* } => {
        with_lcstring_conversion!{ PUB(pub) enum $($rest)* }
    };
    { pub($access:tt) enum $($rest:tt)* } => {
        with_lcstring_conversion!{ PUB(pub($access)) enum $($rest)* }
    };
}
