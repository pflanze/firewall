use proc_macro::TokenStream;
use quote::quote;

/// Define an enum with the given members, deriving `Debug, PartialEq,
/// Eq, Clone`, and with a conversion into String that
/// lower-cases the member names.
#[proc_macro_attribute]
pub fn lc_string_enum(atts: TokenStream, input: TokenStream) -> TokenStream {
    if !atts.is_empty() {
        panic!("lc_string_enum does not expect any attribute arguments (got: {atts})");
    }
    let ast: syn::DeriveInput = syn::parse(input).expect("can't parse as Rust code");

    let name = &ast.ident;
    let gen = quote! {
        impl string_enum::ToLcString for #name {
            fn to_lc_string(&self) -> String {
                let name: &'static str = self.into();
                name.to_ascii_lowercase()
            }
        }
        impl From<&#name> for String {
            fn from(value: &#name) -> Self {
                let name: &'static str = value.into();
                name.to_ascii_lowercase()
            }
        }
        #[derive(Debug, PartialEq, Eq, Clone, strum_macros::IntoStaticStr)]
        #ast
    };
    gen.into()
}


