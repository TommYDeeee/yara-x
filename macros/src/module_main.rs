extern crate proc_macro;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::ItemFn;

pub(crate) fn impl_module_main_macro(
    input: ItemFn,
) -> syn::Result<TokenStream> {
    let fn_name = &input.sig.ident;

    let main_stub = quote! {
        use protobuf::MessageDyn;
        // todo unsure about how good of a practice it is to use the type path like this (`crate::ScanInputRaw`)
        // is it "hygienic" enough?
        pub(crate) fn __main__(data: &crate::ScanInputRaw) -> Box<dyn MessageDyn> {
            Box::new(#fn_name(data))
        }
    };

    let mut token_stream = input.to_token_stream();

    token_stream.extend(main_stub);

    syn::Result::Ok(token_stream)
}
