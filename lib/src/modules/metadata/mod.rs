use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::metadata::*;

#[module_main]
fn main(_data: &[u8]) -> Metadata {
    let parsed = serde_json::from_slice::<serde_json::Value>(_data).unwrap();

    println!("{:?}", _data);
    println!("{:?}", parsed);

    // this is where to fill the ctx fro the fns
    Metadata::new()
}

// todo self: note i64 should be the default
#[module_export(name = "file.name")]
fn match_list_string(ctx: &ScanContext, string: RuntimeString) -> Option<i64> {
    Some(42)
}

#[module_export(name = "file.name")]
fn match_list_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    Some(666)
}

// #[module_export(name = "file.name")]
// fn foo(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
//     let _ = ctx.module_output::<Metadata>();
//     Some(666)
// }
