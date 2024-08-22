use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::metadata::*;

#[module_main]
fn main(_data: &[u8]) -> Metadata {
    let parsed = serde_json::from_slice::<serde_json::Value>(_data).unwrap();

    // todo fix & remove before prod / upstream merge
    if cfg!(not(debug_assertions)) {
        panic!(
            r"
        this module is not meant to be used in production yet
        currently, we are abusing the `_data` arg to send the json file -> fix this
        "
        )
    }

    println!("{:?}", _data);
    println!("{:?}", parsed);

    // this is where to fill the ctx fro the fns
    Metadata::new()
}

#[module_export(name = "file.name")]
fn name_string(_ctx: &ScanContext, _string: RuntimeString) -> Option<i64> {
    Some(42)
}

#[module_export(name = "file.name")]
fn name_regex(_ctx: &ScanContext, _re: RegexpId) -> Option<i64> {
    Some(666)
}

// detection

#[module_export(name = "detection.name")]
fn detection_int(_ctx: &ScanContext, _re: RegexpId) -> Option<i64> {
    todo!()
}

#[module_export(name = "detection.name")]
fn detection_string(
    _ctx: &ScanContext,
    _string: RuntimeString,
) -> Option<i64> {
    todo!()
}

#[module_export(name = "detection.name")]
fn detection_regexp_av(
    _ctx: &ScanContext,
    _string: RuntimeString,
    _re: RegexpId,
) -> Option<i64> {
    todo!()
}

#[module_export(name = "detection.name")]
fn detection_string_av(
    _ctx: &ScanContext,
    _string1: RuntimeString,
    _string2: RuntimeString,
) -> Option<i64> {
    todo!()
}

// arpot

#[module_export(name = "arpot.dll")]
fn arpot_dll_regexp(_ctx: &ScanContext, _re: RegexpId) -> Option<i64> {
    todo!()
}

#[module_export(name = "arpot.process")]
fn arpot_process_regexp(_ctx: &ScanContext, _re: RegexpId) -> Option<i64> {
    todo!()
}

// idp

#[module_export(name = "idp.rule_name")]
fn idp_rule_regexp(_ctx: &ScanContext, _re: RegexpId) -> Option<i64> {
    todo!()
}

// source

#[module_export(name = "source.url")]
fn source_url_regexp(_ctx: &ScanContext, _re: RegexpId) -> Option<i64> {
    todo!()
}

// parent_process

#[module_export(name = "parent_process.path")]
fn parent_process_path_regexp(
    _ctx: &ScanContext,
    _re: RegexpId,
) -> Option<i64> {
    todo!()
}
