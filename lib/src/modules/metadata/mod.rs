use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::metadata::*;

const FILE_NAMES_JSON_KEY: &str = "file_names"; // key in the json file

/// Counts the number of times a string appears in a json list of strings
pub fn match_list_string(
    ctx: &ScanContext,
    json_array: &json::Array,
    match_value: &RuntimeString,
) -> usize {
    let match_value =
        match_value.to_str(ctx).expect("conversion should be possible");

    json_array
        .iter()
        .filter_map(|it| {
            let actual = match it {
                json::JsonValue::String(actual) => actual,
                json::JsonValue::Short(short_actual) => short_actual.as_str(),
                other => panic!(
                    "expected the array item to be string, but was {:?}",
                    other
                ), // todo behavior in this case???
            };

            (actual == match_value).then_some(())
        })
        .count()
}

fn match_list_regex(
    ctx: &ScanContext, // todo how to test? (how to create the ctx instance?)
    json_array: &json::Array,
    re: RegexpId,
) -> usize {
    json_array
        .iter()
        .filter_map(|it| {
            let actual = match it {
                json::JsonValue::String(actual) => actual,
                json::JsonValue::Short(short_actual) => short_actual.as_str(),
                other => panic!(
                    "expected the array item to be string, but was {:?}",
                    other
                ), // todo behavior in this case???
            };

            ctx.regexp_matches(re, actual.as_bytes()).then_some(())
        })
        .count()
}

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

    let mut res = Metadata::new();
    res.set_json(parsed.to_string());
    res
}

fn get_file_names_array(ctx: &ScanContext) -> json::Array {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    let json::JsonValue::Array(file_names_array) =
        parsed_json[FILE_NAMES_JSON_KEY].to_owned()
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            FILE_NAMES_JSON_KEY, parsed_json
        );
    };

    file_names_array
}

#[module_export(name = "file.name")]
fn name_string(
    ctx: &ScanContext,
    matched_string: RuntimeString,
) -> Option<i64> {
    // todo get it from somewhere else than the ctx once implemented in upstream
    let file_names_array = get_file_names_array(ctx);

    let matches_count =
        match_list_string(ctx, &file_names_array, &matched_string);

    Some(matches_count as _)
}

#[module_export(name = "file.name")]
fn name_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    // todo get it from somewhere else than the ctx once implemented in upstream
    let file_names_array = get_file_names_array(ctx);

    let matches_count = match_list_regex(ctx, &file_names_array, re);

    Some(matches_count as _)
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
