use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::metadata::*;

// todo; just wanted to see how stuff works, serious refactor needed
// - [x] make it work
// - [ ] make it right
// - [ ] make it fast

const FILE_NAMES_JSON_KEY: &str = "file_names"; // key in the json file

const DETECTIONS_JSON_KEY: &str = "detections";
const NAMES_IN_DETECTIONS_JSON_KEY: &str = "names";
const AV_WITHIN_DETECTIONS_JSON_KEY: &str = "av";

const ARPOT_JSON_KEY: &str = "arpot";
const DLLS_IN_ARPOT_JSON_KEY: &str = "dlls";
const PROCESSES_IN_ARPOT_JSON_KEY: &str = "processes";

const IDP_JSON_KEY: &str = "idp";
const RULES_IN_IDP_JSON_KEY: &str = "rules";

const SOURCE_JSON_KEY: &str = "source";
const URLS_IN_SOURCE_JSON_KEY: &str = "urls";

const PARENT_PROCESS_JSON_KEY: &str = "parent_process";
const PATHS_IN_PARENT_PROCESS_JSON_KEY: &str = "paths";

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

fn get_json(ctx: &ScanContext) -> json::JsonValue {
    // todo get it from somewhere else than the ctx once implemented in upstream
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    json::parse(received_json).expect("json should be valid")
}

// todo this function is often used in the context of arrays, where we assume that all the values are strings
// vs this is not documented anywhere
// original .c code "solves" this by having UB (`strcmp(maybe_null, _)` in `match_list_string`)
// -> using this function (panicking on non-string values) is likely the way to go
// would still be nice to write this down somewhere
fn expect_str(json_value: &json::JsonValue) -> &str {
    match json_value {
        json::JsonValue::String(actual) => actual,
        json::JsonValue::Short(short_actual) => short_actual.as_str(),
        other => panic!("expected string value, found {:?}", other),
    }
}

fn expect_array(json_value: &json::JsonValue) -> &json::Array {
    match json_value {
        json::JsonValue::Array(array) => array,
        other => panic!("expected array value, found {:?}", other),
    }
}

fn expect_object(json_value: &json::JsonValue) -> &json::JsonValue {
    match json_value {
        object @ json::JsonValue::Object(_) => object,
        other => panic!("expected object value, found {:?}", other),
    }
}

#[module_export(name = "file.name")]
fn name_string(
    ctx: &ScanContext,
    matched_string: RuntimeString,
) -> Option<i64> {
    let received_json = get_json(ctx);
    let matched_string =
        matched_string.to_str(ctx).expect("should be able to convert");

    let file_names_array = expect_array(&received_json[FILE_NAMES_JSON_KEY]);

    let matches_count = file_names_array
        .iter()
        .filter(|fname| expect_str(fname) == matched_string)
        .count();

    Some(matches_count as _)
}

#[module_export(name = "file.name")]
fn name_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx);

    let file_names_array = expect_array(&received_json[FILE_NAMES_JSON_KEY]);

    let matches_count = file_names_array
        .iter()
        .filter(|fname| ctx.regexp_matches(re, expect_str(fname).as_bytes()))
        .count();

    Some(matches_count as _)
}

// detection

#[module_export(name = "detection.name")]
fn detection_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx);

    let detections_array = expect_array(&received_json[DETECTIONS_JSON_KEY]);

    let matches_count = detections_array
        .iter()
        .flat_map(|detection| {
            expect_array(&detection[NAMES_IN_DETECTIONS_JSON_KEY])
        })
        .filter(|detection_name| {
            ctx.regexp_matches(re, expect_str(detection_name).as_bytes())
        })
        .count();

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_string(
    ctx: &ScanContext,
    matching_string: RuntimeString,
) -> Option<i64> {
    let received_json = get_json(ctx);
    let matching_string =
        matching_string.to_str(ctx).expect("should be able to convert");

    let detections_array = expect_array(&received_json[DETECTIONS_JSON_KEY]);

    let matches_count = detections_array
        .iter()
        .flat_map(|detection| {
            expect_array(&detection[NAMES_IN_DETECTIONS_JSON_KEY])
        })
        .filter(|detection_name| expect_str(detection_name) == matching_string)
        .count();

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_regexp_av(
    ctx: &ScanContext,
    av_filter: RuntimeString,
    re: RegexpId,
) -> Option<i64> {
    let received_json = get_json(ctx);
    let av_filter = av_filter.to_str(ctx).expect("should be able to convert");

    let detections_array = expect_array(&received_json[DETECTIONS_JSON_KEY]);

    let matches_count = detections_array
        .iter()
        .filter(|detection| {
            let actual_av =
                expect_str(&detection[AV_WITHIN_DETECTIONS_JSON_KEY]);
            actual_av == av_filter
        })
        .flat_map(|detection| {
            expect_array(&detection[NAMES_IN_DETECTIONS_JSON_KEY])
        })
        .filter(|detection_name| {
            ctx.regexp_matches(re, expect_str(detection_name).as_bytes())
        })
        .count();

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_string_av(
    ctx: &ScanContext,
    av_filter: RuntimeString,
    matching_string: RuntimeString,
) -> Option<i64> {
    let received_json = get_json(ctx);
    let av_filter = av_filter.to_str(ctx).expect("should be able to convert");
    let matching_string =
        matching_string.to_str(ctx).expect("should be able to convert");

    let detections_array = expect_array(&received_json[DETECTIONS_JSON_KEY]);

    let matches_count = detections_array
        .iter()
        .filter(|detection| {
            let actual_av =
                expect_str(&detection[AV_WITHIN_DETECTIONS_JSON_KEY]);
            actual_av == av_filter
        })
        .flat_map(|detection| {
            expect_array(&detection[NAMES_IN_DETECTIONS_JSON_KEY])
        })
        .filter(|detection_name| expect_str(detection_name) == matching_string)
        .count();

    Some(matches_count as _)
}

// arpot

#[module_export(name = "arpot.dll")]
fn arpot_dll_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx);

    let arpot_object = expect_object(&received_json[ARPOT_JSON_KEY]);
    let dlls = expect_array(&arpot_object[DLLS_IN_ARPOT_JSON_KEY]);

    let matches_count = dlls
        .iter()
        .filter(|dll| ctx.regexp_matches(re, expect_str(dll).as_bytes()))
        .count();

    Some(matches_count as _)
}

#[module_export(name = "arpot.process")]
fn arpot_process_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx);

    let arpot_object = expect_object(&received_json[ARPOT_JSON_KEY]);
    let processes = expect_array(&arpot_object[PROCESSES_IN_ARPOT_JSON_KEY]);

    let matches_count = processes
        .iter()
        .filter(|process| {
            ctx.regexp_matches(re, expect_str(process).as_bytes())
        })
        .count();

    Some(matches_count as _)
}

// idp

#[module_export(name = "idp.rule_name")]
fn idp_rule_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx);

    let idp_object = expect_object(&received_json[IDP_JSON_KEY]);
    let rules = expect_array(&idp_object[RULES_IN_IDP_JSON_KEY]);

    let matches_count = rules
        .iter()
        .filter(|rule| ctx.regexp_matches(re, expect_str(rule).as_bytes()))
        .count();

    Some(matches_count as _)
}

// source

#[module_export(name = "source.url")]
fn source_url_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx);

    let source_object = expect_object(&received_json[SOURCE_JSON_KEY]);
    let urls = expect_array(&source_object[URLS_IN_SOURCE_JSON_KEY]);

    let matches_count = urls
        .iter()
        .filter(|url| ctx.regexp_matches(re, expect_str(url).as_bytes()))
        .count();

    Some(matches_count as _)
}

// parent_process

#[module_export(name = "parent_process.path")]
fn parent_process_path_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx);

    let parent_process_object =
        expect_object(&received_json[PARENT_PROCESS_JSON_KEY]);
    let paths =
        expect_array(&parent_process_object[PATHS_IN_PARENT_PROCESS_JSON_KEY]);

    let matches_count = paths
        .iter()
        .filter(|path| ctx.regexp_matches(re, expect_str(path).as_bytes()))
        .count();

    Some(matches_count as _)
}
