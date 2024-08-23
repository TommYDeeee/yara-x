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

fn match_list_string(
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
fn detection_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    let json::JsonValue::Array(ref detections_array) =
        parsed_json[DETECTIONS_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            DETECTIONS_JSON_KEY, parsed_json
        );
    };

    let matches_count = detections_array
        .iter()
        .map(|it| {
            let json::JsonValue::Array(ref names) =
                it[NAMES_IN_DETECTIONS_JSON_KEY]
            else {
                panic!(
                    "expected element at key {} to be an array, but was {:?}",
                    NAMES_IN_DETECTIONS_JSON_KEY, it
                );
            };

            match_list_regex(ctx, names, re)
        })
        .sum::<usize>();

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_string(
    ctx: &ScanContext,
    matched_string: RuntimeString,
) -> Option<i64> {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    let json::JsonValue::Array(ref detections_array) =
        parsed_json[DETECTIONS_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            DETECTIONS_JSON_KEY, parsed_json
        );
    };

    let matches_count = detections_array
        .iter()
        .map(|it| {
            let json::JsonValue::Array(ref names) =
                it[NAMES_IN_DETECTIONS_JSON_KEY]
            else {
                panic!(
                    "expected element at key {} to be an array, but was {:?}",
                    NAMES_IN_DETECTIONS_JSON_KEY, it
                );
            };

            match_list_string(ctx, names, &matched_string)
        })
        .sum::<usize>();

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_regexp_av(
    ctx: &ScanContext,
    av_filter: RuntimeString,
    re: RegexpId,
) -> Option<i64> {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    let json::JsonValue::Array(ref detections_array) =
        parsed_json[DETECTIONS_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            DETECTIONS_JSON_KEY, parsed_json
        );
    };

    let matches_count = detections_array
        .iter()
        .filter_map(|it| {
            if match &it[AV_WITHIN_DETECTIONS_JSON_KEY] {
                json::JsonValue::String(av_value) => av_value,
                json::JsonValue::Short(short_av_value) => {
                    short_av_value.as_str()
                }
                other => panic!(
                    "expected the array item to be string, but was {:?}",
                    other
                ), // todo behavior in this case???
            } != av_filter.to_str(ctx).expect("should be able to convert")
            {
                return None;
            }

            let json::JsonValue::Array(ref names) =
                it[NAMES_IN_DETECTIONS_JSON_KEY]
            else {
                panic!(
                    "expected element at key {} to be an array, but was {:?}",
                    NAMES_IN_DETECTIONS_JSON_KEY, it
                );
            };

            Some(match_list_regex(ctx, names, re))
        })
        .sum::<usize>();

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_string_av(
    ctx: &ScanContext,
    av_filter: RuntimeString,
    matching_string: RuntimeString,
) -> Option<i64> {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    let json::JsonValue::Array(ref detections_array) =
        parsed_json[DETECTIONS_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            DETECTIONS_JSON_KEY, parsed_json
        );
    };

    let matches_count = detections_array
        .iter()
        .filter_map(|it| {
            if match &it[AV_WITHIN_DETECTIONS_JSON_KEY] {
                json::JsonValue::String(av_value) => av_value,
                json::JsonValue::Short(short_av_value) => {
                    short_av_value.as_str()
                }
                other => panic!(
                    "expected the array item to be string, but was {:?}",
                    other
                ), // todo behavior in this case???
            } != av_filter.to_str(ctx).expect("should be able to convert")
            {
                return None;
            }

            let json::JsonValue::Array(ref names) =
                it[NAMES_IN_DETECTIONS_JSON_KEY]
            else {
                panic!(
                    "expected element at key {} to be an array, but was {:?}",
                    NAMES_IN_DETECTIONS_JSON_KEY, it
                );
            };

            Some(match_list_string(ctx, names, &matching_string))
        })
        .sum::<usize>();

    Some(matches_count as _)
}

// arpot

#[module_export(name = "arpot.dll")]
fn arpot_dll_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    // let json::JsonValue::

    let ref arpot_object @ json::JsonValue::Object(_) =
        parsed_json[ARPOT_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an object, but was {:?}",
            ARPOT_JSON_KEY, parsed_json
        );
    };

    let json::JsonValue::Array(ref dlls) =
        arpot_object[DLLS_IN_ARPOT_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            DLLS_IN_ARPOT_JSON_KEY, arpot_object
        );
    };

    let matches_count = match_list_regex(ctx, dlls, re);

    Some(matches_count as _)
}

#[module_export(name = "arpot.process")]
fn arpot_process_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    // let json::JsonValue::

    let ref arpot_object @ json::JsonValue::Object(_) =
        parsed_json[ARPOT_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an object, but was {:?}",
            ARPOT_JSON_KEY, parsed_json
        );
    };

    let json::JsonValue::Array(ref processes) =
        arpot_object[PROCESSES_IN_ARPOT_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            PROCESSES_IN_ARPOT_JSON_KEY, arpot_object
        );
    };

    let matches_count = match_list_regex(ctx, processes, re);

    Some(matches_count as _)
}

// idp

#[module_export(name = "idp.rule_name")]
fn idp_rule_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    // let json::JsonValue::

    let ref idp_object @ json::JsonValue::Object(_) =
        parsed_json[IDP_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an object, but was {:?}",
            ARPOT_JSON_KEY, parsed_json
        );
    };

    let json::JsonValue::Array(ref rules) = idp_object[RULES_IN_IDP_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            RULES_IN_IDP_JSON_KEY, idp_object
        );
    };

    let matches_count = match_list_regex(ctx, rules, re);

    Some(matches_count as _)
}

// source

#[module_export(name = "source.url")]
fn source_url_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    let ref source_object @ json::JsonValue::Object(_) =
        parsed_json[SOURCE_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an object, but was {:?}", // todo update all the error messages
            ARPOT_JSON_KEY, parsed_json
        );
    };

    let json::JsonValue::Array(ref processes) =
        source_object[URLS_IN_SOURCE_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            URLS_IN_SOURCE_JSON_KEY, source_object
        );
    };

    let matches_count = match_list_regex(ctx, processes, re);

    Some(matches_count as _)
}

// parent_process

#[module_export(name = "parent_process.path")]
fn parent_process_path_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = ctx
        .module_output::<Metadata>()
        .expect("metadata should be set")
        .json();

    let parsed_json =
        json::parse(received_json).expect("json should be valid");

    let ref parent_process_object @ json::JsonValue::Object(_) =
        parsed_json[PARENT_PROCESS_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an object, but was {:?}", // todo update all the error messages
            ARPOT_JSON_KEY, parsed_json
        );
    };

    let json::JsonValue::Array(ref paths) =
        parent_process_object[PATHS_IN_PARENT_PROCESS_JSON_KEY]
    else {
        panic!(
            "expected element at key {} to be an array, but was {:?}",
            PATHS_IN_PARENT_PROCESS_JSON_KEY, parent_process_object
        );
    };

    let matches_count = match_list_regex(ctx, paths, re);

    Some(matches_count as _)
}
