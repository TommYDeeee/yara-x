use utils::{expect_array, expect_object, expect_str};

use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::metadata::*;
use crate::scanner::ScanInputRaw;

use std::cell::RefCell;

#[cfg(test)]
mod tests;

mod utils;

const FILE_NAMES_JSON_KEY: &str = "file_names";

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

// ugly hack to modify the "return type" of the module `main` function
//
// the `main` is supposed to return `Metadata` (an empty struct),
// but we need the parsed `serde_json::Value` in the other functions
//
// solution is to have this "global" value, which is set in the `main` function
// and then forwarded into the other functions
thread_local! {
    static JSON_VALUE_GLOBAL_VAR: RefCell<Option<json::JsonValue>> = const {
        RefCell::new(None)
    };
}

/// ugly hack to extract the json value from the thread-local storage
///
/// expects that the `main` function has already set the value
///
/// `take`s the value out of the storage (`Option<_>`), so it's not available anymore
fn pull_json_out_thin_air() -> Option<json::JsonValue> {
    JSON_VALUE_GLOBAL_VAR.with(|parameter| parameter.borrow_mut().take())
}

/// Converts a slice of bytes into a `json::JsonValue`
///
/// if the conversion fails, returns `json::JsonValue::Null` json
fn u8_to_json_value(data: &[u8]) -> json::JsonValue {
    let str_json: &str = std::str::from_utf8(data).unwrap_or_default();
    json::parse(str_json).unwrap_or(json::JsonValue::Null)
}

#[module_main]
fn main(data: &ScanInputRaw) -> Metadata {
    // in case this is `json::JsonValue::Null`, all the functions should return `None`
    let metadata_json = u8_to_json_value(data.meta.unwrap_or_default());

    JSON_VALUE_GLOBAL_VAR.with(|cache| {
        *cache.borrow_mut() = Some(metadata_json);
    });

    Metadata::new()
}

#[module_export(name = "file.name")]
fn name_string(
    ctx: &ScanContext,
    matched_string: RuntimeString,
) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;
    let matched_string = matched_string.to_str(ctx).ok()?;

    let file_names_array = expect_array(&received_json[FILE_NAMES_JSON_KEY])?;

    let mut matches_count = 0;
    for file_name in file_names_array.iter() {
        let file_name_str = expect_str(file_name)?;
        if file_name_str == matched_string {
            matches_count += 1;
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "file.name")]
fn name_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;

    let file_names_array = expect_array(&received_json[FILE_NAMES_JSON_KEY])?;

    let mut matches_count = 0;
    for file_name in file_names_array.iter() {
        let file_name_str = expect_str(file_name)?;
        if ctx.regexp_matches(re, file_name_str.as_bytes()) {
            matches_count += 1;
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;

    let detections_array = expect_array(&received_json[DETECTIONS_JSON_KEY])?;

    let mut matches_count = 0;
    for detection in detections_array.iter() {
        let names_array =
            expect_array(&detection[NAMES_IN_DETECTIONS_JSON_KEY])?;

        for name in names_array.iter() {
            let name_str = expect_str(name)?;
            if ctx.regexp_matches(re, name_str.as_bytes()) {
                matches_count += 1;
            }
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_string(
    ctx: &ScanContext,
    matching_string: RuntimeString,
) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;
    let matching_string = matching_string.to_str(ctx).ok()?;

    let detections_array = expect_array(&received_json[DETECTIONS_JSON_KEY])?;

    let mut matches_count = 0;
    for detection in detections_array.iter() {
        let names_array =
            expect_array(&detection[NAMES_IN_DETECTIONS_JSON_KEY])?;

        for name in names_array.iter() {
            let name_str = expect_str(name)?;
            if name_str == matching_string {
                matches_count += 1;
            }
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_regexp_av(
    ctx: &ScanContext,
    av_filter: RuntimeString,
    re: RegexpId,
) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;
    let av_filter = av_filter.to_str(ctx).ok()?;

    let detections_array = expect_array(&received_json[DETECTIONS_JSON_KEY])?;

    let mut matches_count = 0;
    for detection in detections_array.iter() {
        let actual_av = expect_str(&detection[AV_WITHIN_DETECTIONS_JSON_KEY])?;
        if actual_av != av_filter {
            continue;
        }

        let names_array =
            expect_array(&detection[NAMES_IN_DETECTIONS_JSON_KEY])?;

        for name in names_array.iter() {
            let name_str = expect_str(name)?;
            if ctx.regexp_matches(re, name_str.as_bytes()) {
                matches_count += 1;
            }
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "detection.name")]
fn detection_string_av(
    ctx: &ScanContext,
    av_filter: RuntimeString,
    matching_string: RuntimeString,
) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;
    let av_filter = av_filter.to_str(ctx).ok()?;
    let matching_string = matching_string.to_str(ctx).ok()?;

    let detections_array = expect_array(&received_json[DETECTIONS_JSON_KEY])?;

    let mut matches_count = 0;
    for detection in detections_array.iter() {
        let actual_av = expect_str(&detection[AV_WITHIN_DETECTIONS_JSON_KEY])?;
        if actual_av != av_filter {
            continue;
        }

        let names_array =
            expect_array(&detection[NAMES_IN_DETECTIONS_JSON_KEY])?;

        for name in names_array.iter() {
            let name_str = expect_str(name)?;
            if name_str == matching_string {
                matches_count += 1;
            }
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "arpot.dll")]
fn arpot_dll_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;

    let arpot_object = expect_object(&received_json[ARPOT_JSON_KEY])?;
    let dlls = expect_array(&arpot_object[DLLS_IN_ARPOT_JSON_KEY])?;

    let mut matches_count = 0;
    for dll in dlls.iter() {
        let dll_str = expect_str(dll)?;
        if ctx.regexp_matches(re, dll_str.as_bytes()) {
            matches_count += 1;
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "arpot.process")]
fn arpot_process_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;

    let arpot_object = expect_object(&received_json[ARPOT_JSON_KEY])?;
    let processes = expect_array(&arpot_object[PROCESSES_IN_ARPOT_JSON_KEY])?;

    let mut matches_count = 0;
    for process in processes.iter() {
        let process_str = expect_str(process)?;
        if ctx.regexp_matches(re, process_str.as_bytes()) {
            matches_count += 1;
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "idp.rule_name")]
fn idp_rule_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;

    let idp_object = expect_object(&received_json[IDP_JSON_KEY])?;
    let rules = expect_array(&idp_object[RULES_IN_IDP_JSON_KEY])?;

    let mut matches_count = 0;
    for rule in rules.iter() {
        let rule_str = expect_str(rule)?;
        if ctx.regexp_matches(re, rule_str.as_bytes()) {
            matches_count += 1;
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "source.url")]
fn source_url_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;

    let source_object = expect_object(&received_json[SOURCE_JSON_KEY])?;
    let urls = expect_array(&source_object[URLS_IN_SOURCE_JSON_KEY])?;

    let mut matches_count = 0;
    for url in urls.iter() {
        let url_str = expect_str(url)?;
        if ctx.regexp_matches(re, url_str.as_bytes()) {
            matches_count += 1;
        }
    }

    Some(matches_count as _)
}

#[module_export(name = "parent_process.path")]
fn parent_process_path_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = pull_json_out_thin_air()?;

    let parent_process_object =
        expect_object(&received_json[PARENT_PROCESS_JSON_KEY])?;
    let paths = expect_array(
        &parent_process_object[PATHS_IN_PARENT_PROCESS_JSON_KEY],
    )?;

    let mut matches_count = 0;
    for path in paths.iter() {
        let path_str = expect_str(path)?;
        if ctx.regexp_matches(re, path_str.as_bytes()) {
            matches_count += 1;
        }
    }

    Some(matches_count as _)
}
