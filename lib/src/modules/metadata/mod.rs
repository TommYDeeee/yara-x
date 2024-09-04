use crate::compiler::RegexpId;
use crate::modules::prelude::*;
use crate::modules::protos::metadata::*;

use std::cell::RefCell;

use utils::Detection;
use utils::MetaJson;

#[cfg(test)]
mod tests;

mod utils;

// hack allowing us to "extend the return type" of the module `main` function
//
// the `main` is supposed to return `Metadata` (an empty struct),
// but we need the parsed `serde_json::Value` in the other functions
//
// solution is to have this "global" value, which is set in the `main` function
// and then forwarded into the other functions
thread_local! {
    static JSON_VALUE_GLOBAL_VAR: RefCell<Option<MetaJson>> = const {
        RefCell::new(None)
    };
}

/// hack to extract the json value from the thread-local storage
///
/// expects that the `main` function has already set the value
///
/// `take`s the value out of the storage (`Option<_>`), so it's not available anymore
fn pull_json_out_thin_air() -> Option<MetaJson> {
    JSON_VALUE_GLOBAL_VAR.with(|it| it.borrow_mut().take())
}

#[module_main]
fn main(_data: &[u8], meta: Option<&[u8]>) -> Metadata {
    // in case the `meta` is invalid json (or is `None`), the "parameter" in the function will be `None`
    // that should be propagated (`return None`) to the caller - graceful failure
    let parsed =
        serde_json::from_slice::<MetaJson>(meta.unwrap_or_default()).ok();

    // set the "parameter" of the function for it to pick up
    JSON_VALUE_GLOBAL_VAR.with(|it| {
        *it.borrow_mut() = parsed;
    });

    Metadata::new()
}

#[module_export(name = "file.name")]
fn name_string(
    ctx: &ScanContext,
    matched_string: RuntimeString,
) -> Option<i64> {
    let matched_string = matched_string.to_str(ctx).ok()?;

    Some(
        pull_json_out_thin_air()?
            .file_names
            .iter()
            .filter(|file_name| *file_name == matched_string)
            .count() as _,
    )
}

#[module_export(name = "file.name")]
fn name_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    Some(
        pull_json_out_thin_air()?
            .file_names
            .iter()
            .filter(|file_name| ctx.regexp_matches(re, file_name.as_bytes()))
            .count() as _,
    )
}

#[module_export(name = "detection.name")]
fn detection_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    Some(
        pull_json_out_thin_air()?
            .detections
            .iter()
            .flat_map(|Detection { names, .. }| names.iter())
            .filter(|detection_name| {
                ctx.regexp_matches(re, detection_name.as_bytes())
            })
            .count() as _,
    )
}

#[module_export(name = "detection.name")]
fn detection_string(
    ctx: &ScanContext,
    matching_string: RuntimeString,
) -> Option<i64> {
    let matching_string = matching_string.to_str(ctx).ok()?;

    Some(
        pull_json_out_thin_air()?
            .detections
            .iter()
            .flat_map(|Detection { names, .. }| names.iter())
            .filter(|detection_name| *detection_name == matching_string)
            .count() as _,
    )
}

#[module_export(name = "detection.name")]
fn detection_regexp_av(
    ctx: &ScanContext,
    av_filter: RuntimeString,
    re: RegexpId,
) -> Option<i64> {
    let av_filter = av_filter.to_str(ctx).ok()?;

    Some(
        pull_json_out_thin_air()?
            .detections
            .iter()
            .filter(|Detection { av, .. }| av == av_filter)
            .flat_map(|Detection { names, .. }| names.iter())
            .filter(|detection_name| {
                ctx.regexp_matches(re, detection_name.as_bytes())
            })
            .count() as _,
    )
}

#[module_export(name = "detection.name")]
fn detection_string_av(
    ctx: &ScanContext,
    av_filter: RuntimeString,
    matching_string: RuntimeString,
) -> Option<i64> {
    let av_filter = av_filter.to_str(ctx).ok()?;
    let matching_string = matching_string.to_str(ctx).ok()?;

    Some(
        pull_json_out_thin_air()?
            .detections
            .iter()
            .filter(|Detection { av, .. }| av == av_filter)
            .flat_map(|Detection { names, .. }| names.iter())
            .filter(|detection_name| *detection_name == matching_string)
            .count() as _,
    )
}

#[module_export(name = "arpot.dll")]
fn arpot_dll_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    Some(
        pull_json_out_thin_air()?
            .arpot
            .dlls
            .iter()
            .filter(|dll| ctx.regexp_matches(re, dll.as_bytes()))
            .count() as _,
    )
}

#[module_export(name = "arpot.process")]
fn arpot_process_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    Some(
        pull_json_out_thin_air()?
            .arpot
            .processes
            .iter()
            .filter(|process| ctx.regexp_matches(re, process.as_bytes()))
            .count() as _,
    )
}

#[module_export(name = "idp.rule_name")]
fn idp_rule_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    Some(
        pull_json_out_thin_air()?
            .idp
            .rules
            .iter()
            .filter(|rule| ctx.regexp_matches(re, rule.as_bytes()))
            .count() as _,
    )
}

#[module_export(name = "source.url")]
fn source_url_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    Some(
        pull_json_out_thin_air()?
            .source
            .urls
            .iter()
            .filter(|url| ctx.regexp_matches(re, url.as_bytes()))
            .count() as _,
    )
}

#[module_export(name = "parent_process.path")]
fn parent_process_path_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    Some(
        pull_json_out_thin_air()?
            .parent_process
            .paths
            .iter()
            .filter(|path| ctx.regexp_matches(re, path.as_bytes()))
            .count() as _,
    )
}
