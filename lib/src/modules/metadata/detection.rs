use super::utils::{expect_array, expect_str, get_json};
use crate::compiler::RegexpId;
use crate::modules::prelude::*;

const DETECTIONS_JSON_KEY: &str = "detections";
const NAMES_IN_DETECTIONS_JSON_KEY: &str = "names";
const AV_WITHIN_DETECTIONS_JSON_KEY: &str = "av";

#[module_export(name = "detection.name")]
fn detection_regex(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx)?;

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
    let received_json = get_json(ctx)?;
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
    let received_json = get_json(ctx)?;
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
    let received_json = get_json(ctx)?;
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
