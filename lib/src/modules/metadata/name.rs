use super::utils::*;
use crate::compiler::RegexpId;
use crate::modules::prelude::*;

const FILE_NAMES_JSON_KEY: &str = "file_names";

#[module_export(name = "file.name")]
fn name_string(
    ctx: &ScanContext,
    matched_string: RuntimeString,
) -> Option<i64> {
    let received_json = get_json(ctx)?;
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
    let received_json = get_json(ctx)?;

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
