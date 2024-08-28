// use super::utils::*;
use crate::compiler::RegexpId;
use crate::modules::prelude::*;

use super::utils::{expect_array, expect_object, expect_str, get_json};

const PARENT_PROCESS_JSON_KEY: &str = "parent_process";
const PATHS_IN_PARENT_PROCESS_JSON_KEY: &str = "paths";

#[module_export(name = "parent_process.path")]
fn parent_process_path_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx)?;

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
