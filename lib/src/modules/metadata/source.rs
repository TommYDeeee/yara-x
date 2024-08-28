use crate::compiler::RegexpId;
use crate::modules::prelude::*;

use super::utils::{expect_array, expect_object, expect_str, get_json};

const SOURCE_JSON_KEY: &str = "source";
const URLS_IN_SOURCE_JSON_KEY: &str = "urls";

#[module_export(name = "source.url")]
fn source_url_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx)?;

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
