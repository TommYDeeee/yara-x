use super::utils::{expect_array, expect_object, expect_str, get_json};
use crate::compiler::RegexpId;
use crate::modules::prelude::*;

const IDP_JSON_KEY: &str = "idp";
const RULES_IN_IDP_JSON_KEY: &str = "rules";

#[module_export(name = "idp.rule_name")]
fn idp_rule_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx)?;

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
