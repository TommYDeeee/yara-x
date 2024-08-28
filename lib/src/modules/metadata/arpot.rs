use super::utils::{expect_array, expect_object, expect_str, get_json};
use crate::compiler::RegexpId;
use crate::modules::prelude::*;

const ARPOT_JSON_KEY: &str = "arpot";
const DLLS_IN_ARPOT_JSON_KEY: &str = "dlls";
const PROCESSES_IN_ARPOT_JSON_KEY: &str = "processes";

#[module_export(name = "arpot.dll")]
fn arpot_dll_regexp(ctx: &ScanContext, re: RegexpId) -> Option<i64> {
    let received_json = get_json(ctx)?;

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
    let received_json = get_json(ctx)?;

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
