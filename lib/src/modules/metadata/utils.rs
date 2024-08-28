use crate::modules::prelude::*;
use crate::modules::protos::metadata::*;

pub(super) fn get_json(ctx: &ScanContext) -> Option<json::JsonValue> {
    let received_json = ctx.module_output::<Metadata>()?.json();

    let parsed = json::parse(received_json).ok()?;

    Some(parsed)
}

pub(super) fn expect_str(json_value: &json::JsonValue) -> Option<&str> {
    match json_value {
        json::JsonValue::String(actual) => Some(actual),
        json::JsonValue::Short(short_actual) => Some(short_actual.as_str()),
        _ => None,
    }
}

pub(super) fn expect_array(
    json_value: &json::JsonValue,
) -> Option<&json::Array> {
    match json_value {
        json::JsonValue::Array(array) => Some(array),
        _ => None,
    }
}

pub(super) fn expect_object(
    json_value: &json::JsonValue,
) -> Option<&json::JsonValue> {
    match json_value {
        object @ json::JsonValue::Object(_) => Some(object),
        _ => None,
    }
}
