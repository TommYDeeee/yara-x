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
