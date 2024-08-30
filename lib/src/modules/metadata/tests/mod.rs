use crate::tests::test_rule;

#[test]
fn invalid_json_fails_gracefully() {
    let meta = include_bytes!("./testdata/invalid_json_fails_gracefully.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    not defined metadata.file.name("test")
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn serde_tolerates_extra_junk() {
    let meta = include_bytes!("./testdata/serde_tolerates_extra_junk.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name("") == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn file_name_string_json_empty_is_ok() {
    let meta = include_bytes!("./testdata/empty_valid_json.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name("test") == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn file_name_regex_json_empty_is_ok() {
    let meta = include_bytes!("./testdata/empty_valid_json.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn file_name_string_names_counted() {
    let meta =
        include_bytes!("./testdata/file_name_string_names_counted.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name("test") == 2
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn file_name_regex_names_counted() {
    let meta = include_bytes!("./testdata/file_name_regex_names_counted.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name(/^test$/) == 2
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn file_name_string_other_ignored() {
    let meta =
        include_bytes!("./testdata/file_name_string_other_ignored.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name("test") == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn file_name_regex_other_ignored() {
    let meta = include_bytes!("./testdata/file_name_regex_other_ignored.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn detection_name_string_empty_is_ok() {
    let meta = include_bytes!("./testdata/empty_valid_json.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("test") == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn detection_name_regex_empty_is_ok() {
    let meta = include_bytes!("./testdata/empty_valid_json.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn detection_name_string_counts() {
    let meta = include_bytes!("./testdata/detection_name_string_counts.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("test") == 4
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn detection_name_regex_counts() {
    let meta = include_bytes!("./testdata/detection_name_regex_counts.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name(/^test$/) == 4
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn detection_name_string_other_ignored() {
    let meta =
        include_bytes!("./testdata/detection_name_string_other_ignored.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("test") == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn detection_name_regex_other_ignored() {
    let meta =
        include_bytes!("./testdata/detection_name_regex_other_ignored.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn detection_name_string_filter_filters() {
    let meta =
        include_bytes!("./testdata/detection_name_string_filter_filters.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("filter", "test") == 2
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn detection_name_regex_filter_filters() {
    let meta =
        include_bytes!("./testdata/detection_name_regex_filter_filters.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("filter", /^test$/) == 2
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn arpot_dll_empty_ok() {
    let meta = include_bytes!("./testdata/empty_valid_json.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.dll(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn arpot_dll_counts() {
    let meta = include_bytes!("./testdata/arpot_dll_counts.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.dll(/^test$/) == 2
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn arpot_dll_other_ignored() {
    let meta = include_bytes!("./testdata/arpot_dll_other_ignored.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.dll(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn arpot_process_empty_ok() {
    let meta = include_bytes!("./testdata/empty_valid_json.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.process(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn arpot_process_counts() {
    let meta = include_bytes!("./testdata/arpot_process_counts.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.process(/^test$/) == 2
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn arpot_process_other_ignored() {
    let meta = include_bytes!("./testdata/arpot_process_other_ignored.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.process(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn idp_rule_name_empty_ok() {
    let meta = include_bytes!("./testdata/empty_valid_json.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.idp.rule_name(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn idp_rule_name_counts() {
    let meta = include_bytes!("./testdata/idp_rule_name_counts.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.idp.rule_name(/^test$/) == 2
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn idp_rule_name_other_ignored() {
    let meta = include_bytes!("./testdata/idp_rule_name_other_ignored.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.idp.rule_name(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn source_url_empty_ok() {
    let meta = include_bytes!("./testdata/empty_valid_json.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.source.url(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn source_url_counts() {
    let meta = include_bytes!("./testdata/source_url_counts.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.source.url(/^test$/) == 2
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn source_url_other_ignored() {
    let meta = include_bytes!("./testdata/source_url_other_ignored.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.source.url(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn parent_process_path_empty_ok() {
    let meta = include_bytes!("./testdata/empty_valid_json.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.parent_process.path(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn parent_process_path_counts() {
    let meta = include_bytes!("./testdata/parent_process_path_counts.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.parent_process.path(/^test$/) == 2
        }
        "#,
        &[],
        Some(meta),
        1
    );
}

#[test]
fn parent_process_path_ignored() {
    let meta = include_bytes!("./testdata/parent_process_path_ignored.json");

    test_rule!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.parent_process.path(/^test$/) == 0
        }
        "#,
        &[],
        Some(meta),
        1
    );
}
