use crate::tests::test_rule_with_metadata;

#[test]
fn invalid_json_fails_gracefully() {
    let meta = "invalid json";

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name("test") >= 0 // `>=` ~> `true` iff is not undefined
        }
        "#,
        &[],
        meta.as_bytes(),
        0 // should match 0 files (`undefined` is not `>= 0`)
    );
}

#[test]
fn serde_tolerates_extra_junk() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        },
        "some_extra_junk": {
            "that": "should be ignored"
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name("") == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn file_name_string_json_empty_is_ok() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name("test") == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn file_name_regex_json_empty_is_ok() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn file_name_string_names_counted() {
    let meta = r#"
        {
        "file_names": ["test", "not a match", "test"],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name("test") == 2
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn file_name_regex_names_counted() {
    let meta = r#"
        {
        "file_names": ["test", "not a match", "test"],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name(/^test$/) == 2
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn file_name_string_other_ignored() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "test",
            "names": ["test"]
            }
        ],
        "arpot": {
            "processes": ["test"],
            "dlls": ["test"]
        },
        "idp": {
            "rules": ["test"]
        },
        "parent_process": {
            "paths": ["test"]
        },
        "source": {
            "urls": ["test"]
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name("test") == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn file_name_regex_other_ignored() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "test",
            "names": ["test"]
            }
        ],
        "arpot": {
            "processes": ["test"],
            "dlls": ["test"]
        },
        "idp": {
            "rules": ["test"]
        },
        "parent_process": {
            "paths": ["test"]
        },
        "source": {
            "urls": ["test"]
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.file.name(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn detection_name_string_empty_is_ok() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("test") == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn detection_name_regex_empty_is_ok() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn detection_name_string_counts() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": ["test", "not a match", "test"]
            },
            {
            "av": "",
            "names": ["test", "not a match", "test"]
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("test") == 4
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn detection_name_regex_counts() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": ["test", "not a match", "test"]
            },
            {
            "av": "",
            "names": ["test", "not a match", "test"]
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name(/^test$/) == 4
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn detection_name_string_other_ignored() {
    let meta = r#"
        {
        "file_names": ["test"],
        "detections": [
            {
            "av": "test",
            "names": []
            }
        ],
        "arpot": {
            "processes": ["test"],
            "dlls": ["test"]
        },
        "idp": {
            "rules": ["test"]
        },
        "parent_process": {
            "paths": ["test"]
        },
        "source": {
            "urls": ["test"]
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("test") == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn detection_name_regex_other_ignored() {
    let meta = r#"
        {
        "file_names": ["test"],
        "detections": [
            {
            "av": "test",
            "names": []
            }
        ],
        "arpot": {
            "processes": ["test"],
            "dlls": ["test"]
        },
        "idp": {
            "rules": ["test"]
        },
        "parent_process": {
            "paths": ["test"]
        },
        "source": {
            "urls": ["test"]
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn detection_name_string_filter_filters() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "filter",
            "names": ["test", "not a match", "test"]
            },
            {
            "av": "not filter",
            "names": ["test", "not a match", "test"]
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("filter", "test") == 2
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn detection_name_regex_filter_filters() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "filter",
            "names": ["test", "not a match", "test"]
            },
            {
            "av": "not filter",
            "names": ["test", "not a match", "test"]
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.detection.name("filter", /^test$/) == 2
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn arpot_dll_empty_ok() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.dll(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn arpot_dll_counts() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": ["test", "not a match", "test"]
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.dll(/^test$/) == 2
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn arpot_dll_other_ignored() {
    let meta = r#"
    {
    "file_names": ["test"],
    "detections": [
        {
        "av": "test",
        "names": ["test"]
        }
    ],
    "arpot": {
        "processes": ["test"],
        "dlls": []
    },
    "idp": {
        "rules": ["test"]
    },
    "parent_process": {
        "paths": ["test"]
    },
    "source": {
        "urls": ["test"]
    }
    }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.dll(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn arpot_process_empty_ok() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.process(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn arpot_process_counts() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": ["test", "not a match", "test"],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.process(/^test$/) == 2
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn arpot_process_other_ignored() {
    let meta = r#"
    {
    "file_names": ["test"],
    "detections": [
        {
        "av": "test",
        "names": ["test"]
        }
    ],
    "arpot": {
        "processes": [],
        "dlls": ["test"]
    },
    "idp": {
        "rules": ["test"]
    },
    "parent_process": {
        "paths": ["test"]
    },
    "source": {
        "urls": ["test"]
    }
    }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.arpot.process(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn idp_rule_name_empty_ok() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.idp.rule_name(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn idp_rule_name_counts() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": ["test", "not a match", "test"]
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.idp.rule_name(/^test$/) == 2
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn idp_rule_name_other_ignored() {
    let meta = r#"
    {
    "file_names": ["test"],
    "detections": [
        {
        "av": "test",
        "names": ["test"]
        }
    ],
    "arpot": {
        "processes": ["test"],
        "dlls": ["test"]
    },
    "idp": {
        "rules": []
    },
    "parent_process": {
        "paths": ["test"]
    },
    "source": {
        "urls": ["test"]
    }
    }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.idp.rule_name(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn source_url_empty_ok() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.source.url(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn source_url_counts() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": ["test", "not a match", "test"]
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.source.url(/^test$/) == 2
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn source_url_other_ignored() {
    let meta = r#"
    {
    "file_names": ["test"],
    "detections": [
        {
        "av": "test",
        "names": ["test"]
        }
    ],
    "arpot": {
        "processes": ["test"],
        "dlls": ["test"]
    },
    "idp": {
        "rules": ["test"]
    },
    "parent_process": {
        "paths": ["test"]
    },
    "source": {
        "urls": []
    }
    }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.source.url(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn parent_process_path_empty_ok() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": []
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.parent_process.path(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn parent_process_path_counts() {
    let meta = r#"
        {
        "file_names": [],
        "detections": [
            {
            "av": "",
            "names": []
            }
        ],
        "arpot": {
            "processes": [],
            "dlls": []
        },
        "idp": {
            "rules": []
        },
        "parent_process": {
            "paths": ["test", "not a match", "test"]
        },
        "source": {
            "urls": []
        }
        }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.parent_process.path(/^test$/) == 2
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}

#[test]
fn parent_process_path_ignored() {
    let meta = r#"
    {
    "file_names": ["test"],
    "detections": [
        {
        "av": "test",
        "names": ["test"]
        }
    ],
    "arpot": {
        "processes": ["test"],
        "dlls": ["test"]
    },
    "idp": {
        "rules": ["test"]
    },
    "parent_process": {
        "paths": []
    },
    "source": {
        "urls": ["test"]
    }
    }
    "#;

    test_rule_with_metadata!(
        r#"
        import "metadata"
        rule test {
            condition:
    		    metadata.parent_process.path(/^test$/) == 0
        }
        "#,
        &[],
        meta.as_bytes(),
        1
    );
}
