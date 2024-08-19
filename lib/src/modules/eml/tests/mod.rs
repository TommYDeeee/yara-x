use pretty_assertions::assert_eq;

use crate::modules::tests::create_binary_from_zipped_ihex;
use crate::tests::rule_true;
use crate::tests::test_rule;

#[test]
fn header() {
    let eml = create_binary_from_zipped_ihex(
        "src/modules/eml/tests/testdata/accc36e59322cff8680fbaf24438adc61d200c9650db532a176080999c46cbff.in.zip",
    );

    rule_true!(
        r#"
        import "eml"
        rule test {
          condition:
            eml.header("X-VirusScan") == "safe"
            and eml.header("X-Other-Unknown") == "unknown header's value"
            and not defined eml.header("Non-existent")
        }
        "#,
        &eml
    );
}