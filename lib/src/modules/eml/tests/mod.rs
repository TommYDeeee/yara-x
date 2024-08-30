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

#[test]
fn sender_hash() {
    // sender's mail address is in header Sender
    let eml = create_binary_from_zipped_ihex(
        "src/modules/eml/tests/testdata/accc36e59322cff8680fbaf24438adc61d200c9650db532a176080999c46cbff.in.zip",
    );

    rule_true!(
        r#"
        import "eml"
        rule test {
          condition:
            eml.sender_hash() == "9905f10c7c8a75929fb3222ca17c7884ff6143abae12695dc1d32a190b1b60f4"
        }
        "#,
        &eml
    );

    // sender's mail address only in header From
    let eml = create_binary_from_zipped_ihex(
        "src/modules/eml/tests/testdata/a0dea55abdb4de2e2701b908752c0bd0ee12ec6f2cf96424fb6083729d380b8f.in.zip",
    );

    rule_true!(
        r#"
        import "eml"
        rule test {
          condition:
            eml.sender_hash() == "9e7d7362f7bfc00a59a23057b828658ec237998cccbed95b2c626f72f3f8341a"
        }
        "#,
        &eml
    );
}
