use expect_test::expect;
use healthscript::parse;

#[test]
fn http_verb() {
    let input = r#"[hi](https://example.com)"#;
    let (ast, errors) = parse(input);

    assert_eq!(errors.len(), 1);

    let expected = expect![[r#"
        Some(
            Http(
                Http {
                    RequestHeader: [],
                    Verb: None,
                    RequestBody: None,
                    Url: "https://example.com",
                    StatusCode: None,
                },
            ),
        )
    "#]];
    expected.assert_debug_eq(&ast);
}
