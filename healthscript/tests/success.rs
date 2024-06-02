use expect_test::expect;
use healthscript::parse;

#[test]
fn single_url() {
    let input = r#"(https://example.com)"#;
    let (ast, _errors) = parse(input);

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

#[test]
fn http_verb() {
    let input = r#"[GET](https://example.com)"#;
    let (ast, _errors) = parse(input);

    let expected = expect![[r#"
        Some(
            Http(
                Http {
                    RequestHeader: [],
                    Verb: Some(
                        Get,
                    ),
                    RequestBody: None,
                    Url: "https://example.com",
                    StatusCode: None,
                },
            ),
        )
    "#]];
    expected.assert_debug_eq(&ast);
}
