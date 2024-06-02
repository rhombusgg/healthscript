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
                    request_header: [],
                    verb: None,
                    request_body: None,
                    url: "https://example.com",
                    status_code: None,
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
                    request_header: [],
                    verb: Some(
                        Get,
                    ),
                    request_body: None,
                    url: "https://example.com",
                    status_code: None,
                },
            ),
        )
    "#]];
    expected.assert_debug_eq(&ast);
}
