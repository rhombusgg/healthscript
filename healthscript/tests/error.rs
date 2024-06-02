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
                    request_headers: [],
                    verb: None,
                    request_body: None,
                    url: "https://example.com",
                    status_code: None,
                    response_body: None,
                    response_headers: [],
                },
            ),
        )
    "#]];
    expected.assert_debug_eq(&ast);
}
