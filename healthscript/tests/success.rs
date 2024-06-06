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
                    request_headers: [],
                    verb: None,
                    request_body: None,
                    url: "https://example.com",
                    timeout: None,
                    status_code: None,
                    response_headers: [],
                    response_body: None,
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
                    request_headers: [],
                    verb: Some(
                        Get,
                    ),
                    request_body: None,
                    url: "https://example.com",
                    timeout: None,
                    status_code: None,
                    response_headers: [],
                    response_body: None,
                },
            ),
        )
    "#]];
    expected.assert_debug_eq(&ast);
}

#[test]
fn http_verb_status_code() {
    let input = r#"[GET](https://example.com)[404]"#;
    let (ast, _errors) = parse(input);

    let expected = expect![[r#"
        Some(
            Http(
                Http {
                    request_headers: [],
                    verb: Some(
                        Get,
                    ),
                    request_body: None,
                    url: "https://example.com",
                    timeout: None,
                    status_code: Some(
                        404,
                    ),
                    response_headers: [],
                    response_body: None,
                },
            ),
        )
    "#]];
    expected.assert_debug_eq(&ast);
}

#[test]
fn response_body_regex() {
    let input = r#"(https://example.com)</hi/>"#;
    let (ast, _errors) = parse(input);

    let expected = expect![[r#"
        Some(
            Http(
                Http {
                    request_headers: [],
                    verb: None,
                    request_body: None,
                    url: "https://example.com",
                    timeout: None,
                    status_code: None,
                    response_headers: [],
                    response_body: Some(
                        Regex(hi),
                    ),
                },
            ),
        )
    "#]];
    expected.assert_debug_eq(&ast);
}

#[test]
fn response_body_jq() {
    let input = r#"(https://example.com)<(.x == 3)>"#;
    let (ast, _errors) = parse(input);

    let expected = expect![[r#"
        Some(
            Http(
                Http {
                    request_headers: [],
                    verb: None,
                    request_body: None,
                    url: "https://example.com",
                    timeout: None,
                    status_code: None,
                    response_headers: [],
                    response_body: Some(
                        Jq(.x == 3),
                    ),
                },
            ),
        )
    "#]];
    expected.assert_debug_eq(&ast);
}
