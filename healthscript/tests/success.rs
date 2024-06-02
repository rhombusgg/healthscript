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
                    status_code: None,
                    response_headers: [],
                    response_body: Some(
                        Regex(
                            Regex(
                                "hi",
                            ),
                        ),
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
                    status_code: None,
                    response_headers: [],
                    response_body: Some(
                        Jq {
                            body: ".x == 3",
                            expr: Main {
                                defs: [],
                                body: (
                                    Binary(
                                        (
                                            Path(
                                                (
                                                    Id,
                                                    0..1,
                                                ),
                                                [
                                                    (
                                                        Index(
                                                            (
                                                                Str(
                                                                    Str {
                                                                        fmt: None,
                                                                        parts: [
                                                                            Str(
                                                                                "x",
                                                                            ),
                                                                        ],
                                                                    },
                                                                ),
                                                                1..3,
                                                            ),
                                                        ),
                                                        Essential,
                                                    ),
                                                ],
                                            ),
                                            0..3,
                                        ),
                                        Ord(
                                            Eq,
                                        ),
                                        (
                                            Num(
                                                "3",
                                            ),
                                            6..7,
                                        ),
                                    ),
                                    0..7,
                                ),
                            },
                        },
                    ),
                },
            ),
        )
    "#]];
    expected.assert_debug_eq(&ast);
}
