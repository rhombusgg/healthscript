use healthscript::parse;

#[test]
fn url() {
    let input = r#"(https://example.com)"#;
    let (ast, _errors) = parse(input);

    let ast = ast.unwrap();

    assert_eq!(ast.to_string(), input);
}

#[test]
fn request_body_json() {
    let input = r#"<{"x":5}>(https://example.com)"#;
    let (ast, _errors) = parse(input);

    let ast = ast.unwrap();

    assert_eq!(ast.to_string(), input);
}

#[test]
fn request_body_text() {
    let input = r#"<"hello">(https://example.com)"#;
    let (ast, _errors) = parse(input);

    let ast = ast.unwrap();

    assert_eq!(ast.to_string(), input);
}

#[test]
fn request_body_base64() {
    let input = r#"<+uwgVQA=>(https://example.com)"#;
    let (ast, _errors) = parse(input);

    let ast = ast.unwrap();

    assert_eq!(ast.to_string(), input);
}

#[test]
fn http_verb() {
    let input = r#"[OPTIONS](https://example.com)"#;
    let (ast, _errors) = parse(input);

    let ast = ast.unwrap();

    assert_eq!(ast.to_string(), input);
}

#[test]
fn response_body_jq() {
    let input = r#"(https://example.com)<(.x == 3)>"#;
    let (ast, _errors) = parse(input);

    let ast = ast.unwrap();

    assert_eq!(ast.to_string(), input);
}
