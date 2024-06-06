use std::{fmt::Display, ops::Range};

use ariadne::{Color, Label, Report, ReportKind, Source};
use base64::Engine;
use chumsky::{prelude::*, text::whitespace, util::MaybeRef};

use regex::Regex;
use serde_json::Value;
use strsim::normalized_levenshtein;
use yansi::Paint;

pub type Span = SimpleSpan<usize>;
pub type Spanned<T> = (T, Span);

#[derive(Debug)]
pub enum Expr<'a> {
    Http(Http<'a>),
    Tcp(Tcp<'a>),
    Ping(Ping<'a>),
    Dns(Dns<'a>),
    Invalid,
    And(Box<Expr<'a>>, Box<Expr<'a>>),
}

impl Display for Expr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Http(http) => write!(f, "{}", http),
            Expr::Tcp(tcp) => write!(f, "{}", tcp),
            Expr::Ping(ping) => write!(f, "{}", ping),
            Expr::Dns(dns) => write!(f, "{}", dns),
            Expr::Invalid => write!(f, "Invalid"),
            Expr::And(lhs, rhs) => write!(f, "{} and {}", lhs, rhs),
        }
    }
}

#[derive(Debug)]
pub struct Http<'a> {
    request_headers: Vec<(&'a str, &'a str)>,
    verb: Option<HttpVerb>,
    request_body: Option<Body<'a>>,
    url: &'a str,
    timeout: Option<u64>,
    status_code: Option<u16>,
    response_headers: Vec<(&'a str, &'a str)>,
    response_body: Option<Body<'a>>,
}

#[derive(Debug)]
enum HttpRequest<'a> {
    Header((&'a str, &'a str)),
    Verb(Spanned<HttpVerb>),
    Body(Spanned<Body<'a>>),
}

#[derive(Debug)]
enum HttpResponse<'a> {
    Timeout(Spanned<Option<u64>>),
    StatusCode(Spanned<Option<u16>>),
    Body(Spanned<Body<'a>>),
    Header((&'a str, &'a str)),
}

#[derive(Debug)]
enum TcpResponse<'a> {
    Timeout(Spanned<Option<u64>>),
    Body(Spanned<Body<'a>>),
}

impl Display for Http<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (name, value) in self.request_headers.iter() {
            write!(f, "[{}: {}]", name, value)?;
        }

        if let Some(verb) = &self.verb {
            write!(f, "[{}]", verb)?;
        }

        if let Some(body) = &self.request_body {
            write!(f, "{}", body)?;
        }

        write!(f, "({})", self.url)?;

        if let Some(timeout) = self.timeout {
            write!(f, "[{}s]", timeout)?;
        }

        if let Some(status_code) = self.status_code {
            write!(f, "[{}]", status_code)?;
        }

        for (name, value) in self.response_headers.iter() {
            write!(f, "[{}: {}]", name, value)?;
        }

        if let Some(body) = &self.response_body {
            write!(f, "{}", body)?;
        }

        Ok(())
    }
}
#[derive(Clone, Debug)]
pub enum Body<'a> {
    Json(Value),
    Text(String),
    Base64(&'a str),
    Jq { body: &'a str, expr: jaq_syn::Main },
    Regex(Regex),
    Invalid,
}

impl Display for Body<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::Json(value) => {
                let json_string = serde_json::to_string(value).unwrap();
                let hashes = largest_escape_sequence(json_string.as_str(), '}');
                let hashes_string = "#".repeat(hashes + 1);

                write!(f, "<{}{}{}>", hashes_string, value, hashes_string)?
            }
            Body::Text(text) => {
                let text = escape_string(text);
                let hashes = largest_escape_sequence(text.as_str(), '"');
                let hashes_string = "#".repeat(hashes + 1);

                write!(f, r#"<{}"{}"{}>"#, hashes_string, text, hashes_string)?
            }
            Body::Base64(base64) => write!(f, "<{}>", base64)?,
            Body::Jq { body, expr: _ } => write!(f, "<({})>", body)?,
            Body::Regex(r) => write!(f, "</{}/>", r)?,
            Body::Invalid => write!(f, "")?,
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpVerb {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    Invalid,
}

impl Display for HttpVerb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_uppercase())?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Tcp<'a> {
    uri: &'a str,
    timeout: Option<u64>,
    response_body: Option<Body<'a>>,
}

impl Display for Tcp<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(tcp://{})", self.uri)?;

        if let Some(timeout) = self.timeout {
            write!(f, "[{}s]", timeout)?;
        }

        if let Some(body) = &self.response_body {
            write!(f, "{}", body)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Ping<'a> {
    uri: &'a str,
    timeout: Option<u64>,
}

impl Display for Ping<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(ping://{})", self.uri)?;

        if let Some(timeout) = self.timeout {
            write!(f, "[{}s]", timeout)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Dns<'a> {
    uri: &'a str,
    server: Option<&'a str>,
    timeout: Option<u64>,
}

impl Display for Dns<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(server) = self.server {
            write!(f, "(dns://{}/{})", self.uri, server)?;
        } else {
            write!(f, "(dns://{})", self.uri)?;
        }

        if let Some(timeout) = self.timeout {
            write!(f, "[{}s]", timeout)?;
        }

        Ok(())
    }
}

fn closest_verb(verb: &str) -> Result<HttpVerb, Option<(&'static str, HttpVerb)>> {
    match verb {
        "GET" => Ok(HttpVerb::Get),
        "HEAD" => Ok(HttpVerb::Head),
        "POST" => Ok(HttpVerb::Post),
        "PUT" => Ok(HttpVerb::Put),
        "DELETE" => Ok(HttpVerb::Delete),
        "CONNECT" => Ok(HttpVerb::Connect),
        "OPTIONS" => Ok(HttpVerb::Options),
        "TRACE" => Ok(HttpVerb::Trace),
        "PATCH" => Ok(HttpVerb::Patch),
        _ => {
            let lower = verb.to_uppercase();
            let verbs = [
                ("GET", HttpVerb::Get),
                ("HEAD", HttpVerb::Head),
                ("POST", HttpVerb::Post),
                ("PUT", HttpVerb::Put),
                ("DELETE", HttpVerb::Delete),
                ("CONNECT", HttpVerb::Connect),
                ("OPTIONS", HttpVerb::Options),
                ("TRACE", HttpVerb::Trace),
                ("PATCH", HttpVerb::Patch),
            ];

            let mut closest = None;
            let mut distance = 0.0;

            for v in verbs.iter() {
                let d = normalized_levenshtein(&lower, v.0);
                if d > distance {
                    distance = d;
                    closest = Some(v.clone());
                }
            }

            if distance > 0.5 {
                Err(closest)
            } else {
                Err(None)
            }
        }
    }
}

fn validate_http_code(code: &str) -> Result<u16, Option<(u16, &'static str)>> {
    let code_num = code.parse::<u16>().ok();
    if let Some(code) = code_num {
        if let Ok(code) = reqwest::StatusCode::from_u16(code) {
            return Ok(code.as_u16());
        }
    }

    let http_codes = [
        (100, "Continue"),
        (101, "Switching Protocols"),
        (102, "Processing"),
        (103, "Early Hints"),
        (200, "OK"),
        (201, "Created"),
        (202, "Accepted"),
        (203, "Non-Authoritative Information"),
        (204, "No Content"),
        (205, "Reset Content"),
        (206, "Partial Content"),
        (207, "Multi-Status"),
        (208, "Already Reported"),
        (218, "This is fine"),
        (226, "IM Used"),
        (300, "Multiple Choices"),
        (301, "Moved Permanently"),
        (302, "Found"),
        (302, "Moved Temporarily"),
        (303, "See Other"),
        (304, "Not Modified"),
        (305, "Use Proxy"),
        (306, "Switch Proxy"),
        (307, "Temporary Redirect"),
        (308, "Permanent Redirect"),
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (402, "Payment Required"),
        (403, "Forbidden"),
        (404, "Not Found"),
        (405, "Method Not Allowed"),
        (406, "Not Acceptable"),
        (407, "Proxy Authentication Required"),
        (408, "Request Timeout"),
        (409, "Conflict"),
        (410, "Gone"),
        (411, "Length Required"),
        (412, "Precondition Failed"),
        (413, "Payload Too Large"),
        (414, "URI Too Long"),
        (415, "Unsupported Media Type"),
        (416, "Range Not Satisfiable"),
        (417, "Expectation Failed"),
        (418, "I'm a teapot"),
        (419, "Page Expired"),
        (421, "Misdirected Request"),
        (422, "Unprocessable Entity"),
        (423, "Locked"),
        (424, "Failed Dependency"),
        (425, "Too Early"),
        (426, "Upgrade Required"),
        (428, "Precondition Required"),
        (429, "Too Many Requests"),
        (430, "Request Header Fields Too Large"),
        (431, "Request Header Fields Too Large"),
        (440, "Login Timeout"),
        (444, "No Response"),
        (449, "Retry With"),
        (450, "Blocked By Windows Parental Controls"),
        (451, "Unavailable For Legal Reasons"),
        (460, "Client closed connection prematurely"),
        (463, "Too many forwarded IP addresses"),
        (464, "Incompatible protocol"),
        (494, "Request header too large"),
        (495, "SSL Certificate Error"),
        (496, "SSL Certificate Required"),
        (497, "HTTP Request Sent to HTTPS Port"),
        (498, "Invalid Token"),
        (499, "Client Closed Request"),
        (500, "Internal Server Error"),
        (501, "Not Implemented"),
        (502, "Bad Gateway"),
        (503, "Service Unavailable"),
        (504, "Gateway Timeout"),
        (505, "HTTP Version Not Supported"),
        (506, "Variant Also Negotiates"),
        (507, "Insufficient Storage"),
        (508, "Loop Detected"),
        (509, "Bandwidth Limit Exceeded"),
        (510, "Not Extended"),
        (511, "Network Authentication Required"),
        (520, "Web server is returning an unknown error"),
        (521, "Web server is down"),
        (522, "Connection timed out"),
        (523, "Origin is unreachable"),
        (524, "A Timeout Occurred"),
        (525, "SSL handshake failed"),
        (526, "Invalid SSL certificate"),
        (527, "Railgun Listener to Origin"),
        (529, "The service is overloaded"),
        (530, "Site Frozen"),
        (561, "Unauthorized"),
        (598, "Network read timeout error"),
        (599, "Network Connect Timeout Error"),
        (999, "Request Denied"),
    ];

    for c in http_codes.iter() {
        if c.1.to_lowercase() == code.to_lowercase() {
            return Ok(c.0);
        }
    }

    let mut closest = http_codes[0];
    let mut distance = 0.0;

    for c in http_codes.iter() {
        let d = normalized_levenshtein(&code.to_lowercase(), &c.1.to_lowercase());
        if d > distance {
            distance = d;
            closest = *c;
        }
    }

    if distance > 0.5 {
        return Err(Some(closest));
    }
    Err(None)
}

enum MyError<'a> {
    Rich(Rich<'a, char>),
    Report(Report<'a, Range<usize>>),
}

fn unescape_c_style(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next_c) = chars.peek() {
                match next_c {
                    'n' => {
                        result.push('\n');
                        chars.next();
                    }
                    't' => {
                        result.push('\t');
                        chars.next();
                    }
                    'r' => {
                        result.push('\r');
                        chars.next();
                    }
                    '\\' => {
                        result.push('\\');
                        chars.next();
                    }
                    '"' => {
                        result.push('"');
                        chars.next();
                    }
                    '\'' => {
                        result.push('\'');
                        chars.next();
                    }
                    '0' => {
                        result.push('\0');
                        chars.next();
                    }
                    _ => {
                        result.push(c);
                    }
                }
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

fn escape_string(input: &str) -> String {
    let mut result = String::new();

    for c in input.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\t' => result.push_str("\\t"),
            '\r' => result.push_str("\\r"),
            '\\' => result.push_str("\\\\"),
            '\'' => result.push_str("\\'"),
            '\0' => result.push_str("\\0"),
            _ => result.push(c),
        }
    }

    result
}

fn largest_escape_sequence(input: &str, delimiter: char) -> usize {
    let mut max_hashes = 0;
    let mut current_hashes = 0;
    let mut in_sequence = false;

    for c in input.chars() {
        match c {
            '#' if in_sequence => current_hashes += 1,
            '>' if in_sequence => {
                if current_hashes > max_hashes {
                    max_hashes = current_hashes;
                }
                in_sequence = false;
            }
            _ => {
                if c == delimiter {
                    current_hashes = 0;
                    in_sequence = true;
                } else {
                    in_sequence = false;
                }
            }
        }
    }

    max_hashes
}

impl<'a> chumsky::error::Error<'a, &'a str> for MyError<'a> {
    fn expected_found<E: IntoIterator<Item = Option<MaybeRef<'a, char>>>>(
        expected: E,
        found: Option<MaybeRef<'a, char>>,
        span: SimpleSpan<usize>,
    ) -> MyError<'a> {
        MyError::Rich(
            <Rich<'_, char, SimpleSpan<usize>, &'static str> as chumsky::error::Error<
                '_,
                &'_ str,
            >>::expected_found::<E>(expected, found, span),
        )
    }
}

fn parser<'a>() -> impl Parser<'a, &'a str, Expr<'a>, extra::Full<MyError<'a>, (), usize>> {
    let header = just("[")
        .ignore_then(text::ident())
        .then_ignore(just(":").then(whitespace()))
        .then(text::ident())
        .then_ignore(just("]").recover_with(skip_then_retry_until(any().ignored(), end())))
        .boxed();

    let http_verb = text::ident()
        .validate(|verb_str: &str, e, emitter| match closest_verb(verb_str) {
            Ok(verb) => (verb, e.span()),
            Err(verb) => match verb {
                None => {
                    let span: SimpleSpan<usize> = e.span();
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Unknown HTTP verb")
                        .with_label(
                            Label::new(span.into_range())
                                .with_message(format!("Unknown HTTP verb {}", verb_str.bold()))
                                .with_color(Color::Red),
                        )
                        .with_note("See https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods")
                        .finish();
                    emitter.emit(MyError::Report(report));
                    (HttpVerb::Invalid, e.span())
                }
                Some(v) => {
                    let span: SimpleSpan<usize> = e.span();
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Unknown HTTP verb")
                        .with_label(
                            Label::new(span.into_range())
                                .with_message(format!("Unknown HTTP verb {}", verb_str.bold()))
                                .with_color(Color::Red),
                        )
                        .with_help(format!("Did you mean {}?", v.0.bold()))
                        .finish();
                    emitter.emit(MyError::Report(report));
                    (HttpVerb::Invalid, e.span())
                }
            },
        })
        .delimited_by(just("["), just("]"))
        .boxed();

    let timeout = text::int(10)
        .then(none_of("]"))
        .validate(|(time, unit): (&str, char), e, emitter| {
            let span: SimpleSpan<usize> = e.span();
            let time = time.parse::<u64>().unwrap();

            match unit {
                's' => (Some(time), span),
                'm' => (Some(time * 60), span),
                _ => {
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Invalid timeout")
                        .with_label(
                            Label::new(span.into_range())
                                .with_message("Invalid timeout duration")
                                .with_color(Color::Red),
                        )
                        .with_help(format!(
                            "Did you mean {}{}?",
                            time.to_string().bold(),
                            's'.bold().yellow()
                        ))
                        .with_note("Timeouts must be a number followed by a unit (s, m)")
                        .finish();
                    emitter.emit(MyError::Report(report));
                    (None, span)
                }
            }
        })
        .delimited_by(just("["), just("]"))
        .boxed();

    let url = choice((just("http://"), just("https://")))
        .then(none_of(")").repeated())
        .to_slice()
        .validate(|url: &str, e, emitter| {
            if reqwest::Url::parse(url).is_err() {
                emitter.emit(MyError::Rich(Rich::custom(e.span(), "Invalid URL")))
            }
            url
        })
        .delimited_by(just("("), just(")"))
        .boxed();

    let hashes = just('#').repeated();
    let start = hashes.count().then_ignore(just('{'));
    let end = just('}')
        .then(hashes.configure(|cfg, ctx| cfg.exactly(*ctx)))
        .then(just(">"));
    let inner = any().and_is(end.not()).repeated().to_slice();
    let raw_json = just("<").ignore_then(start.ignore_with_ctx(inner.then_ignore(end)));
    let body_json = raw_json
        .validate(|body: &str, e, emitter| {
            let span: SimpleSpan<usize> = e.span();

            match serde_json::from_str(format!("{{{}}}", body).as_str()) {
                Ok(value) => (Body::Json(value), span),
                Err(err) => {
                    let column = err.column();
                    let json_span =
                        SimpleSpan::new(span.start + column - 2, span.start + column - 2);

                    let report = Report::build(ReportKind::Error, (), json_span.start)
                        .with_message("Invalid JSON body")
                        .with_label(
                            Label::new(json_span.into_range())
                                .with_message(err.to_string())
                                .with_color(Color::Yellow),
                        )
                        .with_label(
                            Label::new(span.into_range())
                                .with_message("Invalid JSON body")
                                .with_color(Color::Red),
                        )
                        .finish();
                    emitter.emit(MyError::Report(report));

                    (Body::Invalid, span)
                }
            }
        })
        .boxed();

    let hashes = just('#').repeated();
    let start = hashes.count().then_ignore(just('"'));
    let end = just('"')
        .then(hashes.configure(|cfg, ctx| cfg.exactly(*ctx)))
        .then(just(">"));
    let inner = any().and_is(end.not()).repeated().to_slice();
    let raw_string = just("<").ignore_then(
        just('r')
            .repeated()
            .at_most(1)
            .to_slice()
            .then(start.ignore_with_ctx(inner.then_ignore(end))),
    );
    let body_text = raw_string
        .validate(|(raw, body): (&str, &str), e, _emitter| {
            let span: SimpleSpan<usize> = e.span();

            let body = if raw.is_empty() {
                unescape_c_style(&body)
            } else {
                body.to_owned()
            };

            (Body::Text(body), span)
        })
        .boxed();

    let body_base64 = none_of(">")
        .repeated()
        .to_slice()
        .validate(|body: &str, e, emitter| {
            let span: SimpleSpan<usize> = e.span();

            match base64::prelude::BASE64_STANDARD.decode(body) {
                Ok(_) => (Body::Base64(body), span),
                Err(_) => {
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Invalid base64 body")
                        .with_label(
                            Label::new(span.into_range())
                                .with_message("Invalid base64 body")
                                .with_color(Color::Red),
                        )
                        .with_note("For raw string literals, wrap the string in double quotes")
                        .with_help(format!(
                            "Did you mean {}{}{}{}{}?",
                            "<".bold(),
                            '"'.bold().green(),
                            body.bold(),
                            '"'.bold().green(),
                            ">".bold()
                        ))
                        .finish();
                    emitter.emit(MyError::Report(report));
                    (Body::Invalid, span)
                }
            }
        })
        .delimited_by(just("<"), just(">"))
        .boxed();

    let request_body = choice((body_json.clone(), body_text.clone(), body_base64.clone())).boxed();

    let status_code = none_of("]").repeated().to_slice()
        .validate(|code: &str, e, emitter| {
            match validate_http_code(code) {
                Ok(code) => (Some(code), e.span()),
                Err(Some((suggested_code, suggested_name))) => {
                    let span: SimpleSpan<usize> = e.span();
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Invalid HTTP status code")
                        .with_label(
                            Label::new(span.into_range())
                                .with_message(format!("Invalid HTTP status code {}", code.bold()))
                                .with_color(Color::Red),
                        )
                        .with_help(format!(
                            "Did you mean {} ({})?",
                            suggested_name.bold(),
                            suggested_code.bold()
                        ))
                        .finish();
                    emitter.emit(MyError::Report(report));
                    (None, span)
                }
                Err(None) => {
                    let span: SimpleSpan<usize> = e.span();
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Invalid HTTP status code")
                        .with_label(
                            Label::new(span.into_range())
                                .with_message(format!("Invalid HTTP status code {}", code.bold()))
                                .with_color(Color::Red),
                        )
                        .with_note("See https://developer.mozilla.org/en-US/docs/Web/HTTP/Status for available status codes")
                        .finish();
                    emitter.emit(MyError::Report(report));
                    (None, span)
                }
            }
        })
        .delimited_by(just("["), just("]")).boxed();

    let hashes = just('#').repeated();
    let start = hashes.count().then_ignore(just('/'));
    let end = just('/')
        .then(hashes.configure(|cfg, ctx| cfg.exactly(*ctx)))
        .then(just(">"));
    let inner = any().and_is(end.not()).repeated().to_slice();
    let raw_regex = just("<").ignore_then(start.ignore_with_ctx(inner.then_ignore(end)));
    let body_regex = raw_regex
        .validate(|body: &str, e, emitter| {
            let span: SimpleSpan<usize> = e.span();

            match Regex::new(body) {
                Ok(re) => (Body::Regex(re), span),
                Err(err) => {
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Invalid regex response body")
                        .with_label(
                            Label::new(span.into_range())
                                .with_message(err.to_string())
                                .with_color(Color::Red),
                        )
                        .finish();
                    emitter.emit(MyError::Report(report));
                    (Body::Invalid, span)
                }
            }
        })
        .boxed();

    let hashes = just('#').repeated();
    let start = hashes.count().then_ignore(just('('));
    let end = just(')')
        .then(hashes.configure(|cfg, ctx| cfg.exactly(*ctx)))
        .then(just(">"));
    let inner = any().and_is(end.not()).repeated().to_slice();
    let raw_jq = just("<").ignore_then(start.ignore_with_ctx(inner.then_ignore(end)));
    let body_jq = raw_jq
        .validate(|body: &str, e, emitter| {
            let span: SimpleSpan<usize> = e.span();

            let mut defs = jaq_interpret::ParseCtx::new(vec![]);
            defs.insert_natives(jaq_core::core());
            defs.insert_defs(jaq_std::std());

            let (expr, errors) = jaq_parse::parse(body, jaq_parse::main());

            if !errors.is_empty() {
                let labels = errors
                    .iter()
                    .map(|e| {
                        let jq_span = e.span();
                        let jq_span =
                            SimpleSpan::new(span.start + jq_span.start, span.start + jq_span.end);

                        Label::new(jq_span.into_range())
                            .with_message(format!("{:#?}", e.reason()))
                            .with_color(Color::Yellow)
                    })
                    .collect::<Vec<_>>();
                let report = Report::build(ReportKind::Error, (), span.start)
                    .with_message("Invalid jq expression")
                    .with_label(
                        Label::new(span.into_range())
                            .with_message("Invalid jq expression")
                            .with_color(Color::Red),
                    )
                    .with_labels(labels)
                    .finish();
                emitter.emit(MyError::Report(report));
            }

            match expr {
                Some(expr) => (Body::Jq { body, expr }, span),
                None => (Body::Invalid, span),
            }
        })
        .boxed();

    let response_body = choice((
        body_json,
        body_text.clone(),
        body_regex.clone(),
        body_jq,
        body_base64.clone(),
    ))
    .boxed();

    let http = choice((
        header.clone().map(|h| HttpRequest::Header(h)),
        http_verb.map(|v| HttpRequest::Verb(v)),
        request_body.map(|b| HttpRequest::Body(b)),
    ))
    .repeated()
    .collect::<Vec<_>>()
    .then(url)
    .validate(|(request, url), e, emitter| {
        let verb = {
            let verbs = request
                .iter()
                .filter_map(|r| match r {
                    HttpRequest::Verb(v) => match v.0 {
                        HttpVerb::Invalid => None,
                        _ => Some(v),
                    },
                    _ => None,
                })
                .collect::<Vec<_>>();

            if verbs.len() > 1 {
                let span: SimpleSpan<usize> = e.span();
                let report = Report::build(ReportKind::Error, (), span.start)
                    .with_message("Multiple HTTP verbs")
                    .with_labels(
                        verbs
                            .iter()
                            .map(|verb| {
                                Label::new(verb.1.into_range())
                                    .with_message(format!(
                                        "Specified HTTP verb {} here",
                                        verb.0.bold()
                                    ))
                                    .with_color(Color::Red)
                            })
                            .collect::<Vec<_>>(),
                    )
                    .finish();
                emitter.emit(MyError::Report(report));
            }

            verbs.first().map(|v| v.0.clone())
        };

        let body = {
            let bodies = request
                .iter()
                .filter_map(|r| match r {
                    HttpRequest::Body(b) => match b.0 {
                        Body::Invalid => None,
                        _ => Some(b),
                    },
                    _ => None,
                })
                .collect::<Vec<_>>();

            if bodies.len() > 1 {
                let span: SimpleSpan<usize> = e.span();
                let report = Report::build(ReportKind::Error, (), span.start)
                    .with_message("Multiple request bodies")
                    .with_labels(
                        bodies
                            .iter()
                            .map(|body| {
                                let body_span = match body.0 {
                                    Body::Json(_) => "JSON",
                                    Body::Text(_) => "text",
                                    Body::Base64(_) => "base64",
                                    _ => "invalid",
                                };

                                Label::new(body.1.into_range())
                                    .with_message(format!(
                                        "Specified {} request body here",
                                        body_span
                                    ))
                                    .with_color(Color::Red)
                            })
                            .collect::<Vec<_>>(),
                    )
                    .finish();
                emitter.emit(MyError::Report(report));
            }

            bodies.first().map(|(b, _)| b.clone())
        };

        let headers = request
            .into_iter()
            .filter_map(|r| match r {
                HttpRequest::Header(h) => Some(h),
                _ => None,
            })
            .collect::<Vec<_>>();

        (headers, verb, body, url)
    })
    .then(
        choice((
            header.map(|h| HttpResponse::Header(h)),
            timeout.clone().map(|t| HttpResponse::Timeout(t)),
            status_code.map(|c| HttpResponse::StatusCode(c)),
            response_body.map(|b| HttpResponse::Body(b)),
        ))
        .repeated()
        .collect::<Vec<_>>()
        .validate(|request, e, emitter| {
            let timeout = {
                let timeouts = request
                    .iter()
                    .filter_map(|r| match r {
                        HttpResponse::Timeout(t) => match t.0 {
                            Some(d) => Some((d, t.1)),
                            None => None,
                        },
                        _ => None,
                    })
                    .collect::<Vec<_>>();

                if timeouts.len() > 1 {
                    let span: SimpleSpan<usize> = e.span();
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Multiple timeouts")
                        .with_labels(
                            timeouts
                                .iter()
                                .enumerate()
                                .map(|(i, timeout)| {
                                    Label::new(timeout.1.into_range())
                                        .with_message(format!(
                                            "Specified timeout {} here",
                                            (i + 1).italic()
                                        ))
                                        .with_color(Color::Red)
                                })
                                .collect::<Vec<_>>(),
                        )
                        .finish();
                    emitter.emit(MyError::Report(report));
                }

                timeouts.first().map(|t| t.0)
            };

            let status_code = {
                let status_codes = request
                    .iter()
                    .filter_map(|r| match r {
                        HttpResponse::StatusCode(c) => match c.0 {
                            Some(d) => Some((d, c.1)),
                            None => None,
                        },
                        _ => None,
                    })
                    .collect::<Vec<_>>();

                if status_codes.len() > 1 {
                    let span: SimpleSpan<usize> = e.span();
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Multiple status codes")
                        .with_labels(
                            status_codes
                                .iter()
                                .enumerate()
                                .map(|(i, status_code)| {
                                    Label::new(status_code.1.into_range())
                                        .with_message(format!(
                                            "Specified status code {} here",
                                            (i + 1).italic()
                                        ))
                                        .with_color(Color::Red)
                                })
                                .collect::<Vec<_>>(),
                        )
                        .finish();
                    emitter.emit(MyError::Report(report));
                }

                status_codes.first().map(|c| c.0)
            };

            let response_body = {
                let bodies = request
                    .iter()
                    .filter_map(|r| match r {
                        HttpResponse::Body(b) => match b.0 {
                            Body::Invalid => None,
                            _ => Some(b),
                        },
                        _ => None,
                    })
                    .collect::<Vec<_>>();

                if bodies.len() > 1 {
                    let span: SimpleSpan<usize> = e.span();
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Multiple response bodies")
                        .with_labels(
                            bodies
                                .iter()
                                .map(|body| {
                                    let body_span = match body.0 {
                                        Body::Json(_) => "JSON",
                                        Body::Text(_) => "text",
                                        Body::Base64(_) => "base64",
                                        Body::Regex(_) => "regex",
                                        Body::Jq { .. } => "jq",
                                        _ => "invalid",
                                    };

                                    Label::new(body.1.into_range())
                                        .with_message(format!(
                                            "Specified {} response body here",
                                            body_span
                                        ))
                                        .with_color(Color::Red)
                                })
                                .collect::<Vec<_>>(),
                        )
                        .finish();
                    emitter.emit(MyError::Report(report));
                }

                bodies.first().map(|(b, _)| b.clone())
            };

            let headers = request
                .into_iter()
                .filter_map(|r| match r {
                    HttpResponse::Header(h) => Some(h),
                    _ => None,
                })
                .collect::<Vec<_>>();

            (headers, timeout, status_code, response_body)
        }),
    )
    .map(
        |(
            (request_headers, verb, request_body, url),
            (response_headers, timeout, status_code, response_body),
        )| {
            Http {
                request_headers,
                verb,
                request_body,
                url,
                timeout,
                response_headers,
                status_code,
                response_body,
            }
        },
    )
    .boxed();

    let unwrapped_http = choice((just("http://"), just("https://")))
        .then(none_of(" ").repeated())
        .to_slice()
        .validate(|url: &str, e, emitter| {
            if reqwest::Url::parse(url).is_err() {
                emitter.emit(MyError::Rich(Rich::custom(e.span(), "Invalid URL")))
            }
            url
        })
        .map(|url| Http {
            request_headers: vec![],
            verb: None,
            request_body: None,
            url,
            timeout: None,
            response_headers: vec![],
            status_code: None,
            response_body: None,
        })
        .boxed();
    let http = http.or(unwrapped_http);

    let tcp_response_body = choice((body_text, body_regex, body_base64)).boxed();

    let tcp_url = just("tcp://")
        .ignore_then(none_of(")").repeated().to_slice())
        .delimited_by(just("("), just(")"))
        .boxed();

    let tcp = tcp_url
        .then(
            choice((
                timeout.clone().map(|t| TcpResponse::Timeout(t)),
                tcp_response_body.map(|b| TcpResponse::Body(b)),
            ))
            .repeated()
            .collect::<Vec<_>>(),
        )
        .validate(|(uri, responses), e, emitter| {
            let timeout = {
                let timeouts = responses
                    .iter()
                    .filter_map(|r| match r {
                        TcpResponse::Timeout(t) => match t.0 {
                            Some(d) => Some((d, t.1)),
                            None => None,
                        },
                        _ => None,
                    })
                    .collect::<Vec<_>>();

                if timeouts.len() > 1 {
                    let span: SimpleSpan<usize> = e.span();
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Multiple timeouts")
                        .with_labels(
                            timeouts
                                .iter()
                                .enumerate()
                                .map(|(i, timeout)| {
                                    Label::new(timeout.1.into_range())
                                        .with_message(format!(
                                            "Specified timeout {} here",
                                            (i + 1).italic()
                                        ))
                                        .with_color(Color::Red)
                                })
                                .collect::<Vec<_>>(),
                        )
                        .finish();
                    emitter.emit(MyError::Report(report));
                }

                timeouts.first().map(|t| t.0)
            };

            let response_body = {
                let bodies = responses
                    .iter()
                    .filter_map(|r| match r {
                        TcpResponse::Body(b) => match b.0 {
                            Body::Invalid => None,
                            _ => Some(b),
                        },
                        _ => None,
                    })
                    .collect::<Vec<_>>();

                if bodies.len() > 1 {
                    let span: SimpleSpan<usize> = e.span();
                    let report = Report::build(ReportKind::Error, (), span.start)
                        .with_message("Multiple response bodies")
                        .with_labels(
                            bodies
                                .iter()
                                .map(|body| {
                                    let body_span = match body.0 {
                                        Body::Text(_) => "text",
                                        Body::Base64(_) => "base64",
                                        Body::Regex(_) => "regex",
                                        _ => "invalid",
                                    };

                                    Label::new(body.1.into_range())
                                        .with_message(format!(
                                            "Specified {} response body here",
                                            body_span
                                        ))
                                        .with_color(Color::Red)
                                })
                                .collect::<Vec<_>>(),
                        )
                        .finish();
                    emitter.emit(MyError::Report(report));
                }

                bodies.first().map(|(b, _)| b.clone())
            };

            (uri, timeout, response_body)
        })
        .map(|(uri, timeout, response_body)| Tcp {
            uri,
            timeout,
            response_body,
        })
        .boxed();

    let unwrapped_tcp = just("tcp://")
        .ignore_then(none_of(" ").repeated().to_slice())
        .map(|uri| Tcp {
            uri,
            timeout: None,
            response_body: None,
        })
        .boxed();
    let tcp = tcp.or(unwrapped_tcp);

    let ping_url = just("ping://")
        .ignore_then(none_of(")").repeated().to_slice())
        .delimited_by(just("("), just(")"))
        .boxed();

    let ping = ping_url
        .then(
            timeout
                .clone()
                .map(|t| t.0)
                .repeated()
                .at_most(1)
                .collect::<Vec<_>>(),
        )
        .map(|(uri, timeout)| Ping {
            uri,
            timeout: timeout.first().map(|t| *t).flatten(),
        })
        .boxed();

    let unwrapped_ping = just("ping://")
        .ignore_then(none_of(" ").repeated().to_slice())
        .map(|uri| Ping { uri, timeout: None })
        .boxed();

    let ping = ping.or(unwrapped_ping);

    let dns_url = just("dns://")
        .ignore_then(none_of("/)").repeated().at_least(1).to_slice())
        .then(
            just("/")
                .ignore_then(none_of(")").repeated().at_least(1).to_slice())
                .repeated()
                .at_most(1)
                .collect::<Vec<&str>>(),
        )
        .delimited_by(just("("), just(")"))
        .boxed();

    let dns = dns_url
        .then(
            timeout
                .map(|t| t.0)
                .repeated()
                .at_most(1)
                .collect::<Vec<_>>(),
        )
        .map(|((uri, server), timeout)| Dns {
            uri,
            server: server.first().copied(),
            timeout: timeout.first().map(|t| *t).flatten(),
        })
        .boxed();

    let unwrapped_dns = just("dns://")
        .ignore_then(none_of("/ ").repeated().at_least(1).to_slice())
        .then(
            just("/")
                .ignore_then(none_of(" ").repeated().at_least(1).to_slice())
                .repeated()
                .at_most(1)
                .collect::<Vec<&str>>(),
        )
        .map(|(uri, server)| Dns {
            uri,
            server: server.first().copied(),
            timeout: None,
        })
        .boxed();

    let dns = dns.or(unwrapped_dns);

    let single_expression = choice((
        dns.map(|d| Expr::Dns(d)),
        ping.map(|p| Expr::Ping(p)),
        tcp.map(|t| Expr::Tcp(t)),
        http.map(|h| Expr::Http(h)),
    ))
    .boxed();

    recursive(|expr| {
        choice((
            single_expression
                .clone()
                .then_ignore(just(" and "))
                .then(expr.clone())
                .map(|(a, b)| Expr::And(Box::new(a), Box::new(b))),
            single_expression,
        ))
    })
    .boxed()
}

pub fn parse(input: &str) -> (Option<Expr>, Vec<String>) {
    let (ast, errors) = parser().parse(input).into_output_errors();

    let mut errs = Vec::new();
    errors.into_iter().for_each(|e| match e {
        MyError::Rich(e) => {
            let span: SimpleSpan<usize> = *e.span();
            let e = Report::build(ReportKind::Error, (), span.start)
                .with_message(e.reason())
                .with_label(
                    Label::new(span.into_range())
                        .with_message(e.reason())
                        .with_color(Color::Red),
                )
                .finish();
            let mut report = Vec::<u8>::new();
            e.write_for_stdout(Source::from(input), &mut report)
                .unwrap();
            let report = String::from_utf8_lossy(&report).into_owned();
            errs.push(report);
        }
        MyError::Report(e) => {
            let mut report = Vec::<u8>::new();
            e.write_for_stdout(Source::from(input), &mut report)
                .unwrap();
            let report = String::from_utf8_lossy(&report).into_owned();
            errs.push(report);
        }
    });

    (ast, errs)
}
