use std::ops::Range;

use ariadne::{Color, Label, Report, ReportKind, Source};
use base64::Engine;
use chumsky::{prelude::*, text::whitespace, util::MaybeRef};

use serde_json::Value;
use strsim::normalized_levenshtein;
use yansi::Paint;

// pub type Span = SimpleSpan<usize>;
// pub type Spanned<T> = (T, Span);

#[derive(Debug, PartialEq, Eq)]
pub enum Expr<'a> {
    Http(Http<'a>),
    Tcp(Tcp<'a>),
    Ping(Ping<'a>),
    Dns(Dns<'a>),
    Invalid,
}

#[derive(Debug, PartialEq, Eq)]
struct Http<'a> {
    RequestHeader: Vec<(&'a str, &'a str)>,
    Verb: Option<HttpVerb>,
    RequestBody: Option<HttpBody<'a>>,
    Url: &'a str,
    StatusCode: Option<u16>,
    // ReponseBody: Option<&'a str>,
    // ResponseHeader: Vec<(&'a str, &'a str)>,
    // Jq: Option<&'a str>,
    // Regex: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HttpBody<'a> {
    Json(Value),
    Text(&'a str),
    Base64(&'a str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HttpVerb {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
}

#[derive(Debug, PartialEq, Eq)]
struct Tcp<'a> {
    Uri: &'a str,
    Timeout: Option<u16>,
    Regex: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq)]
struct Ping<'a> {
    Uri: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
struct Dns<'a> {
    Uri: &'a str,
    Server: &'a str,
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
            closest = c.clone();
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

fn parser<'a>() -> impl Parser<'a, &'a str, Expr<'a>, extra::Err<MyError<'a>>> {
    let headers = just("[")
        .ignore_then(text::ident())
        .then_ignore(just(":").then(whitespace()))
        .then(text::ident())
        .then_ignore(just("]").recover_with(skip_then_retry_until(any().ignored(), end())))
        .repeated()
        .collect::<Vec<_>>();

    let http_verb = text::ident()
        .validate(|verb_str: &str, e, emitter| match closest_verb(verb_str) {
            Ok(verb) => Some(verb),
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
                    None
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
                    None
                }
            },
        })
        .delimited_by(just("["), just("]"));

    let url = none_of(")")
        .repeated()
        .to_slice()
        .validate(|url: &str, e, emitter| {
            if reqwest::Url::parse(url).is_err() {
                emitter.emit(MyError::Rich(Rich::custom(e.span(), "Invalid URL")))
            }
            url
        })
        .delimited_by(just("("), just(")"));

    let body = any()
        .and_is(just(">").then(url).not())
        .repeated()
        .to_slice()
        .validate(|body: &str, e, emitter| {
            let span: SimpleSpan<usize> = e.span();

            if body.starts_with('{') && body.ends_with('}') {
                match serde_json::from_str(body) {
                    Ok(value) => return Some(HttpBody::Json(value)),
                    Err(err) => {
                        let column = err.column();
                        let json_span =
                            SimpleSpan::new(span.start + column - 1, span.start + column - 1);

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

                        return None;
                    }
                }
            }

            if body.starts_with('"') && body.ends_with('"') {
                return Some(HttpBody::Text(&body[1..body.len() - 1]));
            }

            match base64::prelude::BASE64_STANDARD.decode(body) {
                Ok(_) => return Some(HttpBody::Base64(body)),
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
                    return None;
                }
            }
        })
        .delimited_by(just("<"), just(">"));

    let status_code = none_of("]").repeated().to_slice()
        .validate(|code: &str, e, emitter| {
            match validate_http_code(code) {
                Ok(code) => Some(code),
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
                    None
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
                    None
                }
            }
        })
        .delimited_by(just("["), just("]"));

    // let jq = just(".").then(text::ident());

    // let regex = text::ident().delimited_by(just('/'), just('/'));

    let http = headers
        .then(http_verb.repeated().at_most(1).collect::<Vec<_>>())
        .then(body.repeated().at_most(1).collect::<Vec<_>>())
        .then(url)
        .then(status_code.repeated().at_most(1).collect::<Vec<_>>())
        .map(|((((request_headers, verb), body), url), status_code)| {
            Expr::Http(Http {
                RequestHeader: request_headers,
                Verb: verb.get(0).cloned().flatten(),
                RequestBody: body.get(0).cloned().flatten(),
                Url: url,
                StatusCode: status_code.get(0).cloned().flatten(),
            })
        });
    http

    // uri.map(|x| Expr::Http(x))
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
