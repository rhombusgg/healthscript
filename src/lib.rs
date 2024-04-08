use chumsky::prelude::*;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[derive(Clone, Debug)]
enum Expr<'a> {
    Verb(HttpVerb),
    Url(&'a str),
}

#[derive(Clone, Debug)]
enum HttpVerb {
    GET,
    POST,
}

fn parser<'a>() -> impl Parser<char, Expr<'a>, Error = Simple<char>> {
    choice((
        just("GET").to(Expr::Verb(HttpVerb::GET)),
        just("POST").to(Expr::Verb(HttpVerb::POST)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use expect_test::expect;

    #[test]
    fn http_verb_get() {
        let verb = "GET";
        let acutal = parser().parse(verb).unwrap();
        let expected = expect![[r#"
            Verb(
                GET,
            )
        "#]];
        expected.assert_debug_eq(&acutal);
    }
}
