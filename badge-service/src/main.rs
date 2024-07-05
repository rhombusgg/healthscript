use axum::{extract::Path, http::Response, response::IntoResponse, routing::get, Router};
use badge_maker::BadgeBuilder;
use tracing_subscriber;

fn render_shield(uri: &str, healthy: bool) -> String {
    BadgeBuilder::new()
        .label(uri)
        .message(if healthy { "healthy" } else { "unhealthy" })
        .color_parse(if healthy { "#4c1" } else { "#e05d44" })
        .build()
        .unwrap()
        .svg()
}

async fn route_shield(Path(script): Path<String>) -> impl IntoResponse {
    let (expr, _) = healthscript::parse(&script);
    let (uri, healthy) = if let Some(expr) = &expr {
        let (healthy, _) = expr.execute().await;
        (expr.representative_uri(), healthy)
    } else {
        ("invalid expression".to_owned(), false)
    };

    tracing::info!(script, healthy, "executed health check");

    Response::builder()
        .header("content-type", "image/svg+xml")
        .body(render_shield(&uri, healthy))
        .unwrap()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    tracing::info!("Started shield service");

    let router = Router::new().route("/*script", get(route_shield));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
