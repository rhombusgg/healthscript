use clap::Parser;

/// Run healthscript healthchecks
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Healthscript to execute
    #[arg()]
    script: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let (ast, errors) = healthscript::parse(&args.script);

    if errors.is_empty() {
        println!("Parsed successfully");
    } else {
        for error in errors {
            eprintln!("{}", error);
        }
    }

    println!("{:#?}", ast);
    if let Some(ast) = ast {
        println!("{}", ast);
        let result = ast.execute().await;
        println!("{:#?}", result);
    }
}
