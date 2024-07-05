use clap::Parser;
use yansi::Paint;

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

    for error in errors {
        eprintln!("{}", error);
    }

    if let Some(ast) = ast {
        let result = ast.execute().await;
        println!(
            "{}{}",
            "Service is ".bold(),
            if result.0 {
                "healthy".bold().bright_green()
            } else {
                "unhealthy".bold().red()
            }
        );
        println!();

        for (i, errors) in result.1.iter().enumerate() {
            print!("{}", format!("Check #{}: ", i + 1).bold());
            if errors.is_empty() {
                println!("{}", "success".bold().bright_green())
            }
            for error in errors {
                println!("{}", error.to_string().bold().red());
            }
        }
    }
}
