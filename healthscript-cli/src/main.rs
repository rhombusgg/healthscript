use clap::Parser;

/// Run healthscript healthchecks
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Healthscript to execute
    #[arg()]
    script: String,
}

fn main() {
    let args = Args::parse();

    let (_ast, errors) = healthscript::parse(&args.script);

    if errors.is_empty() {
        println!("Parsed successfully");
    } else {
        for error in errors {
            eprintln!("{}", error);
        }
    }
}
