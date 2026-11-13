use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser, Debug)]
#[command(name = "hyntel", version, about = "Cross-platform security audit tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run audit with CLI arguments
    Run(hyntel_cli::Args),
    /// Launch terminal UI
    Tui,
    /// Launch graphical UI
    Gui,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => {
            // Use the CLI crate's main logic
            hyntel_cli::run_with_args(args)
        }
        Commands::Tui => {
            hyntel_tui::run_tui()
        }
        Commands::Gui => {
            hyntel_gui::main()
        }
    }
}