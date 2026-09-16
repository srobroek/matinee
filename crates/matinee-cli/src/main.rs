mod dispatch;
mod doctor;

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    match dispatch::dispatch(env::args_os().skip(1)) {
        dispatch::Dispatch::Help => {
            println!("{}", dispatch::USAGE);
            ExitCode::SUCCESS
        }
        dispatch::Dispatch::Version => {
            println!("matinee {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        dispatch::Dispatch::Doctor => doctor::doctor(),
        dispatch::Dispatch::Invalid(argument) => {
            eprintln!(
                "error: unrecognized argument '{}'\n\nUsage: matinee <COMMAND>",
                argument.to_string_lossy()
            );
            ExitCode::from(2)
        }
    }
}
