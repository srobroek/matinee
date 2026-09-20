mod dispatch;
mod doctor;

use std::{env, io, path::PathBuf, process::ExitCode, sync::Arc};

use matinee_daemon::failure::FailureCode;
use matinee_daemon::lifecycle::Daemon;
use uuid::Uuid;

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
        dispatch::Dispatch::Setup => setup(),
        dispatch::Dispatch::Status => status(),
        dispatch::Dispatch::Stop => stop(),
        dispatch::Dispatch::Mcp => mcp(),
        dispatch::Dispatch::Fixture { port } => fixture(port),
        dispatch::Dispatch::Invalid(argument) => {
            eprintln!(
                "error: unrecognized argument '{}'\n\nUsage: matinee <COMMAND>",
                argument.to_string_lossy()
            );
            ExitCode::from(2)
        }
    }
}

fn state_dir() -> PathBuf {
    env::var_os("MATINEE_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("matinee"))
}

fn setup() -> ExitCode {
    match Daemon::start(state_dir()) {
        Ok(daemon) => {
            println!("daemon\tready\t{}", daemon.instance_id());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}: {}", error.code(), error.detail());
            ExitCode::FAILURE
        }
    }
}

fn status() -> ExitCode {
    match Daemon::start(state_dir()) {
        Ok(daemon) => {
            drop(daemon);
            println!("daemon\tstopped");
            ExitCode::SUCCESS
        }
        Err(error) if error.code() == FailureCode::DaemonStartConflict => {
            println!("daemon\trunning");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}: {}", error.code(), error.detail());
            ExitCode::FAILURE
        }
    }
}

fn stop() -> ExitCode {
    // The public CLI has no daemon-start command and cannot address a daemon
    // that belongs to another process without the authenticated control
    // channel. The command remains an idempotent status operation until that
    // channel is available.
    match Daemon::start(state_dir()) {
        Ok(daemon) => {
            drop(daemon);
            println!("daemon\tstopped");
            ExitCode::SUCCESS
        }
        Err(error) if error.code() == FailureCode::DaemonStartConflict => {
            println!("daemon\trunning");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}: {}", error.code(), error.detail());
            ExitCode::FAILURE
        }
    }
}

fn mcp() -> ExitCode {
    let daemon = match Daemon::start(state_dir()) {
        Ok(daemon) => Arc::new(daemon),
        Err(error) => {
            eprintln!("{}: {}", error.code(), error.detail());
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start MCP runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "matinee MCP adapter ready on stdio (daemon instance {})",
        daemon.instance_id()
    );
    match runtime.block_on(matinee_mcp::run_stdio(daemon, Uuid::now_v7())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("MCP stdio failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn fixture(port: u16) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start fixture runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run_fixture(port)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fixture failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run_fixture(port: u16) -> io::Result<()> {
    let (address, server) = matinee_fixture::bind_and_serve(port)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    println!("fixture listening on http://{address}/alpha");

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    tokio::select! {
        result = server => {
            result
                .map_err(|error| io::Error::other(error.to_string()))?
                .map_err(|error| io::Error::other(error.to_string()))
        }
        result = tokio::io::AsyncBufReadExt::read_line(&mut stdin, &mut line) => {
            result.map(|_| ())
        }
    }
}
