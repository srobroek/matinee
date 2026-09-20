mod dispatch;
mod doctor;

use std::{
    env, fs, io,
    path::PathBuf,
    process::{Command, ExitCode, Stdio},
};

use matinee_daemon::server::{ControlClient, Endpoint};
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
        dispatch::Dispatch::SetupPairExtension => pair_extension(),
        dispatch::Dispatch::Status => status(),
        dispatch::Dispatch::Stop => stop(),
        dispatch::Dispatch::Report { output } => report(output),
        dispatch::Dispatch::Mcp => mcp(),
        dispatch::Dispatch::Fixture { port } => fixture(port),
        dispatch::Dispatch::DaemonChild => daemon_child(),
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
    let runtime = runtime();
    match runtime.block_on(ensure_daemon(state_dir())) {
        Ok(endpoint) => {
            println!(
                "daemon\tready\t{}\tcontrol={}\textension={}",
                endpoint.instance_id, endpoint.control_addr, endpoint.extension_addr
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn pair_extension() -> ExitCode {
    let runtime = runtime();
    match runtime.block_on(async {
        let endpoint = ensure_daemon(state_dir()).await?;
        let response = ControlClient::new(endpoint)
            .request(serde_json::json!({"command":"pair_extension"}))
            .await?;
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            let code = response
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("authorization.denied");
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, code));
        }
        let key = response
            .get("one_time_key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "pairing key missing"))?;
        let extension_addr = response
            .get("extension_addr")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "extension endpoint missing")
            })?;
        let origin = response
            .get("origin")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "extension origin missing")
            })?;
        println!("extension pairing key: {key}");
        println!("extension WebSocket: {extension_addr}");
        println!("extension origin: {origin}");
        Ok::<_, io::Error>(())
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn status() -> ExitCode {
    let state = state_dir();
    let runtime = runtime();
    match runtime.block_on(read_ready(&state)) {
        Ok(Some(endpoint)) => {
            println!(
                "daemon\tready\t{}\tcontrol={}\textension={}",
                endpoint.instance_id, endpoint.control_addr, endpoint.extension_addr
            );
            ExitCode::SUCCESS
        }
        Ok(None) => {
            println!("daemon\tstopped");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn stop() -> ExitCode {
    let state = state_dir();
    let runtime = runtime();
    match runtime.block_on(async {
        let Some(endpoint) = Endpoint::read(&state)? else {
            return Ok::<_, io::Error>(false);
        };
        let response = ControlClient::new(endpoint)
            .request(serde_json::json!({"command":"stop"}))
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(response
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false))
    }) {
        Ok(true) => {
            println!("daemon\tstopped");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("daemon\tstopped");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn report(output: PathBuf) -> ExitCode {
    let state = state_dir();
    let runtime = runtime();
    match runtime.block_on(async {
        let endpoint = Endpoint::read(&state)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "daemon is not running"))?;
        let response = ControlClient::new(endpoint)
            .request(serde_json::json!({"command":"evidence"}))
            .await?;
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            let code = response
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("authorization.denied");
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, code));
        }
        let report = response
            .get("report")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "evidence report missing"))?;
        let mut encoded = serde_json::to_vec_pretty(report)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        encoded.push(b'\n');
        fs::write(&output, encoded)?;
        let count = |name: &str| {
            report
                .get(name)
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len)
        };
        let lost_boundary_count = report
            .get("lost_boundary")
            .and_then(|value| value.get("operations"))
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        Ok::<_, io::Error>((
            count("sessions"),
            count("requests"),
            count("operations"),
            count("artifacts"),
            count("resource_reads"),
            lost_boundary_count,
        ))
    }) {
        Ok((sessions, requests, operations, artifacts, resource_reads, lost_boundaries)) => {
            println!(
                "report\t{}\tsessions={}\trequests={}\toperations={}\tartifacts={}\tresource_reads={}\tlost_boundary_operations={}",
                output.display(),
                sessions,
                requests,
                operations,
                artifacts,
                resource_reads,
                lost_boundaries,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn mcp() -> ExitCode {
    let runtime = runtime();
    match runtime.block_on(ensure_daemon(state_dir())) {
        Ok(endpoint) => {
            match runtime.block_on(matinee_mcp::run_stdio_client(endpoint, Uuid::now_v7())) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("MCP stdio failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn daemon_child() -> ExitCode {
    let runtime = runtime();
    match runtime.block_on(matinee_daemon::server::run(state_dir())) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}: {}", error.code(), error.detail());
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

async fn read_ready(state: &PathBuf) -> io::Result<Option<Endpoint>> {
    let Some(endpoint) = Endpoint::read(state)? else {
        return Ok(None);
    };
    match ControlClient::new(endpoint.clone())
        .request(serde_json::json!({"command":"status"}))
        .await
    {
        Ok(_) => Ok(Some(endpoint)),
        Err(_) => Ok(None),
    }
}

async fn ensure_daemon(state: PathBuf) -> io::Result<Endpoint> {
    if let Some(endpoint) = read_ready(&state).await? {
        return Ok(endpoint);
    }
    let executable = env::current_exe()?;
    Command::new(executable)
        .arg("--__daemon-child")
        .env("MATINEE_STATE_DIR", &state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let start = std::time::Instant::now();
    loop {
        if let Some(endpoint) = read_ready(&state).await? {
            return Ok(endpoint);
        }
        if start.elapsed() > std::time::Duration::from_secs(5) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "daemon did not become ready",
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
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
