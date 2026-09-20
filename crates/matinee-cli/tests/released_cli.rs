use std::process::Command;

#[test]
fn help_is_successful_and_writes_no_diagnostics() {
    let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("--help")
        .output()
        .expect("run matinee --help");

    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty());
    assert_eq!(output.stderr, b"");
}

#[test]
fn version_matches_released_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("--version")
        .output()
        .expect("run matinee --version");

    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"matinee 0.0.2\n");
    assert_eq!(output.stderr, b"");
}

#[test]
fn invalid_argument_matches_released_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("wat")
        .output()
        .expect("run matinee with an invalid argument");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    assert_eq!(
        output.stderr,
        b"error: unrecognized argument 'wat'\n\nUsage: matinee <COMMAND>\n"
    );
}

#[test]
fn doctor_lists_firefox_then_chrome_rows() {
    let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("doctor")
        .output()
        .expect("run matinee doctor");

    let stdout = String::from_utf8(output.stdout).expect("doctor output is UTF-8");
    let rows: Vec<_> = stdout.lines().collect();
    assert_eq!(rows.len(), 2);

    for (row, expected_name) in rows.iter().zip(["Firefox", "Google Chrome"]) {
        let (name, value) = row.split_once('\t').expect("doctor row has a tab");
        assert_eq!(name, expected_name);
        assert!(value == "not found" || !value.is_empty());
    }
}

#[test]
fn help_advertises_supported_commands_and_options() {
    let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("--help")
        .output()
        .expect("run matinee --help");

    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("help output is UTF-8");
    let commands: Vec<_> = advertised_entries(&help, "Commands:")
        .into_iter()
        .map(|(command, _)| command)
        .collect();
    for command in [
        "doctor", "setup", "status", "stop", "mcp", "fixture", "help",
    ] {
        assert!(
            commands.iter().any(|entry| entry == command),
            "missing command {command}"
        );
    }

    let options: Vec<_> = advertised_entries(&help, "Options:")
        .into_iter()
        .map(|(option, _)| option)
        .collect();
    assert!(options.iter().any(|option| option == "-h, --help"));
    assert!(options.iter().any(|option| option == "-V, --version"));
}

#[test]
fn every_advertised_command_is_recognized_when_run() {
    let help = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("--help")
        .output()
        .expect("run matinee --help");
    let help_text = String::from_utf8(help.stdout).expect("help output is UTF-8");

    for (command, _) in advertised_entries(&help_text, "Commands:") {
        let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
            .arg(&command)
            .output()
            .expect("run advertised matinee command");
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.code().is_some(),
            "advertised command {command:?} was terminated by a signal"
        );
        assert_ne!(
            output.status.code(),
            Some(2),
            "advertised command {command:?} was rejected"
        );
        assert!(
            !stderr.contains("unrecognized argument"),
            "advertised command {command:?} was reported as unrecognized: {stderr}"
        );
    }
}

#[test]
fn help_does_not_advertise_a_public_daemon_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("--help")
        .output()
        .expect("run matinee --help");
    let help = String::from_utf8(output.stdout).expect("help output is UTF-8");
    let commands: Vec<_> = advertised_entries(&help, "Commands:")
        .into_iter()
        .map(|(command, _)| command)
        .collect();
    assert!(!commands.iter().any(|command| command == "daemon"));
}

fn advertised_entries(help: &str, heading: &str) -> Vec<(String, String)> {
    let mut lines = help.lines();
    assert!(
        lines.by_ref().any(|line| line == heading),
        "help is missing {heading:?} section"
    );

    lines
        .take_while(|line| !line.is_empty())
        .map(|line| {
            let line = line.trim_start();
            let (label, description) = line
                .split_once("  ")
                .expect("help entry has label and description");
            (label.trim().to_owned(), description.trim().to_owned())
        })
        .collect()
}
