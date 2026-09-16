use std::process::Command;

#[test]
fn help_matches_released_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("--help")
        .output()
        .expect("run matinee --help");

    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"Matinee checks headed-browser environments for coding agents.\n\nUsage: matinee <COMMAND>\n\nCommands:\n  doctor   Check for supported browser executables\n  help     Print help\n\nOptions:\n  -h, --help     Print help\n  -V, --version  Print version\n"
    );
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
fn help_advertises_exact_released_commands_and_options() {
    let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("--help")
        .output()
        .expect("run matinee --help");

    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("help output is UTF-8");

    assert_eq!(
        advertised_entries(&help, "Commands:"),
        vec![
            (
                "doctor".to_owned(),
                "Check for supported browser executables".to_owned()
            ),
            ("help".to_owned(), "Print help".to_owned()),
        ]
    );
    assert_eq!(
        advertised_entries(&help, "Options:"),
        vec![
            ("-h, --help".to_owned(), "Print help".to_owned()),
            ("-V, --version".to_owned(), "Print version".to_owned()),
        ]
    );
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
fn help_omits_later_spec_surface_vocabulary() {
    let output = Command::new(env!("CARGO_BIN_EXE_matinee"))
        .arg("--help")
        .output()
        .expect("run matinee --help");
    let help = String::from_utf8(output.stdout)
        .expect("help output is UTF-8")
        .to_ascii_lowercase();

    for term in [
        "setup",
        "status",
        "stop",
        "mcp",
        "diagnostics",
        "uninstall",
        "daemon",
        "extension",
        "endpoint",
        "tool",
        "automation",
        "workflow",
    ] {
        assert!(
            !help.contains(term),
            "help unexpectedly advertises later-spec surface term {term:?}"
        );
    }
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
