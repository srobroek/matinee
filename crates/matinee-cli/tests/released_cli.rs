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
