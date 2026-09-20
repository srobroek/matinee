use std::ffi::OsString;

/// Help text for the supported Matinee command surface.
pub(crate) const USAGE: &str = "Matinee checks headed-browser environments for coding agents.\n\nUsage: matinee <COMMAND>\n\nCommands:\n  doctor   Check for supported browser executables\n  setup    Start the local daemon setup path\n  status   Report local daemon status\n  stop     Stop the local daemon\n  mcp      Run the newline-delimited MCP adapter\n  fixture  Serve the deterministic local fixture\n  help     Print help\n\nOptions:\n  -h, --help     Print help\n  -V, --version  Print version";

/// A command accepted by the released CLI, or the first argument of an invalid
/// invocation for the caller to render with the released diagnostic format.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Dispatch {
    Help,
    Version,
    Doctor,
    Setup,
    Status,
    Stop,
    Mcp,
    Fixture { port: u16 },
    Invalid(OsString),
}

/// Parse process arguments and select the released command surface.
pub(crate) fn dispatch<I>(arguments: I) -> Dispatch
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let Some(command) = arguments.next() else {
        return Dispatch::Help;
    };

    if command == "-h" || command == "--help" || command == "help" {
        return if arguments.next().is_none() {
            Dispatch::Help
        } else {
            Dispatch::Invalid(command)
        };
    }
    if command == "-V" || command == "--version" {
        return if arguments.next().is_none() {
            Dispatch::Version
        } else {
            Dispatch::Invalid(command)
        };
    }

    match command.to_string_lossy().as_ref() {
        "doctor" if arguments.next().is_none() => Dispatch::Doctor,
        "setup" if arguments.next().is_none() => Dispatch::Setup,
        "status" if arguments.next().is_none() => Dispatch::Status,
        "stop" if arguments.next().is_none() => Dispatch::Stop,
        "mcp" if arguments.next().is_none() => Dispatch::Mcp,
        "fixture" => parse_fixture(arguments),
        _ => Dispatch::Invalid(command),
    }
}

fn parse_fixture<I>(mut arguments: I) -> Dispatch
where
    I: Iterator<Item = OsString>,
{
    let Some(flag) = arguments.next() else {
        return Dispatch::Fixture { port: 8787 };
    };
    if flag != "--port" && flag != "-p" {
        return Dispatch::Invalid(flag);
    }
    let Some(port) = arguments.next() else {
        return Dispatch::Invalid(flag);
    };
    if arguments.next().is_some() {
        return Dispatch::Invalid(port);
    }
    match port.to_string_lossy().parse::<u16>() {
        Ok(port) => Dispatch::Fixture { port },
        _ => Dispatch::Invalid(port),
    }
}
