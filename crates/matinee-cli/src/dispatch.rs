use std::ffi::OsString;

/// The unchanged help text for the released command surface.
pub(crate) const USAGE: &str = "Matinee checks headed-browser environments for coding agents.\n\nUsage: matinee <COMMAND>\n\nCommands:\n  doctor   Check for supported browser executables\n  help     Print help\n\nOptions:\n  -h, --help     Print help\n  -V, --version  Print version";

/// A command accepted by the released CLI, or the first argument of an invalid
/// invocation for the caller to render with the released diagnostic format.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Dispatch {
    Help,
    Version,
    Doctor,
    Invalid(OsString),
}

/// Parse process arguments and select the released command surface.
pub(crate) fn dispatch<I>(arguments: I) -> Dispatch
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();

    match (arguments.next(), arguments.next()) {
        (None, None) => Dispatch::Help,
        (Some(argument), None)
            if argument == "-h" || argument == "--help" || argument == "help" =>
        {
            Dispatch::Help
        }
        (Some(argument), None) if argument == "-V" || argument == "--version" => Dispatch::Version,
        (Some(argument), None) if argument == "doctor" => Dispatch::Doctor,
        (Some(argument), _) => Dispatch::Invalid(argument),
        (None, Some(argument)) => Dispatch::Invalid(argument),
    }
}
