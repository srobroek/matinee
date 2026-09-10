use std::{
    env,
    path::{Path, PathBuf},
    process::ExitCode,
};

const USAGE: &str = "Matinee checks headed-browser environments for coding agents.\n\nUsage: matinee <COMMAND>\n\nCommands:\n  doctor   Check for supported browser executables\n  help     Print help\n\nOptions:\n  -h, --help     Print help\n  -V, --version  Print version";

struct Browser {
    name: &'static str,
    executable_names: &'static [&'static str],
    fixed_paths: fn() -> Vec<PathBuf>,
}

const BROWSERS: [Browser; 2] = [
    Browser {
        name: "Firefox",
        executable_names: &["firefox", "firefox.exe"],
        fixed_paths: firefox_paths,
    },
    Browser {
        name: "Google Chrome",
        executable_names: &["google-chrome", "google-chrome-stable", "chrome.exe"],
        fixed_paths: chrome_paths,
    },
];

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);

    match (arguments.next(), arguments.next()) {
        (None, None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        (Some(argument), None)
            if argument == "-h" || argument == "--help" || argument == "help" =>
        {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        (Some(argument), None) if argument == "-V" || argument == "--version" => {
            println!("matinee {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        (Some(argument), None) if argument == "doctor" => doctor(),
        (Some(argument), _) => {
            eprintln!(
                "error: unrecognized argument '{}'\n\nUsage: matinee <COMMAND>",
                argument.to_string_lossy()
            );
            ExitCode::from(2)
        }
        (None, Some(_)) => unreachable!(),
    }
}

fn doctor() -> ExitCode {
    let mut found = 0;

    for browser in &BROWSERS {
        match find_browser(browser) {
            Some(path) => {
                println!("{}\t{}", browser.name, path.display());
                found += 1;
            }
            None => println!("{}\tnot found", browser.name),
        }
    }

    if found == 0 {
        eprintln!("no supported browser found; install Firefox or Google Chrome");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn find_browser(browser: &Browser) -> Option<PathBuf> {
    if let Some(path) = (browser.fixed_paths)()
        .into_iter()
        .find(|path| is_executable(path))
    {
        return Some(path);
    }

    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        for name in browser.executable_names {
            let candidate = directory.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };

    if !metadata.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn firefox_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from(
            "/Applications/Firefox.app/Contents/MacOS/firefox",
        )]
    }

    #[cfg(target_os = "windows")]
    {
        windows_program_paths("Mozilla Firefox", "firefox.exe")
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

fn chrome_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        )]
    }

    #[cfg(target_os = "windows")]
    {
        windows_program_paths("Google/Chrome/Application", "chrome.exe")
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "windows")]
fn windows_program_paths(directory: &str, executable: &str) -> Vec<PathBuf> {
    ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"]
        .into_iter()
        .filter_map(env::var_os)
        .map(PathBuf::from)
        .map(|root| root.join(directory).join(executable))
        .collect()
}
