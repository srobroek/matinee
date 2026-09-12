use std::{
    env,
    ffi::OsString,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

struct Browser {
    name: &'static str,
    executable_names: &'static [&'static str],
    fixed_paths: fn() -> Vec<PathBuf>,
}

struct DiscoveryEnvironment {
    fixed_paths: Vec<PathBuf>,
    path: Option<OsString>,
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

const NO_BROWSER_DIAGNOSTIC: &str = "no supported browser found; install Firefox or Google Chrome";

struct DoctorResult {
    rows: Vec<String>,
    diagnostic: Option<&'static str>,
    outcome: ExitCode,
}

fn emit_doctor_output<W: Write, E: Write>(
    result: &DoctorResult,
    stdout: &mut W,
    stderr: &mut E,
) -> ExitCode {
    for row in &result.rows {
        stdout
            .write_all(row.as_bytes())
            .expect("write doctor stdout");
        stdout
            .write_all(b"\n")
            .expect("write doctor stdout");
    }

    if let Some(diagnostic) = result.diagnostic {
        stderr
            .write_all(diagnostic.as_bytes())
            .expect("write doctor stderr");
        stderr
            .write_all(b"\n")
            .expect("write doctor stderr");
    }

    result.outcome
}

pub(crate) fn doctor() -> ExitCode {
    let discoveries = BROWSERS.map(|browser| DiscoveryEnvironment {
        fixed_paths: (browser.fixed_paths)(),
        path: env::var_os("PATH"),
    });
    let result = doctor_with_discovery(discoveries);

    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    emit_doctor_output(&result, &mut stdout, &mut stderr)
}

fn doctor_with_discovery(discoveries: [DiscoveryEnvironment; 2]) -> DoctorResult {
    let mut rows = Vec::with_capacity(BROWSERS.len());
    let mut found = false;

    for (browser, discovery) in BROWSERS.iter().zip(discoveries) {
        match find_browser(browser, discovery) {
            Some(path) => {
                rows.push(format!("{}\t{}", browser.name, path.display()));
                found = true;
            }
            None => rows.push(format!("{}\tnot found", browser.name)),
        }
    }

    DoctorResult {
        rows,
        diagnostic: if found {
            None
        } else {
            Some(NO_BROWSER_DIAGNOSTIC)
        },
        outcome: if found {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        },
    }
}

fn find_browser(browser: &Browser, discovery: DiscoveryEnvironment) -> Option<PathBuf> {
    let DiscoveryEnvironment { fixed_paths, path } = discovery;

    if let Some(path) = fixed_paths.into_iter().find(|path| is_executable(path)) {
        return Some(path);
    }

    let path = path?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "matinee-doctor-tests-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temporary test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn discovery(fixed_paths: Vec<PathBuf>, path: Option<PathBuf>) -> DiscoveryEnvironment {
        DiscoveryEnvironment {
            fixed_paths,
            path: path.map(PathBuf::into_os_string),
        }
    }

    fn create_executable(path: &Path) {
        fs::write(path, b"browser").expect("create executable fixture");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(path)
                .expect("read executable fixture metadata")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("mark fixture executable");
        }
    }

    #[cfg(unix)]
    fn create_non_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, b"not executable").expect("create non-executable fixture");
        let mut permissions = fs::metadata(path)
            .expect("read non-executable fixture metadata")
            .permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(path, permissions).expect("mark fixture non-executable");
    }

    #[test]
    fn finds_firefox_at_injected_fixed_path() {
        let temp = TempDir::new();
        let fixed_path = temp.path().join("firefox-fixed");
        create_executable(&fixed_path);

        let found = find_browser(&BROWSERS[0], discovery(vec![fixed_path.clone()], None));

        assert_eq!(found, Some(fixed_path));
    }

    #[test]
    fn finds_google_chrome_at_injected_fixed_path() {
        let temp = TempDir::new();
        let fixed_path = temp.path().join("chrome-fixed");
        create_executable(&fixed_path);

        let found = find_browser(&BROWSERS[1], discovery(vec![fixed_path.clone()], None));

        assert_eq!(found, Some(fixed_path));
    }

    #[test]
    fn falls_through_to_an_injected_path_directory() {
        let temp = TempDir::new();
        let path_candidate = temp.path().join("firefox");
        create_executable(&path_candidate);

        let found = find_browser(
            &BROWSERS[0],
            discovery(Vec::new(), Some(temp.path().to_path_buf())),
        );

        assert_eq!(found, Some(path_candidate));
    }

    #[cfg(unix)]
    #[test]
    fn ignores_a_non_executable_file_with_a_matching_name() {
        let temp = TempDir::new();
        let path_candidate = temp.path().join("firefox");
        create_non_executable(&path_candidate);

        let found = find_browser(
            &BROWSERS[0],
            discovery(Vec::new(), Some(temp.path().to_path_buf())),
        );

        assert_eq!(found, None);
    }

    #[test]
    fn fixed_path_precedes_an_injected_path_candidate() {
        let fixed_temp = TempDir::new();
        let path_temp = TempDir::new();
        let fixed_path = fixed_temp.path().join("firefox-fixed");
        let path_candidate = path_temp.path().join("firefox");
        create_executable(&fixed_path);
        create_executable(&path_candidate);

        let found = find_browser(
            &BROWSERS[0],
            discovery(vec![fixed_path.clone()], Some(path_temp.path().to_path_buf())),
        );

        assert_eq!(found, Some(fixed_path));
    }

    #[test]
    fn doctor_reports_success_through_injected_discovery() {
        let temp = TempDir::new();
        let firefox_path = temp.path().join("firefox");
        let chrome_path = temp.path().join("chrome");
        create_executable(&firefox_path);
        create_executable(&chrome_path);

        let result = doctor_with_discovery([
            discovery(vec![firefox_path.clone()], None),
            discovery(vec![chrome_path.clone()], None),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let outcome = emit_doctor_output(&result, &mut stdout, &mut stderr);

        assert_eq!(
            stdout,
            format!(
                "Firefox\t{}\nGoogle Chrome\t{}\n",
                firefox_path.display(),
                chrome_path.display()
            )
            .into_bytes()
        );
        assert_eq!(stderr, b"");
        assert_eq!(outcome, ExitCode::SUCCESS);
    }

    #[test]
    fn doctor_reports_no_browser_failure_through_injected_discovery() {
        let result = doctor_with_discovery([
            discovery(Vec::new(), None),
            discovery(Vec::new(), None),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let outcome = emit_doctor_output(&result, &mut stdout, &mut stderr);

        assert_eq!(stdout, b"Firefox\tnot found\nGoogle Chrome\tnot found\n");
        assert_eq!(
            stderr,
            b"no supported browser found; install Firefox or Google Chrome\n"
        );
        assert_eq!(outcome, ExitCode::FAILURE);
    }
}
