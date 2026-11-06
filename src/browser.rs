//! "Open browser": start an installed browser in its own profile, set to use the proxy.
//! Chromium-family browsers take the proxy on the command line; Firefox gets it from a
//! profile preferences file. The person's normal browser profile is never touched.

use std::path::PathBuf;
use std::process::{Command, Stdio};

const CHROMIUM_FAMILY: [&str; 9] = [
    "chromium", "chromium-browser", "google-chrome-stable", "google-chrome", "brave-browser",
    "brave", "microsoft-edge-stable", "vivaldi-stable", "thorium-browser",
];

/// `name` on PATH (with ".exe" on Windows).
fn find(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    std::env::split_paths(&path).map(|d| d.join(&file)).find(|p| p.is_file())
}

/// Where Windows installs the browsers (they're usually not on PATH): per-machine under
/// `%ProgramFiles%` and `%ProgramFiles(x86)%`, per-user under `%LOCALAPPDATA%`. Missing
/// variables fall back to the usual `C:\` locations. (name, executable), in preference order:
/// Chromium-family first, Firefox last.
pub fn windows_candidates(env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> Vec<(&'static str, PathBuf)> {
    let dir = |var: &str, default: &str| env(var).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(default));
    let pf = dir("ProgramFiles", r"C:\Program Files");
    let pf86 = dir("ProgramFiles(x86)", r"C:\Program Files (x86)");
    let local = env("LOCALAPPDATA").map(PathBuf::from);
    let mut out = Vec::new();
    let chrome = ["Google", "Chrome", "Application", "chrome.exe"];
    let edge = ["Microsoft", "Edge", "Application", "msedge.exe"];
    let brave = ["BraveSoftware", "Brave-Browser", "Application", "brave.exe"];
    let join = |base: &PathBuf, parts: &[&str]| parts.iter().fold(base.clone(), |p, part| p.join(part));
    for base in [&pf, &pf86] { out.push(("chrome", join(base, &chrome))); }
    if let Some(l) = &local { out.push(("chrome", join(l, &chrome))); }
    for base in [&pf86, &pf] { out.push(("msedge", join(base, &edge))); }
    for base in [&pf, &pf86] { out.push(("brave", join(base, &brave))); }
    if let Some(l) = &local { out.push(("brave", join(l, &brave))); }
    for base in [&pf, &pf86] { out.push(("firefox", join(base, &["Mozilla Firefox", "firefox.exe"]))); }
    out
}

/// Installed browsers in preference order: (name, executable, is Chromium-family).
fn installed() -> Vec<(String, PathBuf, bool)> {
    let mut out: Vec<(String, PathBuf, bool)> = CHROMIUM_FAMILY.iter().filter_map(|n| find(n).map(|p| (n.to_string(), p, true))).collect();
    if cfg!(target_os = "windows") {
        for (name, path) in windows_candidates(&crate::paths::env) {
            if path.is_file() && !out.iter().any(|(_, p, _)| *p == path) {
                out.push((name.to_string(), path, name != "firefox"));
            }
        }
    }
    if let Some(p) = find("firefox") {
        out.push(("firefox".to_string(), p, false));
    }
    // Chromium-family before Firefox: they take the proxy and the CA pin on the command line
    out.sort_by_key(|(_, _, chromium)| !chromium);
    out
}

fn profile_dir(kind: &str) -> PathBuf {
    crate::paths::data_dir().join(format!("browser-{kind}"))
}

/// Chromium flags for an isolated profile using the proxy; with `spki_pin`, certificates
/// whose chain includes that key (the root CA's) are accepted. Never
/// `--ignore-certificate-errors`: every other certificate is still checked as usual.
pub fn chromium_args(profile: &std::path::Path, host: &str, port: u16, spki_pin: Option<&str>, url: &str) -> Vec<String> {
    let mut args = vec![
        format!("--user-data-dir={}", profile.display()),
        format!("--proxy-server=http://{host}:{port}"),
        "--proxy-bypass-list=<-loopback>".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-component-update".to_string(),
        "--disable-sync".to_string(),
        "--disable-domain-reliability".to_string(),
        "--disable-client-side-phishing-detection".to_string(),
        "--disable-component-extensions-with-background-pages".to_string(),
        "--disable-default-apps".to_string(),
        "--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-search-engine-choice-screen".to_string(),
        "--simulate-outdated-no-au='Tue, 31 Dec 2099 23:59:59 GMT'".to_string(),
        "--disable-signin-scoped-device-id".to_string(),
        "--homepage=about:blank".to_string(),
    ];
    if let Some(pin) = spki_pin {
        args.push(format!("--ignore-certificate-errors-spki-list={pin}"));
    }
    args.push("--new-window".to_string());
    args.push(url.to_string());
    args
}

/// Launch a browser using the proxy at host:port, opening `url`. With `spki_pin` (HTTPS
/// interception on), a Chromium-family browser trusts the root CA without installing it.
/// Returns a message for the event log.
pub fn open(host: &str, port: u16, url: &str, spki_pin: Option<&str>) -> Result<String, String> {
    let browsers = installed();
    if let Some((name, bin, _)) = browsers.iter().find(|(_, _, chromium)| *chromium) {
        let profile = profile_dir("chromium");
        crate::paths::create_private_dir(&profile).map_err(|e| e.to_string())?; // cookies and sessions: owner-only
        Command::new(&bin)
            .args(chromium_args(&profile, host, port, spki_pin, url))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Couldn't start {name}: {e}"))?;
        return Ok(match spki_pin {
            Some(pin) => format!("Opened {name} with an isolated profile, using the proxy at {host}:{port}, trusting the root CA by its SPKI pin {pin}. \
                (If {name} was already open with this profile, close it first: a running instance keeps its old settings.)"),
            None => format!("Opened {name} with an isolated profile, using the proxy at {host}:{port}"),
        });
    }
    if let Some((_, bin, _)) = browsers.iter().find(|(_, _, chromium)| !*chromium) {
        let profile = profile_dir("firefox");
        crate::paths::create_private_dir(&profile).map_err(|e| e.to_string())?; // cookies and sessions: owner-only
        let prefs = format!(
            "user_pref(\"network.proxy.type\", 1);\n\
             user_pref(\"network.proxy.http\", \"{host}\");\nuser_pref(\"network.proxy.http_port\", {port});\n\
             user_pref(\"network.proxy.ssl\", \"{host}\");\nuser_pref(\"network.proxy.ssl_port\", {port});\n\
             user_pref(\"network.proxy.no_proxies_on\", \"\");\n\
             user_pref(\"network.proxy.allow_hijacking_localhost\", true);\n\
             user_pref(\"browser.shell.checkDefaultBrowser\", false);\n"
        );
        std::fs::write(profile.join("user.js"), prefs).map_err(|e| e.to_string())?;
        Command::new(&bin)
            .arg("-no-remote")
            .arg("-profile")
            .arg(&profile)
            .arg(url)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Couldn't start Firefox: {e}"))?;
        let note = if spki_pin.is_some() {
            " Firefox can't be told to trust the root CA from the command line: import the exported certificate in its settings (Certificates > Authorities) to use HTTPS interception."
        } else {
            ""
        };
        return Ok(format!("Opened Firefox with an isolated profile, using the proxy at {host}:{port}.{note}"));
    }
    Err(format!(
        "No supported browser found (Chromium, Chrome, Brave, Edge, Vivaldi or Firefox). \
         Set your browser's HTTP and HTTPS proxy to {host}:{port} instead."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_install_locations() {
        use std::ffi::OsString;
        let env = |k: &str| match k {
            "ProgramFiles" => Some(OsString::from(r"D:\Apps")),
            "LOCALAPPDATA" => Some(OsString::from(r"C:\Users\ana\AppData\Local")),
            _ => None,
        };
        let c = windows_candidates(&env);
        let paths: Vec<String> = c.iter().map(|(_, p)| p.display().to_string().replace('/', "\\")).collect();
        // every location you'd expect, built from the variables or the usual defaults
        for want in [r"D:\Apps\Google\Chrome\Application\chrome.exe",
                     r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                     r"C:\Users\ana\AppData\Local\Google\Chrome\Application\chrome.exe",
                     r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                     r"D:\Apps\Microsoft\Edge\Application\msedge.exe",
                     r"D:\Apps\Mozilla Firefox\firefox.exe"] {
            assert!(paths.iter().any(|p| p == want), "{want} in {paths:?}");
        }
        // Firefox comes after every Chromium-family candidate
        let first_ff = c.iter().position(|(n, _)| *n == "firefox").unwrap();
        assert!(c[..first_ff].iter().all(|(n, _)| *n != "firefox") && c[first_ff..].iter().all(|(n, _)| *n == "firefox"));
        // no LOCALAPPDATA: no per-user entries
        assert!(windows_candidates(&|_: &str| None).iter().all(|(_, p)| p.display().to_string().starts_with(r"C:\Program Files")));
    }

    #[test]
    fn chromium_flags() {
        let p = std::path::Path::new("/tmp/profile");
        let with = chromium_args(p, "127.0.0.1", 8080, Some("AbC+/x="), "about:blank");
        for want in [
            "--user-data-dir=/tmp/profile",
            "--proxy-server=http://127.0.0.1:8080",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-domain-reliability",
            "--disable-client-side-phishing-detection",
            "--disable-component-extensions-with-background-pages",
            "--disable-default-apps",
            "--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-search-engine-choice-screen",
            "--simulate-outdated-no-au='Tue, 31 Dec 2099 23:59:59 GMT'",
            "--disable-signin-scoped-device-id",
            "--homepage=about:blank",
            "--ignore-certificate-errors-spki-list=AbC+/x=",
        ] {
            assert!(with.iter().any(|a| a == want), "{want}");
        }
        assert!(!with.iter().any(|a| a == "--ignore-certificate-errors"), "never the blanket flag");
        assert_eq!(with.last().unwrap(), "about:blank");
        let without = chromium_args(p, "127.0.0.1", 8080, None, "about:blank");
        assert!(!without.iter().any(|a| a.starts_with("--ignore-certificate-errors")));
    }
}
