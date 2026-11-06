//! Per-user directories on Linux, macOS and Windows, from environment variables (no extra
//! crates). Each takes the environment lookup as a function so the Windows rules can be
//! tested on any platform.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// `std::env::var_os`, ignoring empty values.
pub fn env(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// The home directory: `HOME`, else `USERPROFILE` (Windows), else the current directory.
pub fn home_dir() -> PathBuf {
    home_with(&env)
}

pub fn home_with(env: &dyn Fn(&str) -> Option<OsString>) -> PathBuf {
    env("HOME").or_else(|| env("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

/// Where project files and reports go by default: `~/Documents` (`%USERPROFILE%\Documents`).
pub fn documents_dir() -> PathBuf {
    home_dir().join("Documents")
}

/// Per-user application data that isn't settings (browser profiles):
/// `%LOCALAPPDATA%\ForgeProxy` on Windows, `~/Library/Application Support/ForgeProxy` on
/// macOS, `$XDG_DATA_HOME/forgeproxy` (or `~/.local/share/forgeproxy`) elsewhere.
pub fn data_dir() -> PathBuf {
    data_with(&env, std::env::consts::OS)
}

pub fn data_with(env: &dyn Fn(&str) -> Option<OsString>, os: &str) -> PathBuf {
    match os {
        "windows" => env("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| home_with(env).join("AppData").join("Local")).join("ForgeProxy"),
        "macos" => home_with(env).join("Library").join("Application Support").join("ForgeProxy"),
        _ => env("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home_with(env).join(".local").join("share")).join("forgeproxy"),
    }
}

/// Settings (the root CA): `%APPDATA%\ForgeProxy` on Windows,
/// `~/Library/Application Support/ForgeProxy` on macOS, `$XDG_CONFIG_HOME/forgeproxy` (or
/// `~/.config/forgeproxy`) elsewhere.
pub fn config_with(env: &dyn Fn(&str) -> Option<OsString>, os: &str) -> PathBuf {
    match os {
        "windows" => env("APPDATA").map(PathBuf::from).unwrap_or_else(|| home_with(env).join("AppData").join("Roaming")).join("ForgeProxy"),
        "macos" => home_with(env).join("Library").join("Application Support").join("ForgeProxy"),
        _ => env("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home_with(env).join(".config")).join("forgeproxy"),
    }
}

/// Refuse to write to `path` if it exists as anything but a regular file: in particular a
/// symbolic link, which could send the data (a private key, say) somewhere else.
pub fn refuse_symlink(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(std::io::Error::other(format!("{} is a symbolic link; refusing to write through it", path.display()))),
        Ok(m) if !m.is_file() => Err(std::io::Error::other(format!("{} exists but isn't a regular file", path.display()))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Write a file only its owner can read and write (0600 on Unix), also when it already
/// existed with looser permissions. For files holding secrets or captured traffic. Refuses
/// a path that is a symbolic link or not a regular file (`refuse_symlink`).
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    refuse_symlink(path)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        opts.mode(0o600);
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    opts.open(path)?.write_all(data)
}

/// Create `dir` (and any missing parents) so only its owner can enter it (0700 on Unix);
/// an existing `dir` is set to 0700 too. Existing parents are left as they are.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn fake(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let m: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).filter(|v| !v.is_empty()).map(OsString::from)
    }

    #[test]
    fn windows_directories() {
        let env = fake(&[("USERPROFILE", r"C:\Users\ana"), ("APPDATA", r"C:\Users\ana\AppData\Roaming"), ("LOCALAPPDATA", r"C:\Users\ana\AppData\Local")]);
        assert_eq!(home_with(&env), PathBuf::from(r"C:\Users\ana"));
        assert_eq!(config_with(&env, "windows"), PathBuf::from(r"C:\Users\ana\AppData\Roaming").join("ForgeProxy"));
        assert_eq!(data_with(&env, "windows"), PathBuf::from(r"C:\Users\ana\AppData\Local").join("ForgeProxy"));
        // APPDATA / LOCALAPPDATA missing: derived from the profile directory
        let bare = fake(&[("USERPROFILE", r"C:\Users\ana")]);
        assert_eq!(config_with(&bare, "windows"), PathBuf::from(r"C:\Users\ana").join("AppData").join("Roaming").join("ForgeProxy"));
    }

    #[test]
    fn linux_directories() {
        let env = fake(&[("HOME", "/home/ana")]);
        assert_eq!(config_with(&env, "linux"), PathBuf::from("/home/ana/.config/forgeproxy"));
        assert_eq!(data_with(&env, "linux"), PathBuf::from("/home/ana/.local/share/forgeproxy"));
        let xdg = fake(&[("HOME", "/home/ana"), ("XDG_CONFIG_HOME", "/cfg"), ("XDG_DATA_HOME", "/data"), ("USERPROFILE", "ignored")]);
        assert_eq!(config_with(&xdg, "linux"), PathBuf::from("/cfg/forgeproxy"));
        assert_eq!(data_with(&xdg, "linux"), PathBuf::from("/data/forgeproxy"));
        // empty variables count as unset
        assert_eq!(config_with(&fake(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "")]), "linux"), PathBuf::from("/h/.config/forgeproxy"));
        assert_eq!(home_with(&fake(&[])), PathBuf::from("."));
    }

    #[cfg(unix)]
    #[test]
    fn private_files_and_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("forgeproxy-paths-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("a").join("b");
        create_private_dir(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        // an existing, looser folder is tightened
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        // files: new ones and existing world-readable ones end up 0600
        let f = dir.join("secret");
        write_private(&f, b"one").unwrap();
        assert_eq!(mode(&f), 0o600);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&f, b"two").unwrap();
        assert_eq!((mode(&f), std::fs::read(&f).unwrap()), (0o600, b"two".to_vec()));
        // a symbolic link is refused, and its target left untouched (and not re-permissioned)
        let target = base.join("elsewhere");
        std::fs::write(&target, b"keep").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = write_private(&link, b"secret").unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert_eq!((std::fs::read(&target).unwrap(), mode(&target)), (b"keep".to_vec(), 0o644));
        // a dangling link too (writing would create the target)
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(base.join("nowhere"), &dangling).unwrap();
        assert!(write_private(&dangling, b"x").is_err());
        assert!(!base.join("nowhere").exists());
        // and a directory in the way
        assert!(write_private(&dir, b"x").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
