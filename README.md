<div align="center">
  <img src="assets/logo.png" width="128" alt="ForgeProxy Logo" />
  <h1>ForgeProxy</h1>
  <p>A fast, lightweight HTTP/HTTPS intercepting proxy for security research built with Rust &amp; egui.</p>
  <p>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/language-Rust-orange.svg" alt="Rust" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0" /></a>
    <a href="https://github.com/7allom/ForgeProxy/releases"><img src="https://img.shields.io/github/v/release/7allom/ForgeProxy?include_prereleases&label=release&color=yellow" alt="Latest Release" /></a>
  </p>
</div>

ForgeProxy sits between your browser and the applications you are testing. It records every request, lets you hold and edit traffic in flight, decrypts HTTPS with certificates it issues on the fly, and gives you a set of manual testing tools around that traffic, all in one native desktop window.

> [!NOTE]
> **Alpha release.** The core interception pipeline and toolset are in place; expect rough edges and changes between releases.

> [!WARNING]
> **Use responsibly.** Only test systems you own or have explicit permission to test.

---

## Core Highlights

- **Zero-config HTTPS interception.** **Open browser** launches a Chromium-family browser (Chrome, Chromium, Edge, Brave, Vivaldi) in an isolated profile that trusts ForgeProxy's root CA through Chromium's `--ignore-certificate-errors-spki-list` pin. There is no root CA to install by hand, nothing is added to your operating system's or browser's certificate stores, and the blanket `--ignore-certificate-errors` flag is never used.
- **Lightweight and cross-platform.** A native GUI built with [egui](https://github.com/emilk/egui), with a small memory footprint and no runtime to install. Pre-built binaries are published for Linux and Windows.
- **Comprehensive security toolkit.** Proxy Intercept, HTTP History, Repeater, Intruder, Decoder (with JWT inspection), Sequencer (token randomness analysis) and Comparer, plus a scope-aware site map, an Inspector panel and more.

---

## Features

- **TLS interception.** HTTPS `CONNECT` tunnels are terminated with a per-host **P-256 ECDSA** certificate minted on the fly and signed by ForgeProxy's own root CA. Each host's `rustls` server configuration is cached, so repeat connections skip the signing cost, and real servers are verified against Mozilla's root store. The engine uses one blocking thread per connection, with no async runtime.
- **Clean payloads.** `Transfer-Encoding: chunked` responses are decoded into plain bodies with an exact `Content-Length` before they reach history, the match-and-replace rules or the browser. Gzip and deflate bodies are unpacked for Repeater.
- **Noise suppression.** The **Only in scope** toggle makes Intercept hold only requests inside your target scope, so browser telemetry and background updates flow past untouched (and are still recorded in history).
- **TLS pass-through.** A bypass list of hosts (`api.example.com`, or `*.example.com` for subdomains) whose HTTPS is tunnelled unopened, for clients that pin their server certificates.
- **Toolset:**

  | Tool | What it does |
  | --- | --- |
  | **Dashboard** | Tasks, live passive crawl and scan results, with an *All issues* view |
  | **Target** | Scope rules (URL prefixes, hosts, wildcard domains or regular expressions) and a site map |
  | **Proxy** | Intercept (hold, edit, forward or drop requests), HTTP history with a filter bar, match-and-replace rules |
  | **Inspector** | Side panel breaking requests and responses into attributes, query and body parameters, headers and cookies |
  | **Repeater** | Edit and resend requests, with the address bar, method and `Host` header kept in sync |
  | **Intruder** | Sniper, Battering ram, Pitchfork and Cluster bomb attacks with live results |
  | **Sequencer** | Captures session tokens and analyses their randomness |
  | **Decoder** | URL, HTML, Base64, Base64URL, hex, octal, binary and GZIP encoding, hashing, smart decode and a JWT inspector |
  | **Comparer** | Word-level (Myers diff) and byte-level comparisons in synchronized side-by-side panes |

  Also included: Logger, Organizer, Collaborator payloads, a command palette (`Ctrl+K`) and an Event log drawer.

---

## Installation

| Platform | Architecture | Release asset |
| --- | --- | --- |
| Linux | `x86_64` | `forgeproxy-linux-x86_64.tar.gz` |
| Windows | `x86_64` | `forgeproxy-windows-x86_64.zip` |

### Pre-built binaries

Download the asset for your platform from [GitHub Releases](https://github.com/7allom/ForgeProxy/releases), then:

- **Linux:**

  ```bash
  tar -xzf forgeproxy-linux-x86_64.tar.gz
  ./forgeproxy
  ```

- **Windows:** extract `forgeproxy-windows-x86_64.zip` and run `forgeproxy.exe`.

### Building from source

**Prerequisites:** a stable Rust toolchain with `cargo` ([rustup.rs](https://rustup.rs)).

**Linux dependencies** (Debian/Ubuntu package names) for the X11/xcb windowing and keyboard libraries. Windows needs no extra system packages.

```bash
sudo apt-get install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev
```

**Build and run:**

```bash
git clone git@github.com:7allom/ForgeProxy.git
cd ForgeProxy

# build and start ForgeProxy in one step
cargo run --release

# or just build: target/release/forgeproxy (forgeproxy.exe on Windows)
cargo build --release

# run the test suite
cargo test
```

---

## Quickstart

### 1. Launch the app

Run `forgeproxy` (or `cargo run --release` from the source tree). On start-up ForgeProxy:

- opens a temporary in-memory project (use **Project > Save project as...** to keep your work; you're asked before closing a temporary project that has data in it),
- starts the proxy listener on **`127.0.0.1:8080`** (change it under **Settings > Tools > Proxy > Proxy listeners**),
- loads its root CA from the config directory, or creates one there on first run. The **Event log** in the status bar shows the result and the certificate's fingerprint.

### 2. Open the isolated browser

Click **Open browser** on the Dashboard (or the globe icon in the tab bar). ForgeProxy starts the first Chromium-family browser it finds, in its own profile, with the proxy at `127.0.0.1:8080` already set and the root CA pinned. Your everyday browser profile is never touched.

> [!TIP]
> To use a different browser or tool, point its HTTP and HTTPS proxy at `127.0.0.1:8080`. To intercept its HTTPS, install the root certificate exported from **Settings > Tools > Proxy** in it; for Firefox that's **Settings > Privacy & Security > Certificates > View Certificates > Authorities**. Firefox is also what **Open browser** falls back to when no Chromium-family browser is installed.

### 3. Intercept HTTPS against your target scope

1. **HTTPS interception is enabled by default.** **Intercept HTTPS** (under **Settings** (gear icon) **> Tools > Proxy > Root CA certificate**) is on out of the box, so the browser from **Open browser** has its HTTPS decrypted with no configuration. Untick it to pass HTTPS through unopened; launching the browser then logs a warning in the **Event log**.
2. **Launch the browser** with **Open browser**. If you change **Intercept HTTPS** while a launched browser is open, close it and launch it again: a running instance keeps the settings it started with.
3. **Define the scope:** in **Target > Scope**, add include rules such as `https://shop.example.com` or `*.example.com`. Use **Check a URL** to try them out.
4. **Intercept only what matters:** in **Proxy > Intercept**, tick **Only in scope** and turn **Intercept on**. Requests to your target are held for you to edit, forward or drop, and everything else goes straight through.
5. **Review the traffic:** decrypted requests appear in **Proxy > HTTP history** with full `https://` URLs, status codes and bodies. Open the filter bar and tick **Show only in-scope items** to hide the noise, and right-click any row to send it to Repeater, Intruder, Comparer or Organizer, or to add it to scope.

If a service refuses the intercepted connection because it pins its certificate, add its host under **Settings > Tools > Proxy > TLS pass-through**.

### Where ForgeProxy keeps its files

| | Linux | Windows |
| --- | --- | --- |
| Root CA (`ca.crt`, `ca.key`) | `~/.config/forgeproxy` | `%APPDATA%\ForgeProxy` |
| Launched-browser profiles | `~/.local/share/forgeproxy` | `%LOCALAPPDATA%\ForgeProxy` |
| Projects and reports (default) | `~/Documents` | `%USERPROFILE%\Documents` |

Set `FORGEPROXY_CONFIG_DIR` to keep the root CA somewhere else. The private key file is created with owner-only permissions on Linux.

> [!CAUTION]
> **Keep `ca.key` private.** Anyone holding it can impersonate any site to a browser that trusts the CA. You can export the certificate (never the key), or regenerate the CA, from **Settings > Tools > Proxy**.

---

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
