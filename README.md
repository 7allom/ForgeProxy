<div align="center">
  <img src="assets/logo.png" width="128" alt="ForgeProxy logo" />
  <h1>ForgeProxy</h1>
  <p>A fast, lightweight HTTP/HTTPS intercepting proxy and web testing workbench, built with Rust &amp; egui.</p>
  <p>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/language-Rust-orange.svg" alt="Rust" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0" /></a>
    <a href="https://github.com/7allom/ForgeProxy/releases"><img src="https://img.shields.io/github/v/release/7allom/ForgeProxy?label=release" alt="Latest release" /></a>
  </p>
</div>

ForgeProxy sits between your browser and the applications you're testing. It records every request, lets you hold and edit traffic in flight, decrypts HTTPS with certificates it issues on the fly, and gives you a set of manual and automated testing tools around that traffic, all in one native desktop window.

The same single binary also runs without a window, so you can capture traffic, scan a target or replay a request from a terminal or a CI job.

> [!WARNING]
> **Use responsibly.** Only test systems you own or have explicit permission to test.

---

## Highlights

- **HTTPS with little or no setup.** The built-in **Open browser** button launches an installed browser in an isolated profile that already uses the proxy. Where the browser accepts it, ForgeProxy's root CA is trusted through a certificate pin given on the command line, so nothing is added to your operating system's or your everyday browser's certificate stores and certificate errors are never switched off wholesale. A browser that can't take the pin still gets the proxy, and you import the CA into that profile yourself.
- **Lightweight and native.** One executable, no runtime to install, a small memory footprint, and a native GUI on Linux and Windows.
- **A full toolkit around your traffic.** Intercept, HTTP history, a site map and scope, a scanner, Repeater, Intruder, Interactor, Sequencer, Decoder, Comparer, Logger, Organizer and Automation, all sharing the same history and scope.
- **Scriptable.** Headless `proxy`, `scan`, `repeat`, `intruder`, `sequence` and `decode` subcommands, most with JSON output, and CI-friendly exit codes.

---

## Installation

### Pre-built binaries

Download the asset for your platform from [GitHub Releases](https://github.com/7allom/ForgeProxy/releases):

| Platform | Architecture | Release asset |
| --- | --- | --- |
| Linux | `x86_64` | `forgeproxy-linux-x86_64.tar.gz` |
| Windows | `x86_64` | `forgeproxy-windows-x86_64.zip` |

On Linux:

```bash
tar -xzf forgeproxy-linux-x86_64.tar.gz
./forgeproxy
```

On Windows, extract the zip and run `forgeproxy.exe`.

### Building from source

You need a stable Rust toolchain with `cargo` ([rustup.rs](https://rustup.rs)). On Debian or Ubuntu, also install the windowing and keyboard libraries (Windows needs nothing extra):

```bash
sudo apt-get install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev
```

Then:

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

Release builds are fully optimized, link-time optimized and stripped.

---

## Quickstart

### 1. Launch the app

Run `forgeproxy`. On start-up it:

- opens a temporary project (click the project name on the top bar and choose **Save project as...** to keep your work; you're asked before a temporary project with data in it is closed),
- starts the proxy listener on **`127.0.0.1:8080`** (change it under **Settings > Tools > Proxy > Proxy listeners**),
- loads its root CA from the config directory, or creates one on first run. The **Event log** in the status bar shows the result and the certificate's fingerprint.

### 2. Open the isolated browser

Click the globe on the top bar (or **Open browser** on the Dashboard or in Proxy > Intercept). ForgeProxy starts an installed browser in its own profile, with the proxy at `127.0.0.1:8080` already set and, if the browser supports it, the root CA pinned. Your everyday browser profile is never touched. If the browser it finds can't take the pin, the Event log says so and you import the exported certificate into that profile.

> [!TIP]
> To use a different browser or tool, point its HTTP and HTTPS proxy at `127.0.0.1:8080`. To intercept its HTTPS, export the root certificate (DER or PEM) from **Settings > Tools > Proxy** and import it into that client's trusted authorities.

### 3. Intercept HTTPS against your target

1. **HTTPS interception is on by default.** **Intercept HTTPS**, in the Root CA certificate section of **Settings > Tools > Proxy**, is ticked out of the box. Untick it to pass HTTPS through unopened. If you change it while a launched browser is open, close the browser and launch it again: a running instance keeps the settings it started with.
2. **Define the scope.** In **Target > Scope**, add include rules such as `https://shop.example.com` or `*.example.com`. Use **Check a URL** to try them out.
3. **Intercept only what matters.** In **Proxy > Intercept**, tick **Only in scope** and turn **Intercept on**. Requests to your target are held for you to edit, forward or drop, and everything else goes straight through (and is still recorded).
4. **Review the traffic.** Decrypted requests appear in **Proxy > HTTP history** with full `https://` URLs, status codes and bodies. Right-click any row to send it to another tool or to add it to scope.

If a client refuses the intercepted connection because it pins its server certificate, add its host (`api.example.com`, or `*.example.com` for subdomains) under **Settings > Tools > Proxy > TLS pass-through**, and its HTTPS is tunnelled unopened.

---

## Features

### Proxy

- **Intercept**: hold each request, edit it, then forward or drop it. **Only in scope** holds just your target's requests.
- **HTTP history**: everything that went through the proxy, with a GraphQL request's operation (`mutation SignIn`) in a column of its own, since every operation against an endpoint is otherwise the same method on the same path. Search it with plain text or a regex, show only certain status classes (2xx to 5xx), hide static files and requests that got no response, or limit it to your scope. Right-click a row to send it to Repeater, Intruder, Sequencer, Decoder, Comparer or Organizer, add it to or remove it from scope, or copy it as a command line.
- **GraphQL**: a request carrying an operation is recognised wherever it arrives — a JSON body, an `application/graphql` document, a query string, or a batch of several — and the operation it carries (`mutation SignIn`) is shown, searched and sorted as a column of its own. Any message pane will show it as **GraphQL**: the document re-indented, with its variables as JSON under it, instead of one long escaped string.
- **Match and replace**: rules that rewrite the request line, request or response headers, or request or response bodies, with plain text or regular expressions. They apply to proxied traffic and to requests sent from Repeater. In a header rule, an empty match adds the replacement as a new header and an empty replacement removes the matching headers.
- **External command rules**: a rule can pipe the matched headers or body through one of your registered programs (Settings > External tools) and use its output instead, for jobs like re-signing a request or decoding a custom format. A rule stores only the program's name, so a project file never carries a command line: open someone else's project and its command rules do nothing until you register a program of that name yourself (the Event log tells you which). Each run has a time limit (1 second by default, set per rule) and a 4 MiB output cap. If the program fails, times out or exits non-zero, the original traffic goes through unchanged and a warning goes to the Event log.
- **Clean bodies**: chunked responses are decoded into plain bodies with an exact `Content-Length` before they reach history, your rules or the browser. Responses to requests ForgeProxy sends itself (Repeater, Intruder, the scanner, the CLI) are unpacked from gzip or deflate.

### Target

- **Site map**: a tree of every host and path in the history, grouped by origin and then by path.
- **Scope**: include and exclude rules. A simple rule is a URL prefix, an origin, a host name, or a domain with its subdomains (`*.example.com`). An advanced rule matches protocol, host, port and path separately, with regular expressions. Scope decides what **Only in scope** holds in Intercept and what the history and site map show when you filter to it.

### Scanner

Start a scan from **Dashboard > New scan**, or with `forgeproxy scan` on the command line. The scanner requests the URL you give it, or follows its links (same scheme, host and port only) when crawling is on, and checks what comes back:

- **Passive checks** on every page it fetches: missing HSTS, CSP and clickjacking protection, cookies without `Secure` or `HttpOnly`, cacheable HTTPS responses, passwords sent over plain HTTP or with autocomplete on, directory listings, and leaked email addresses or private IP addresses.
- **Active checks** on the starting URL: a test value in the query string that comes back unchanged in the page (reflected input), and database error messages.
- **Out-of-band checks**, when an Interactor relay is set up: probes for blind SSRF, blind XXE and blind command injection, with each callback matched back to the request that caused it.

Findings show up in the scan's task on the Dashboard and in **All issues**, and can be exported as an HTML or XML report. **Target > Issues** lists every issue type the scanner knows about.

The Dashboard also has a **live passive crawl** task. While its **Capturing** switch is on, it lists the items your proxied browsing adds to the site map. It doesn't run the checks above.

### Manual testing tools

| Tool | What it does |
| --- | --- |
| **Repeater** | Edit and resend requests, each in its own tab, with the address bar, method and `Host` header kept in sync. Can follow redirects. |
| **Intruder** | Mark positions with `§...§` and run an input list through them: one position at a time, the same value everywhere, two lists in parallel, or every combination of two lists. Lists are typed or pasted in, or loaded from a text file. |
| **Interactor** | Generate unique callback addresses, plant them in requests, and watch for the DNS, HTTP, SMTP and other interactions they trigger on the relay. |
| **Sequencer** | Collect session tokens live or paste them in, then measure their randomness with character-level and bit-level statistical tests and an effective-entropy estimate. |
| **Decoder** | Chain URL, HTML, Base64, Base64URL, hex, octal, binary and gzip encode and decode steps, compute hashes, try smart decode, or split a JWT into its header and payload. |
| **Message panes** | Every request and response reads as **Raw**, **Pretty** (JSON and markup re-indented and coloured), **Hex** (16 bytes a row with an ASCII column) or **GraphQL**. Each pane remembers its own choice; Settings > Display sets which one they open on. |
| **Comparer** | Word-level and byte-level diffs of two messages in side-by-side panes that stay level, so matching lines line up. |
| **Logger** | Every request sent by Proxy, Repeater, Intruder, the scanner and Sequencer, with its response. |
| **Organizer** | Keep interesting requests in collections, each with a status (new, in progress, postponed, done, ignored) and your notes. |
| **Inspector** | A side panel (`Ctrl+Shift+N`) that breaks the selected message into parameters, headers and cookies, and a GraphQL request into its operation and each of its variables. |

### Automation

Register your own programs and chain them into pipelines. Arguments are templates: `{url}`, `{host}`, `{path}`, `{req_file}`, `{res_file}` and the like are filled in from the selected request, `{prev_out_file}` holds the previous step's output, and `{var:KEY}` takes a value you give when starting the run. Nothing goes through a shell, so a URL containing `;` or `$(...)` reaches the program as plain text. Output streams into a live console, and a program can be set to have the findings it prints as JSON imported into the issue list. Pipelines export as bundle files you can share, and run unattended from the command line.

### Projects

A project is a `.forge` file: one JSON document holding the history (which the site map is built from), scope, Match and replace rules, Dashboard tasks and their findings, Repeater tabs, the Intruder setup, Interactor payloads and interactions, Organizer items, and the project's proxy settings. A project saved by an older version opens here unchanged, with nothing where this version would have kept more.

---

## Getting around

- **Top bar**: the project menu (click the project name), a search box that finds any tool or action (`Ctrl+K`), the browser and settings buttons, and a `⋯` menu for the theme, the Inspector, keyboard shortcuts and exit.
- **Left rail**: the Dashboard, then the tools in three groups: Traffic (Proxy, Target, Logger), Testing (Repeater, Intruder, Interactor, Sequencer) and Tools (Decoder, Comparer, Organizer, Automation). On a narrower window it shrinks to icons, and on a very narrow one it becomes a slide-out menu.
- **Status bar**: the Event log, All issues, and the listener's state at a glance.
- **Shortcuts**: every tool has one, and you can change them under **Settings > Hotkeys**.
- **Themes**: dark by default, with a light theme in the `⋯` menu (or start with `--light`).

---

## Command line

Each subcommand has its own `--help`. Exit codes are `0` for success, `1` for a bad command line or a run that didn't finish, and `2` when `--fail-on-findings` is set and something was found.

```bash
# record traffic with no window, until Ctrl+C or for ten minutes
forgeproxy proxy --project capture.forge --port 8080
forgeproxy proxy --project capture.forge --duration 600

# crawl and scan a site, write a report, and fail the CI job on any finding
forgeproxy scan https://staging.example.com --crawl --report issues.html --fail-on-findings

# findings as JSON, with out-of-band checks through an Interactor relay
forgeproxy scan https://staging.example.com --crawl --json --interactor relay.example.com

# send a raw request saved in a file
forgeproxy repeat --req login.txt --target https://staging.example.com --follow-redirects

# run an input set through a request, keeping only 200s and redirects
forgeproxy intruder --req search.txt --wordlist terms.txt --match-status 200,3xx

# token randomness and decoding
forgeproxy sequence --file tokens.txt
forgeproxy decode url-decode,base64-decode,jwt-decode --input "..."

# run a saved Automation pipeline unattended
forgeproxy --run-plan nightly --target https://staging.example.com --report out.html
```

`--json` works on most subcommands, `--project` keeps the results in a `.forge` file, and `--config <dir>` points at a different settings folder, which is handy in containers.

---

## Where ForgeProxy keeps its files

| | Linux | Windows |
| --- | --- | --- |
| Settings and root CA (`settings.json`, `ca.crt`, `ca.key`) | `~/.config/forgeproxy` | `%APPDATA%\ForgeProxy` |
| Launched-browser profiles | `~/.local/share/forgeproxy` | `%LOCALAPPDATA%\ForgeProxy` |
| Projects and reports (default) | `~/Documents` | `%USERPROFILE%\Documents` |

Set `FORGEPROXY_CONFIG_DIR` (or pass `--config`) to keep settings and the root CA somewhere else. On Linux the private key file is created with owner-only permissions.

> [!CAUTION]
> **Keep `ca.key` private.** Anyone holding it can impersonate any site to a client that trusts the CA. You can export the certificate (never the key), or regenerate the CA, from **Settings > Tools > Proxy**.

---

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.

Issue descriptions and remediation advice for the CWE numbers the scanner reports come from MITRE's [Common Weakness Enumeration](https://cwe.mitre.org), Copyright © The MITRE Corporation, used under the [CWE Terms of Use](assets/cwe/LICENSE). CWE is a trademark of The MITRE Corporation. After adding a check with a new CWE, run `python3 tools/update_cwe.py` to bring in its description.
