//! The compiled `forgeproxy proxy` stops cleanly when interrupted: it exits 0 and leaves a
//! project file holding what it captured.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A loopback server that answers every request with `served <path>`. Returns `host:port`.
fn serve() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let Ok(read_half) = stream.try_clone() else { continue };
            let mut reader = BufReader::new(read_half);
            let mut first = String::new();
            let _ = reader.read_line(&mut first);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
            }
            let path = first.split_whitespace().nth(1).unwrap_or("/").to_string();
            let body = format!("served {path}");
            let answer = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            let mut stream = stream;
            let _ = stream.write_all(answer.as_bytes());
        }
    });
    addr
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn an_interrupted_headless_proxy_saves_its_capture_and_exits_zero() {
    let upstream = serve();
    let dir = std::env::temp_dir().join(format!("forge-interrupt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("capture.forge");
    let port = free_port();

    // its own config directory, so no saved settings or CA from this machine leak in
    let mut child = Command::new(env!("CARGO_BIN_EXE_forgeproxy"))
        .args(["proxy", "--bind", "127.0.0.1", "--port", &port.to_string(), "--project"])
        .arg(&project)
        .arg("--config")
        .arg(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the proxy starts");
    let mut stderr = BufReader::new(child.stderr.take().unwrap());

    // wait until it says it is listening
    let mut banner = String::new();
    while !banner.contains("Listening on") {
        let mut line = String::new();
        if stderr.read_line(&mut line).unwrap_or(0) == 0 {
            let _ = child.kill();
            panic!("the proxy ended before listening: {banner}");
        }
        banner.push_str(&line);
    }

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the proxy listens");
    let request = format!("GET http://{upstream}/interrupted HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    assert!(answer.contains("served /interrupted"), "the proxy forwarded the request: {answer:?}");

    let status = Command::new("kill").args(["-INT", &child.id().to_string()]).status().expect("kill runs");
    assert!(status.success());

    let asked = Instant::now();
    let exit = loop {
        if let Some(exit) = child.try_wait().unwrap() {
            break exit;
        }
        if asked.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            panic!("the proxy did not stop after the interrupt");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut rest = String::new();
    let _ = stderr.read_to_string(&mut rest);
    assert_eq!(exit.code(), Some(0), "stderr: {banner}{rest}");
    assert!(rest.contains("Captured 1 request;"), "the summary: {rest}");

    let text = std::fs::read_to_string(&project).expect("the project was written");
    let saved: serde_json::Value = serde_json::from_str(&text).expect("the project is valid JSON");
    let paths: Vec<&str> = saved["history"]
        .as_array()
        .expect("a history list")
        .iter()
        .filter_map(|e| e["path"].as_str())
        .collect();
    assert_eq!(paths, ["/interrupted"]);
    let _ = std::fs::remove_dir_all(&dir);
}
