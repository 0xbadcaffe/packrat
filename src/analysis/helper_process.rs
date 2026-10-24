use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;

pub fn spawn_stdin_stdout_helper(program: &Path, label: &str) -> Result<Child, String> {
    let mut last_error = None;
    for attempt in 0..5 {
        match Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => return Ok(child),
            Err(error) if is_text_busy(&error) && attempt < 4 => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(format!(
                    "start {label} helper {}: {error}",
                    program.display()
                ));
            }
        }
    }
    let error = last_error
        .map(|error| error.to_string())
        .unwrap_or_else(|| "unknown spawn error".into());
    Err(format!(
        "start {label} helper {}: {error}",
        program.display()
    ))
}

fn is_text_busy(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(26)
}

pub struct JsonLineHelper {
    child: Child,
    requests: SyncSender<Vec<u8>>,
    responses: Receiver<Result<Vec<u8>, String>>,
    io_worker: Option<std::thread::JoinHandle<()>>,
    timeout: Duration,
    failed: bool,
    program: PathBuf,
    label: String,
}

impl std::fmt::Debug for JsonLineHelper {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JsonLineHelper")
            .field("program", &self.program)
            .field("label", &self.label)
            .field("pid", &self.child.id())
            .finish()
    }
}

impl JsonLineHelper {
    pub fn spawn(program: impl AsRef<Path>, label: impl Into<String>) -> Result<Self, String> {
        Self::spawn_with_limits(program, label, Duration::from_secs(2), 4 * 1024 * 1024)
    }

    pub fn spawn_with_limits(
        program: impl AsRef<Path>,
        label: impl Into<String>,
        timeout: Duration,
        response_limit: usize,
    ) -> Result<Self, String> {
        if timeout.is_zero() || response_limit == 0 || response_limit > 4 * 1024 * 1024 {
            return Err("Invalid helper timeout or response limit".into());
        }
        let program = program.as_ref().to_path_buf();
        let label = label.into();
        let mut child = spawn_persistent_helper(&program, &label)?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| format!("{label} helper stdin unavailable"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| format!("{label} helper stdout unavailable"))?;
        let (requests, work) = mpsc::sync_channel::<Vec<u8>>(1);
        let (results, responses) = mpsc::sync_channel(1);
        let io_worker = match std::thread::Builder::new()
            .name("packrat-helper-io".into())
            .spawn(move || {
                let mut input = BufWriter::new(input);
                let mut output = BufReader::new(output);
                while let Ok(request) = work.recv() {
                    let result = (|| {
                        input
                            .write_all(&request)
                            .and_then(|_| input.write_all(b"\n"))
                            .and_then(|_| input.flush())
                            .map_err(|error| error.to_string())?;
                        let mut response = Vec::new();
                        Read::take(&mut output, response_limit as u64 + 1)
                            .read_until(b'\n', &mut response)
                            .map_err(|error| error.to_string())?;
                        if response.len() > response_limit {
                            return Err("Helper response exceeds byte limit".into());
                        }
                        if response.last() != Some(&b'\n') {
                            return Err(
                                "Helper closed stdout or returned an unterminated response".into(),
                            );
                        }
                        Ok(response)
                    })();
                    let failed = result.is_err();
                    if results.send(result).is_err() || failed {
                        break;
                    }
                }
            }) {
            Ok(worker) => worker,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("start {label} helper I/O: {error}"));
            }
        };
        Ok(Self {
            child,
            requests,
            responses,
            io_worker: Some(io_worker),
            timeout,
            failed: false,
            program,
            label,
        })
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn request<Request, Response>(&mut self, request: &Request) -> Result<Response, String>
    where
        Request: serde::Serialize,
        Response: serde::de::DeserializeOwned,
    {
        if self.failed {
            return Err(format!(
                "{} helper is unavailable after an earlier failure",
                self.label
            ));
        }
        let request = serde_json::to_vec(request)
            .map_err(|error| format!("encode {} helper request: {error}", self.label))?;
        if request.len() > 4 * 1024 * 1024 {
            return Err("Helper request exceeds byte limit".into());
        }
        if self.requests.try_send(request).is_err() {
            self.terminate();
            return Err(format!("{} helper request queue unavailable", self.label));
        }
        let result = self
            .responses
            .recv_timeout(self.timeout)
            .map_err(|error| {
                format!(
                    "{} helper response timeout/disconnection: {error}",
                    self.label
                )
            })
            .and_then(|response| {
                response.map_err(|error| format!("{} helper: {error}", self.label))
            })
            .and_then(|response| {
                serde_json::from_slice(&response)
                    .map_err(|error| format!("decode {} helper response: {error}", self.label))
            });
        if result.is_err() {
            self.terminate();
        }
        result
    }

    fn terminate(&mut self) {
        self.failed = true;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for JsonLineHelper {
    fn drop(&mut self) {
        self.terminate();
        // Do not join a pipe reader that a helper's descendant may keep open.
        if let Some(worker) = self.io_worker.take() {
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

fn spawn_persistent_helper(program: &Path, label: &str) -> Result<Child, String> {
    let mut last_error = None;
    for attempt in 0..5 {
        match Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => return Ok(child),
            Err(error) if is_text_busy(&error) && attempt < 4 => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(format!(
                    "start {label} helper {}: {error}",
                    program.display()
                ));
            }
        }
    }
    Err(format!(
        "start {label} helper {}: {}",
        program.display(),
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unknown spawn error".into())
    ))
}
