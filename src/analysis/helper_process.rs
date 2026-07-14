use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
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
    input: BufWriter<ChildStdin>,
    output: BufReader<ChildStdout>,
    program: PathBuf,
    label: String,
}

impl std::fmt::Debug for JsonLineHelper {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("JsonLineHelper")
            .field("program", &self.program)
            .field("label", &self.label)
            .field("pid", &self.child.id())
            .finish()
    }
}

impl JsonLineHelper {
    pub fn spawn(program: impl AsRef<Path>, label: impl Into<String>) -> Result<Self, String> {
        let program = program.as_ref().to_path_buf();
        let label = label.into();
        let mut child = spawn_persistent_helper(&program, &label)?;
        let input = child.stdin.take().ok_or_else(|| format!("{label} helper stdin unavailable"))?;
        let output = child.stdout.take().ok_or_else(|| format!("{label} helper stdout unavailable"))?;
        Ok(Self { child, input: BufWriter::new(input), output: BufReader::new(output), program, label })
    }

    pub fn program(&self) -> &Path { &self.program }

    pub fn request<Request, Response>(&mut self, request: &Request) -> Result<Response, String>
    where
        Request: serde::Serialize,
        Response: serde::de::DeserializeOwned,
    {
        serde_json::to_writer(&mut self.input, request)
            .map_err(|error| format!("encode {} helper request: {error}", self.label))?;
        self.input.write_all(b"\n").and_then(|_| self.input.flush())
            .map_err(|error| format!("write {} helper request: {error}", self.label))?;
        let mut response = String::new();
        let count = self.output.read_line(&mut response)
            .map_err(|error| format!("read {} helper response: {error}", self.label))?;
        if count == 0 {
            let status = self.child.try_wait().ok().flatten()
                .map(|status| status.to_string()).unwrap_or_else(|| "closed stdout".into());
            return Err(format!("{} helper stopped: {status}", self.label));
        }
        serde_json::from_str(&response)
            .map_err(|error| format!("decode {} helper response: {error}", self.label))
    }
}

impl Drop for JsonLineHelper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_persistent_helper(program: &Path, label: &str) -> Result<Child, String> {
    let mut last_error = None;
    for attempt in 0..5 {
        match Command::new(program).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
            Ok(child) => return Ok(child),
            Err(error) if is_text_busy(&error) && attempt < 4 => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("start {label} helper {}: {error}", program.display())),
        }
    }
    Err(format!("start {label} helper {}: {}", program.display(),
        last_error.map(|error| error.to_string()).unwrap_or_else(|| "unknown spawn error".into())))
}
