use std::path::Path;
use std::process::{Child, Command, Stdio};
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
