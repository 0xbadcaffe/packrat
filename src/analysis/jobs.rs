//! Lightweight background job framework for heavy analysis operations.
//!
//! Jobs run in tokio tasks and communicate via channels. The UI polls
//! `JobQueue::poll()` each tick to collect completed results without blocking.

use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use tokio::sync::mpsc;

// ─── Job identity ─────────────────────────────────────────────────────────────

static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(u64);

impl JobId {
    fn next() -> Self { Self(JOB_COUNTER.fetch_add(1, Ordering::Relaxed)) }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "job#{}", self.0)
    }
}

// ─── Job status ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum JobStatus {
    Running { progress: f32, label: String },
    Done,
    Failed(String),
    Cancelled,
}

// ─── Job result ───────────────────────────────────────────────────────────────

/// Typed result that a completed job can return.
#[derive(Debug)]
pub enum JobResult {
    /// A list of text lines (generic output).
    Lines(Vec<String>),
    /// Carving produced extracted file paths.
    CarvedFiles(Vec<super::carving::CarvedObject>),
    /// Stream reassembly produced reconstructed bytes.
    Stream { flow_id: String, client: Vec<u8>, server: Vec<u8> },
    /// YARA matches.
    YaraMatches(Vec<String>),
    /// Generic success message.
    Ok(String),
}

// ─── Job descriptor ───────────────────────────────────────────────────────────

pub struct Job {
    pub id:       JobId,
    pub name:     String,
    pub status:   JobStatus,
    cancelled:    Arc<AtomicBool>,
    result_rx:    mpsc::Receiver<(JobStatus, Option<JobResult>)>,
}

impl Job {
    pub fn is_running(&self) -> bool {
        matches!(self.status, JobStatus::Running { .. })
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn progress(&self) -> f32 {
        if let JobStatus::Running { progress, .. } = &self.status { *progress } else { 1.0 }
    }

    pub fn label(&self) -> &str {
        match &self.status {
            JobStatus::Running { label, .. } => label,
            JobStatus::Done                  => "done",
            JobStatus::Failed(_)             => "failed",
            JobStatus::Cancelled             => "cancelled",
        }
    }
}

// ─── Job queue ────────────────────────────────────────────────────────────────

/// Holds all active and recently completed jobs.
#[derive(Default)]
pub struct JobQueue {
    jobs: Vec<Job>,
    completed: Vec<(JobId, String, Option<JobResult>)>,
}

impl JobQueue {
    /// Poll all running jobs for status updates. Returns completed results.
    pub fn poll(&mut self) -> Vec<(JobId, String, Option<JobResult>)> {
        let mut done = Vec::new();
        for job in &mut self.jobs {
            if !job.is_running() { continue; }
            while let Ok((status, result)) = job.result_rx.try_recv() {
                let is_terminal = !matches!(status, JobStatus::Running { .. });
                job.status = status;
                if is_terminal {
                    done.push((job.id, job.name.clone(), result));
                    break;
                }
            }
        }
        self.jobs.retain(|j| j.is_running());
        self.completed.extend(done.iter().map(|(id, n, _)| (*id, n.clone(), None)));
        if self.completed.len() > 100 { self.completed.drain(0..50); }
        done
    }

    pub fn running(&self) -> Vec<&Job> {
        self.jobs.iter().filter(|j| j.is_running()).collect()
    }

    pub fn running_count(&self) -> usize {
        self.jobs.iter().filter(|j| j.is_running()).count()
    }

    pub fn cancel_all(&self) {
        for j in &self.jobs { j.cancel(); }
    }
}

// ─── Job builder helper ───────────────────────────────────────────────────────

/// Spawn a background job. `f` receives a cancel flag and a progress sender.
pub fn spawn<F, Fut>(queue: &mut JobQueue, name: impl Into<String>, f: F) -> JobId
where
    F: FnOnce(Arc<AtomicBool>, mpsc::Sender<(JobStatus, Option<JobResult>)>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let id = JobId::next();
    let name = name.into();
    let cancelled = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel(64);

    let cancel_clone = Arc::clone(&cancelled);
    tokio::spawn(f(cancel_clone, tx));

    queue.jobs.push(Job {
        id,
        name,
        status: JobStatus::Running { progress: 0.0, label: "starting".into() },
        cancelled,
        result_rx: rx,
    });

    id
}

/// Helper: check cancellation inside a job.
pub fn is_cancelled(flag: &AtomicBool) -> bool {
    flag.load(Ordering::Relaxed)
}

/// Helper: send a progress update from inside a job.
pub async fn report_progress(
    tx: &mpsc::Sender<(JobStatus, Option<JobResult>)>,
    pct: f32,
    label: impl Into<String>,
) {
    let _ = tx.send((JobStatus::Running { progress: pct, label: label.into() }, None)).await;
}

/// Helper: send the final result.
pub async fn report_done(
    tx: &mpsc::Sender<(JobStatus, Option<JobResult>)>,
    result: Option<JobResult>,
) {
    let _ = tx.send((JobStatus::Done, result)).await;
}

/// Helper: report failure.
pub async fn report_error(
    tx: &mpsc::Sender<(JobStatus, Option<JobResult>)>,
    msg: impl Into<String>,
) {
    let _ = tx.send((JobStatus::Failed(msg.into()), None)).await;
}
