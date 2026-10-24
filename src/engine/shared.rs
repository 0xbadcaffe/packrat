use super::AnalysisCore;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

/// Shared ownership with an immutable, frame-scoped read interface.
/// The analysis controller is the only adapter allowed to acquire write access.
#[derive(Clone)]
pub struct ReadCore(pub(super) Arc<Mutex<AnalysisCore>>);

pub struct CoreReadGuard<'a>(MutexGuard<'a, AnalysisCore>);

impl Deref for CoreReadGuard<'_> {
    type Target = AnalysisCore;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ReadCore {
    pub(crate) fn edit(&self) -> MutexGuard<'_, AnalysisCore> {
        self.0.lock().unwrap_or_else(|error| error.into_inner())
    }
    pub fn new(core: AnalysisCore) -> Self {
        Self(Arc::new(Mutex::new(core)))
    }
    pub fn try_read(&self) -> Result<Option<CoreReadGuard<'_>>, String> {
        match self.0.try_lock() {
            Ok(core) => Ok(Some(CoreReadGuard(core))),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Poisoned(_)) => {
                Err("Analysis state is poisoned after a worker failure".into())
            }
        }
    }

    /// Synchronous read for offline tools and tests, never the terminal loop.
    pub fn read(&self) -> Result<CoreReadGuard<'_>, String> {
        self.0
            .lock()
            .map(CoreReadGuard)
            .map_err(|_| "Analysis state is poisoned after a worker failure".into())
    }

    pub(super) fn into_core(self) -> Result<AnalysisCore, String> {
        Arc::try_unwrap(self.0)
            .map_err(|_| "Read handles still retain the stopped analysis core")?
            .into_inner()
            .map_err(|_| "Stopped analysis core is poisoned".into())
    }
}

impl Default for ReadCore {
    fn default() -> Self {
        Self::new(AnalysisCore::default())
    }
}
