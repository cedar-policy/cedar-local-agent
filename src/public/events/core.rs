//! Provides handles and receivers for updating data via a clock or a file change.

use std::fmt::Debug;
use std::fs::File;
use std::io;
use std::io::Read;
use std::time::Duration;

use fs2::FileExt;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::task::JoinHandle;
use tracing::{debug, error, instrument};
use uuid::Uuid;

/// An `EventUuid` helpful for logging.
#[derive(Debug, Clone)]
pub struct EventUuid(pub String);

/// An `Event` type limited to `Clock` or `File` type events for now.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// Represents a `Clock` signal, i.e. some period of time has passed.
    Clock(EventUuid),
    /// Represents a `File` signal, i.e. a local file has changed.
    File(EventUuid, String),
    /// For potentially adding future fields.
    #[non_exhaustive]
    Unknown,
}

/// Gives guidance for a reasonable refresh rate for most applications
#[derive(Debug)]
pub enum RefreshRate {
    /// 15 seconds is a reasonable refresh rate for most applications
    FifteenSeconds,
    /// Thirty second refresh rate
    ThirtySeconds,
    /// One minute refresh rate
    OneMinute,
    /// Warning: Setting refresh rates that are very low risks overwhelming the policy set source.
    /// Users should be cautious when setting refresh rates less than the default and ensure
    /// that their policy set source (the disk IO, AVP throttle limit, or anything else)
    /// can handle the rate
    Other(Duration),
}

impl RefreshRate {
    /// Get refresh rate as Duration
    pub fn value(&self) -> Duration {
        match *self {
            Self::FifteenSeconds => Duration::from_secs(15),
            Self::ThirtySeconds => Duration::from_secs(30),
            Self::OneMinute => Duration::from_secs(60),
            Self::Other(d) => d,
        }
    }
}

/// `clock_ticker_task` will create a background thread that will send notification to a broadcast
/// channel periodically. The output will be a handle to this thread and the receiver of these
/// events.
#[instrument]
pub fn clock_ticker_task(refresh_rate: RefreshRate) -> (JoinHandle<()>, Receiver<Event>) {
    let (sender, receiver) = broadcast::channel(10);

    let handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(refresh_rate.value()).await;

            let event = Event::Clock(EventUuid(Uuid::new_v4().to_string()));
            match sender.send(event.clone()) {
                Ok(_) => {
                    debug!("Successfully broadcast clock ticker event: event={event:?}");
                }
                Err(error) => {
                    error!(
                        "Failed to broadcast clock ticker event: event={event:?} : error={error:?}"
                    );
                }
            }
        }
    });

    (handle, receiver)
}

/// `file_inspector_task` will create a background thread that will send a notification when the given file
/// has changed to a broadcast channel periodically. The output will be a handle to this thread and the
/// receiver of these events.
///
/// The mechanism for detecting change within the file is a standard `SHA-256` digest.
#[instrument]
pub fn file_inspector_task(
    refresh_rate: RefreshRate,
    path: String,
) -> (JoinHandle<()>, Receiver<Event>) {
    /// The `FileChangeInspector` tells the authority when policies on disk have changed.
    #[derive(Debug)]
    struct FileChangeInspector {
        /// The path to the file that is being monitored
        file_path: String,
        /// Defines the sha 256 of the file.
        hash: Option<String>,
    }

    impl FileChangeInspector {
        /// Creates a new instance of the `FileChangeInspector`
        pub fn new(file_path: String) -> Self {
            Self {
                // This is the path to the file to monitor for changes.
                file_path,
                hash: None,
            }
        }

        /// `changed` returns true if the file has changed.
        /// It will return true on the first call after creating a `io::Error` instance.
        #[instrument(skip(self), ret, err)]
        pub fn changed(&mut self) -> Result<bool, io::Error> {
            let mut file_data = String::new();

            {
                let mut file = File::open(self.file_path.clone())?;
                file.lock_shared()?;
                file.read_to_string(&mut file_data)?;
                file.unlock()?;
            }

            let calculated_hash = sha256::digest(file_data);
            if Some(calculated_hash.clone()) == self.hash {
                debug!("Authorization data file has not changed");
                return Ok(false);
            }

            self.hash = Some(calculated_hash);
            debug!("Authorization data file has changed: hash={:?}", self.hash);
            Ok(true)
        }
    }
    let (sender, receiver) = broadcast::channel(10);
    let mut inspector = FileChangeInspector::new(path.clone());
    let handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(refresh_rate.value()).await;

            match inspector.changed() {
                Ok(true) => {
                    let event = Event::File(EventUuid(Uuid::new_v4().to_string()), path.clone());

                    match sender.send(event.clone()) {
                        Ok(_) => {
                            debug!("Successfully notificated authorization data file has changed: event={event:?}");
                        }
                        Err(error) => {
                            error!(
                                "Failed to notificate authorization data file has changed: event={event:?}: error={error:?}"
                            );
                        }
                    }
                }
                Err(e) => {
                    error!("Error using file: {e}");
                    return;
                }
                _ => {}
            }
        }
    });

    (handle, receiver)
}

#[cfg(test)]
mod test {
    use std::time::Duration;
    use tempfile::NamedTempFile;

    use crate::public::events::core::{clock_ticker_task, file_inspector_task, Event, RefreshRate};

    #[tokio::test]
    async fn validate_send_receive() {
        let (handle, mut receiver) =
            clock_ticker_task(RefreshRate::Other(Duration::from_millis(1)));
        assert!(receiver.recv().await.is_ok());
        handle.abort();
    }

    #[tokio::test]
    async fn validate_send_receive_file_inspector() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap().to_string();
        let (_, mut receiver) =
            file_inspector_task(RefreshRate::Other(Duration::from_millis(1)), path.clone());

        match receiver.recv().await.unwrap() {
            Event::File(_, recv_path) => {
                assert_eq!(path, recv_path);
            }
            err => {
                panic!("{err:?}");
            }
        }
    }
}
