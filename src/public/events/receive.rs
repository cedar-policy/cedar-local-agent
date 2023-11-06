//! Contains the core functionality to update the authorization data based on an event from a
//! receiver.
use std::sync::Arc;

use tokio::sync::broadcast::Receiver;
use tokio::task::JoinHandle;
use tracing::{debug, error, instrument};

use crate::public::events::core::Event;
use crate::public::UpdateProviderData;

/// The `update_provider_data_thread` is a function that starts a background thread given a `Receiver`
/// to handle `Event`s that will refresh the data within a provider.
#[instrument(skip_all)]
pub fn update_provider_data_task<T>(
    provider: Arc<T>,
    mut update_authority_events: Receiver<Event>,
) -> JoinHandle<()>
where
    T: UpdateProviderData + Send + Sync + 'static,
{
    tokio::spawn(async move {
        loop {
            if let Ok(event) = update_authority_events.recv().await {
                match provider.update_provider_data().await {
                    Ok(_) => {
                        debug!(
                            "Successfully handled event for updating provider data: event={event:?}"
                        );
                    }
                    Err(error) => {
                        error!("Failed to handle event for updating provider data: event={event:?}: error={error:?}");
                    }
                }
            } else {
                error!("Failed to receive the new event.");
            }
        }
    })
}

#[cfg(test)]
mod test {
    use std::fmt::Error;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::sync::{broadcast, RwLock};

    use crate::public::events::core::{Event, EventUuid};
    use crate::public::events::receive::update_provider_data_task;
    use crate::public::{UpdateProviderData, UpdateProviderDataError};

    #[derive(Default, Debug)]
    pub struct MockProvider {
        counter: RwLock<u32>,
    }

    #[async_trait]
    impl UpdateProviderData for MockProvider {
        async fn update_provider_data(&self) -> Result<(), UpdateProviderDataError> {
            if *self.counter.read().await == 10 {
                return Ok(());
            }

            {
                let mut lock = self.counter.write().await;
                *lock += 1;
            }

            Ok(())
        }
    }

    #[tokio::test]
    async fn update() {
        let (sender, receiver) = broadcast::channel(10);
        let authority = Arc::new(MockProvider::default());
        let update_thread = update_provider_data_task(authority.clone(), receiver);
        for i in 0..10 {
            assert!(sender.send(Event::Clock(EventUuid(i.to_string()))).is_ok());
        }

        loop {
            let value = { *authority.counter.read().await };
            if value == 10 {
                update_thread.abort();
                break;
            }
        }
    }

    #[derive(Default, Debug)]
    pub struct MockError {
        error_counter: Arc<RwLock<u32>>,
    }

    #[async_trait]
    impl UpdateProviderData for MockError {
        async fn update_provider_data(&self) -> Result<(), UpdateProviderDataError> {
            if *self.error_counter.read().await == 10 {
                return Ok(());
            }

            {
                let mut lock = self.error_counter.write().await;
                *lock += 1;
            }

            Err(UpdateProviderDataError::General(Box::<Error>::default()))
        }
    }

    #[tokio::test]
    async fn update_fails() {
        let (sender, receiver) = broadcast::channel(10);
        let authority = Arc::new(MockError::default());
        let update_thread = update_provider_data_task(authority.clone(), receiver);
        for i in 0..10 {
            assert!(sender.send(Event::Clock(EventUuid(i.to_string()))).is_ok());
        }

        loop {
            let value = { *authority.error_counter.read().await };
            if value == 10 {
                update_thread.abort();
                break;
            }
        }
    }
}
