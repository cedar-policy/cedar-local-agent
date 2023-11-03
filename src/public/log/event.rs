//! This module implements an authorization formatter with specific targets.

use tracing_core::{Event, Subscriber};
use tracing_subscriber::fmt::{
    format::{FormatEvent, FormatFields, Writer},
    FmtContext,
};
use tracing_subscriber::registry::LookupSpan;

/// An enum variant for providing the `AuthorizerFormatter`
#[derive(Debug)]
pub enum AuthorizerTarget {
    /// Target for the `simple::Authorizer`
    Simple,
    /// Target for other authorizers not defined in this crate
    Other(String),
}

impl AuthorizerTarget {
    fn as_str(&self) -> &str {
        match self {
            Self::Simple => "cedar::simple::authorizer",
            Self::Other(value) => value,
        }
    }
}

/// A tracing event formatter that formats an event targeting `authorization` to a writer with event fields.
#[derive(Debug)]
pub struct AuthorizerFormatter(pub AuthorizerTarget);

impl<S, N> FormatEvent<S, N> for AuthorizerFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();

        if metadata.target() != self.0.as_str() {
            return Ok(());
        }

        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

#[cfg(test)]
mod test {
    use std::io::{Result, Write};
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use tracing::subscriber::DefaultGuard;
    use tracing::{debug, info, warn};
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;

    use crate::public::log::event::{AuthorizerFormatter, AuthorizerTarget};

    #[derive(Clone)]
    pub struct MockTestWriter {
        inner: Arc<Mutex<Vec<u8>>>,
    }

    impl MockTestWriter {
        pub fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn as_string(&self) -> String {
            let b = self.inner.lock().unwrap();
            String::from_utf8(b.clone()).unwrap()
        }
    }

    impl io::Write for MockTestWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.lock().unwrap().append(&mut Vec::from(buf));

            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for MockTestWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn setup_tracing(writer: MockTestWriter, event_formatter: AuthorizerFormatter) -> DefaultGuard
    where
        MockTestWriter:
            for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + 'static + Send + Sync,
    {
        let layer = tracing_subscriber::fmt::layer()
            .event_format(event_formatter)
            .with_writer(writer);
        tracing::subscriber::set_default(tracing_subscriber::registry().with(layer))
    }

    #[test]
    fn format_event_with_authorization_target() -> Result<()> {
        let ocsf = AuthorizerFormatter(AuthorizerTarget::Other("something".to_string()));
        let writer = MockTestWriter::new();

        let g = setup_tracing(writer.clone(), ocsf);

        debug!(
            target:"something",
            "debug"
        );
        info!(target:"Target", "info");
        warn!("warn");

        let mut expected_writer = Vec::new();
        writeln!(&mut expected_writer, "debug")?;

        assert_eq!(
            String::from_utf8(expected_writer).unwrap(),
            writer.as_string()
        );

        drop(g);
        Ok(())
    }

    #[test]
    fn validate_as_str_authorizer_target() {
        assert_eq!(
            "cedar::simple::authorizer",
            AuthorizerTarget::Simple.as_str()
        );
        assert_eq!(
            "something",
            AuthorizerTarget::Other("something".to_string()).as_str()
        );
    }
}
