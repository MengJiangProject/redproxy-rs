use async_trait::async_trait;
use easy_error::{Error, err_msg};
use quinn::ConnectError as QuinnConnectError;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::io::Result as IoResult;

// Assuming QuicEndpointConnector trait is in super (connectors/quic.rs)
use super::quic::QuicEndpointConnector;
// Assuming MockQuicConnection is accessible from common tests or a common mocks module
// and that it implements QuicConnectionLike and is Clone.
use crate::common::quic::tests::MockQuicConnection;
use crate::common::quic::QuicConnectionLike;


#[derive(Default)]
pub struct MockQuicEndpointConnector {
    connect_responses: Mutex<VecDeque<Result<MockQuicConnection, QuinnConnectError>>>,
    local_addr_val: Mutex<SocketAddr>,
}

impl MockQuicEndpointConnector {
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            connect_responses: Mutex::new(VecDeque::new()),
            local_addr_val: Mutex::new(local_addr),
        }
    }

    #[allow(dead_code)]
    pub fn add_connect_response(&self, response: Result<MockQuicConnection, QuinnConnectError>) {
        self.connect_responses.lock().unwrap().push_back(response);
    }

    #[allow(dead_code)]
    pub fn set_local_addr(&self, addr: SocketAddr) {
        *self.local_addr_val.lock().unwrap() = addr;
    }
}

#[async_trait]
impl QuicEndpointConnector for MockQuicEndpointConnector {
    type Connection = MockQuicConnection; // This must match the type returned by connect

    async fn connect(&self, _remote: SocketAddr, _server_name: &str) -> Result<Self::Connection, QuinnConnectError> {
        if let Some(response) = self.connect_responses.lock().unwrap().pop_front() {
            response
        } else {
            // Default behavior if no response is queued: return a generic error or a default MockQuicConnection
            // For simplicity, let's return an error indicating no mock response was set up.
            Err(QuinnConnectError::Timeout) // Or a custom error indicating mock setup issue
        }
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(*self.local_addr_val.lock().unwrap())
    }
}
