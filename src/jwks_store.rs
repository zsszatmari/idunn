use std::collections::HashMap;

use arc_swap::ArcSwap;
use jsonwebtoken::DecodingKey;
use std::sync::Arc;

use crate::transport::HttpTransport;

struct JwksStore<T: HttpTransport> {
    key_set: ArcSwap<HashMap<String, DecodingKey>>,
    transport: T,
    network_request_mutex: async_lock::Mutex<()>,
}

impl<T: HttpTransport> JwksStore<T> {
    pub fn new(transport: T) -> Self {
        Self {
            key_set: ArcSwap::new(Arc::new(HashMap::new())),
            transport,
            network_request_mutex: async_lock::Mutex::new(()),
        }
    }
}

// TODO: timeout for request!!
