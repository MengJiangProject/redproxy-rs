use std::{collections::HashMap, sync::Arc, time::Duration};

use easy_error::Error;
use log::trace;
use serde::{Deserialize, Serialize};
use tokio::{process::Command, sync::Mutex};

//TODO: ratelimit and DDOS protection

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuthData {
    pub required: bool,
    #[serde(default)]
    auth_cmd: Vec<String>,
    #[serde(default)]
    users: Vec<UserEntry>,
    #[serde(default)]
    cache: Cache,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserEntry {
    username: String,
    password: String,
}

impl AuthData {
    pub async fn init(&mut self) -> Result<(), Error> {
        self.cache.init().await
    }
    pub async fn auth_cmd(&self, user: &(String, String)) -> bool {
        if self.auth_cmd.is_empty() {
            return false;
        }
        let cmd = self
            .auth_cmd
            .iter()
            .map(|s| s.replace("#USER#", &user.0).replace("#PASS#", &user.1))
            .collect::<Vec<_>>();
        trace!("auth_cmd: {:?}", cmd);
        let mut child = Command::new(&cmd[0]);
        if cmd.len() > 1 {
            child.args(&cmd[1..]);
        }
        let child = child.spawn();
        if let Ok(mut child) = child {
            let status = child.wait().await.unwrap();
            return self.cache.set(user, status.success()).await;
        }

        self.cache.set(user, false).await
    }

    pub async fn check(&self, user: &Option<(String, String)>) -> bool {
        if !self.required {
            true
        } else if let Some(user) = user {
            self.users
                .iter()
                .any(|e| e.username == user.0 && e.password == user.1)
                || self.cache.check(user).await
                || self.auth_cmd(user).await
        } else {
            false
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Cache {
    timeout: u64,
    #[serde(skip)]
    data: Arc<Mutex<HashMap<(String, String), bool>>>,
}

impl Cache {
    pub async fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }
    pub async fn check(&self, user: &(String, String)) -> bool {
        let data = self.data.lock().await;
        if let Some(v) = data.get(user) {
            trace!("cache hit: {} => {}", user.0, v);
            return *v;
        }
        false
    }

    pub async fn set(&self, key: &(String, String), value: bool) -> bool {
        if self.timeout == 0 {
            return value;
        }
        trace!("cache set: {} => {}", key.0, value);
        let key = (key.0.to_string(), key.1.to_string());
        let mut data = self.data.lock().await;
        data.insert(key.clone(), value);
        let data = self.data.clone();
        let timeout = self.timeout;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(timeout)).await;
            let mut data = data.lock().await;
            data.remove(&key);
        });
        value
    }
}
impl Clone for Cache {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            timeout: 300,
            data: Default::default(),
        }
    }
}
