use lazy_static::lazy_static;
use serde::Serialize;

use crate::config;

const SLACK_HOOK_URL: &str = "https://hooks.slack.com/services";

lazy_static! {
    pub static ref INSTANCE: Client = Client::new(config::INSTANCE.slack_token.clone());
}

#[derive(Serialize)]
struct Request {
    text: String,
}

pub struct Client {
    http_client: reqwest::Client,
    token: String,
}

impl Client {
    pub fn new(token: String) -> Self {
        Client {
            http_client: reqwest::Client::new(),
            token,
        }
    }

    pub async fn send(&self, text: String) -> anyhow::Result<()> {
        let webhook_url = format!("{}/{}", SLACK_HOOK_URL, self.token);

        let payload = serde_json::json!(Request { text });

        let res = self.http_client.post(webhook_url).json(&payload).send().await?;

        if res.status().is_success() {
            return Ok(());
        } else {
            let err_msg = res.text().await?;
            return Err(anyhow::anyhow!("Slack send fail, err: {}", err_msg));
        }
    }
}
