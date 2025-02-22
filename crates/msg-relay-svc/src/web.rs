// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocketUpgrade},
        State,
    },
    response::Response,
};

use crate::Inner;

pub async fn handler(
    State(state): State<Arc<Inner>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(|mut socket| async move {
        let mut conn = state.relay.connect();

        loop {
            tokio::select! {
                Some(msg) = conn.recv() => {
                    if socket.send(Message::Binary(msg)).await.is_err() {
                        break;
                    }
                }

                msg = socket.recv() => {
                    match msg {
                        None => break,

                        Some(Ok(Message::Binary(msg))) => {
                            conn.send_message(msg);
                        }

                        Some(Ok(Message::Ping(_msg))) => {
                            tracing::debug!("recv ping msg");
                        }

                        Some(Ok(Message::Close(_))) => {
                            tracing::debug!("recv close from the client");
                            break;
                        }

                        Some(Err(err)) => {
                            tracing::error!("recv error {err}");
                            break;
                        }

                        _ => {}
                    }
                }
            }
        }

        tracing::info!("close ws connection");
    })
}

pub async fn stats(State(state): State<Arc<Inner>>) -> String {
    let (size, count) = state.relay.stats();

    format!(r#"{{totalSize: {}, totalCount: {}}}"#, size, count)
}
