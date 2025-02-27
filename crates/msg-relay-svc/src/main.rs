// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    env, future::IntoFuture, net::ToSocketAddrs, pin::pin, str::FromStr,
    sync::Arc, time::Duration,
};

use anyhow::bail;
use dotenvy::dotenv;

use tokio::signal::unix::{signal, SignalKind};
use tokio::{sync::broadcast, task::JoinSet, time::sleep};

use axum::{routing::get, Router};
use url::Url;

use futures_util::{stream::StreamExt, SinkExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use msg_relay::MsgRelay;
use msg_relay_client::Endpoint;

mod flags;
mod web;
use flags::MsgRelaySvc;

struct Inner {
    pub(crate) relay: MsgRelay,
}

async fn run_peer(
    endpoint: Endpoint,
    mut queue: broadcast::Receiver<Vec<u8>>,
    relay: MsgRelay,
) {
    let reconnect_delay = u64::from_str(
        &env::var("PEER_RECONNECT_DELAY_SECS").unwrap_or_default(),
    )
    .unwrap_or(3);

    let ping_interval = u64::from_str(
        &env::var("PEER_PING_INTERVAL_SECS").unwrap_or_default(),
    )
    .unwrap_or(5);

    let uri = endpoint.uri();

    loop {
        let mut ws = loop {
            tracing::info!("connecting to {}", uri);

            match connect_async(&endpoint).await {
                Ok((ws, _)) => {
                    tracing::info!("connected to {}", uri);
                    break ws;
                }

                Err(err) => {
                    tracing::error!("connection error {:?}, retrying", err);
                    sleep(Duration::new(reconnect_delay, 0)).await;
                }
            }
        };

        let signal = shutdown();
        let mut signal = pin!(signal);

        loop {
            tokio::select! {
                // we must handle signal, otherwise with_graceful_shutdown()
                // won't allow the service process to finish.
                _ = signal.as_mut() => {
                    tracing::info!("got exit signal, close peer connection");
                    let _ = ws.close(None).await;
                    break;
                }

                // receive an ASK message and proparate it to the peer
                msg = queue.recv() => {
                    if let Ok(msg) = msg {
                        if ws.send(Message::Binary(msg)).await.is_err() {
                            break;
                        }
                    }
                },

                msg = ws.next() => {
                    match msg {
                        None => break,
                        Some(Err(err)) => {
                            tracing::error!("peer recv error {err}");
                            break;
                        },

                        // the peer sent us an ASKed message.
                        Some(Ok(Message::Binary(msg))) => {
                            // make sure this is not an ASK message.
                            if msg.len() > msg_relay::MESSAGE_HEADER_SIZE {
                                relay.handle_message(msg, None);
                            }
                        },

                        Some(Ok(Message::Pong(_))) => {
                            tracing::debug!("recv pong message");
                        },

                        Some(Ok(Message::Ping(_))) => {
                            tracing::debug!("recv ping message");
                        },

                        Some(Ok(Message::Close(_))) => {
                            break;
                        },

                        _ => {}
                    }
                }

                _ = sleep(Duration::new(ping_interval, 0)) => {
                    tracing::debug!("send ping message");
                    if ws.send(Message::Ping(vec![])).await.is_err() {
                        break;
                    }
                }
            };
        }

        tracing::info!("close connection to {}", uri);
    }
}

async fn health_check() -> &'static str {
    "ok"
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    // try to load .env and do not complain if one is not found.
    let _ = dotenv();

    let flags = MsgRelaySvc::from_env_or_exit();

    tracing_subscriber::fmt::init();

    let mut servers = JoinSet::new();

    let peer_queue_size = usize::from_str(
        &env::var("PEER_QUEUE_SIZE").unwrap_or_else(|_| "256".to_string()),
    )
    .map_err(|_| anyhow::Error::msg("can't parse PEER_QUEUE_SIZE"))?;

    let peers: Vec<Url> = flags
        .peer
        .into_iter()
        .chain(
            env::var("PEER")
                .unwrap_or_default()
                .split(' ')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(Url::parse)
                .collect::<Result<Vec<Url>, _>>()?,
        )
        .collect();

    let state = {
        let (queue, _) = broadcast::channel(peer_queue_size);

        // An instance of the MsgRelay that will post all ASK messages
        // to QUEUE if there is at least one connected peer.
        let relay = MsgRelay::new(Some(Box::new({
            let queue = queue.clone();
            move |ask| {
                if queue.receiver_count() > 0 {
                    let _ = queue.send(ask.to_vec());
                }
            }
        })));

        for peer in peers {
            let endpoint = Endpoint::new(&peer)
                .protocols(env::var("PEER_SUBPROTOS").ok().as_deref())
                .token(env::var("PEER_ACCESS_TOKEN").ok().as_deref());

            if endpoint.is_err() {
                bail!("invalid peer endpoint: {}", peer);
            }

            tokio::spawn(run_peer(
                endpoint,
                queue.subscribe(),
                relay.clone(),
            ));
        }

        Arc::new(Inner { relay })
    };

    let app = Router::new()
        .route("/", get(health_check))
        .route("/v1/msg-relay", get(web::handler))
        .route("/v1/msg-stats", get(web::stats))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    for addrs in env::var("LISTEN")
        .ok()
        .unwrap_or_else(|| String::from("localhost:8080"))
        .split(' ')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .chain(flags.listen.iter().map(|s| s.as_str()))
    {
        for addr in addrs.to_socket_addrs()? {
            let listener = tokio::net::TcpListener::bind(addr).await?;

            tracing::info!("listening on {}", listener.local_addr()?);

            servers.spawn(
                axum::serve(listener, app.clone().into_make_service())
                    .with_graceful_shutdown(shutdown())
                    .into_future(),
            );
        }
    }

    while servers.join_next().await.is_some() {}

    Ok(())
}

async fn shutdown() {
    let sigint = async {
        signal(SignalKind::interrupt())
            .expect("cant install SIGINT")
            .recv()
            .await;
    };

    let sigterm = async {
        signal(SignalKind::terminate())
            .expect("cant install SIGTERM")
            .recv()
            .await;
    };

    tokio::select! {
        _ = sigint => {},
        _ = sigterm => {},
    };
}
