//! Integration tests for the DevPanel bridge authentication handshake.
//!
//! These tests spin up a real `BridgeServer` on a temp socket, connect a
//! `BridgeClient`, exercise the `HandshakeMessage` protocol end-to-end,
//! and verify that both the happy path and all rejection paths behave
//! correctly across a real Unix socket (no mocking).
//!
//! Run with:
//!   cargo test -p diatom_bridge --test integration_handshake

use diatom_bridge::protocol::{
    BrowserMessage, DevPanelMessage, HandshakeMessage, generate_auth_token,
};
use diatom_bridge::{BridgeClient, BridgeServer};
use std::time::Duration;
use tokio::time::timeout;

/// Helper: unique temp socket path per test to avoid collision
fn tmp_sock(label: &str) -> String {
    format!("/tmp/diatom-test-{label}-{}.sock", std::process::id())
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn handshake_accepted_on_correct_token() {
    let token = generate_auth_token();
    let path = tmp_sock("accept");

    let server = BridgeServer::start(&path, token.clone())
        .await
        .expect("server bind");

    let client = timeout(
        Duration::from_secs(5),
        BridgeClient::connect(&path, &token, 10),
    )
    .await
    .expect("connect timeout")
    .expect("connect error");

    // Both sides should now be alive — send a message to confirm
    client
        .send(BrowserMessage::Shutdown)
        .await
        .expect("send Shutdown");

    drop(server);
    drop(client);
    let _ = std::fs::remove_file(&path);
}

// ── Wrong token ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn handshake_rejected_on_wrong_token() {
    let server_token = generate_auth_token();
    let wrong_token = generate_auth_token(); // different token
    assert_ne!(server_token, wrong_token);

    let path = tmp_sock("reject");

    let _server = BridgeServer::start(&path, server_token)
        .await
        .expect("server bind");

    let result = timeout(
        Duration::from_secs(5),
        BridgeClient::connect(&path, &wrong_token, 3),
    )
    .await
    .expect("timeout");

    assert!(
        result.is_err(),
        "connection with wrong token should be rejected, got Ok"
    );
    let _ = std::fs::remove_file(&path);
}

// ── Empty token ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn handshake_rejected_on_empty_token() {
    let token = generate_auth_token();
    let path = tmp_sock("empty");

    let _server = BridgeServer::start(&path, token)
        .await
        .expect("server bind");

    let result = timeout(Duration::from_secs(5), BridgeClient::connect(&path, "", 3))
        .await
        .expect("timeout");

    assert!(result.is_err(), "empty token should be rejected");
    let _ = std::fs::remove_file(&path);
}

// ── Token uniqueness ──────────────────────────────────────────────────────────

#[tokio::test]
async fn generated_tokens_are_unique() {
    let tokens: Vec<String> = (0..100).map(|_| generate_auth_token()).collect();
    let unique: std::collections::HashSet<&str> = tokens.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        tokens.len(),
        unique.len(),
        "all 100 generated tokens must be unique"
    );
}

#[tokio::test]
async fn generated_tokens_are_64_hex_chars() {
    for _ in 0..20 {
        let tok = generate_auth_token();
        assert_eq!(tok.len(), 64, "token must be 64 hex chars");
        assert!(
            tok.chars().all(|c| c.is_ascii_hexdigit()),
            "token must be lowercase hex"
        );
    }
}

// ── Message round-trip post-handshake ─────────────────────────────────────────

#[tokio::test]
async fn messages_flow_after_successful_handshake() {
    let token = generate_auth_token();
    let path = tmp_sock("flow");

    let mut server = BridgeServer::start(&path, token.clone())
        .await
        .expect("server bind");

    let client = timeout(
        Duration::from_secs(5),
        BridgeClient::connect(&path, &token, 10),
    )
    .await
    .expect("timeout")
    .expect("connect");

    // Client sends DevPanelMessage::Ready (via the inbound channel on server)
    // We simulate: server sends BrowserMessage::Shutdown; client receives it
    server
        .outbound
        .send(DevPanelMessage::Ready)
        .await
        .expect("server send");

    let msg = timeout(Duration::from_secs(2), client.inbound.recv())
        .await
        .expect("recv timeout");

    // The client inbound receives DevPanelMessages sent by the server outbound
    assert!(
        matches!(msg, Some(DevPanelMessage::Ready)),
        "expected Ready, got {msg:?}"
    );

    let _ = std::fs::remove_file(&path);
}
