//! Non-operational TCP protocol consistency tests for Nezora's existing pool API.
//! These tests validate JSON envelopes only; they do not connect to a pool,
//! submit shares, authenticate workers, or perform mining.

use nezora_supply::blockchain::pool_network::{PoolTcpRequest, PoolTcpResponse};

#[test]
fn ping_request_round_trips_as_expected_json() {
    let request = PoolTcpRequest::Ping;
    let encoded = serde_json::to_string(&request).expect("serialize Ping");
    assert_eq!(encoded, r#"{"type":"ping"}"#);
    let decoded: PoolTcpRequest = serde_json::from_str(&encoded).expect("deserialize Ping");
    assert_eq!(decoded, request);
}


#[test]
fn request_enum_rejects_unknown_fields() {
    let malformed = r#"{"type":"ping","extra":true}"#;
    assert!(serde_json::from_str::<PoolTcpRequest>(malformed).is_err());
}


#[test]
fn request_enum_rejects_unknown_variant() {
    let malformed = r#"{"type":"unsupported_request"}"#;
    assert!(serde_json::from_str::<PoolTcpRequest>(malformed).is_err());
}


#[test]
fn response_error_round_trips() {
    let response = PoolTcpResponse::Error {
        message: "mock protocol test error".to_owned(),
    };
    let encoded = serde_json::to_string(&response).expect("serialize Error response");
    let decoded: PoolTcpResponse = serde_json::from_str(&encoded).expect("deserialize Error response");
    assert_eq!(decoded, response);
}


#[test]
fn response_enum_rejects_unknown_fields() {
    let malformed = r#"{"type":"error","message":"mock","extra":1}"#;
    assert!(serde_json::from_str::<PoolTcpResponse>(malformed).is_err());
}
