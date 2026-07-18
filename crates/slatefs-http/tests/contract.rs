use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};
use slatefs_http::dto::{CapabilitiesResponse, EntryListResponse, VolumeListResponse};
use slatefs_http::errors::ErrorEnvelope;
use slatefs_http::routes::ROUTES;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn shared_wire_fixture_round_trips() {
    let path = repository_root().join("docs/api/fixtures/consumer-v1.json");
    let source = fs::read_to_string(path).expect("shared fixture must be readable");
    let fixture: Value = serde_json::from_str(&source).expect("shared fixture must be valid JSON");

    for key in ["capabilities", "volumes", "entries", "error"] {
        assert!(fixture.get(key).is_some(), "fixture is missing {key}");
    }

    let capabilities: CapabilitiesResponse =
        serde_json::from_value(fixture["capabilities"].clone()).unwrap();
    let volumes: VolumeListResponse = serde_json::from_value(fixture["volumes"].clone()).unwrap();
    let entries: EntryListResponse = serde_json::from_value(fixture["entries"].clone()).unwrap();
    let error: ErrorEnvelope = serde_json::from_value(fixture["error"].clone()).unwrap();

    assert_eq!(
        serde_json::to_value(capabilities).unwrap(),
        fixture["capabilities"]
    );
    assert_eq!(serde_json::to_value(volumes).unwrap(), fixture["volumes"]);
    assert_eq!(serde_json::to_value(entries).unwrap(), fixture["entries"]);
    assert_eq!(serde_json::to_value(error).unwrap(), fixture["error"]);
}

#[test]
fn route_surface_matches_approval_snapshot() {
    let actual = ROUTES
        .iter()
        .map(|route| format!("{} {} {}", route.method, route.path, route.operation_id))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let approved = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/consumer-v1.routes.txt"),
    )
    .unwrap();
    assert_eq!(actual, approved, "review and approve public route changes");
}

#[test]
fn openapi_document_matches_approval_digest() {
    let root = repository_root();
    let source = fs::read(root.join("docs/api/consumer-v1.openapi.yaml")).unwrap();
    let actual = format!("{:x}\n", Sha256::digest(source));
    let approved = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/snapshots/consumer-v1.openapi.sha256"),
    )
    .unwrap();
    assert_eq!(actual, approved, "review and approve OpenAPI changes");
}
