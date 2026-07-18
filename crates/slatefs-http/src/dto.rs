//! Stable v1 JSON wire types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    Live,
    Snapshot,
    Version,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ViewSelection {
    pub kind: ViewKind,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_commit: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityLimits {
    pub max_page_size: u32,
    pub max_range_bytes: u64,
    pub max_recursive_entries: u64,
    pub max_recursive_bytes: u64,
    pub max_text_edit_bytes: u64,
    pub max_diff_bytes: u64,
    pub max_diff_lines: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityFeatures {
    pub historical_snapshots: bool,
    pub historical_versions: bool,
    pub hardlinks: bool,
    pub symlinks: bool,
    pub xattrs: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilitiesResponse {
    pub api_version: String,
    pub limits: CapabilityLimits,
    pub features: CapabilityFeatures,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeKind {
    Filesystem,
    Block,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuotaUsage {
    pub used_bytes: u64,
    pub limit_bytes: Option<u64>,
    pub used_inodes: u64,
    pub limit_inodes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VolumeSummary {
    pub name: String,
    pub kind: VolumeKind,
    pub browsable: bool,
    pub readonly: bool,
    pub quota: QuotaUsage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VolumeListResponse {
    pub volumes: Vec<VolumeSummary>,
    pub next_page_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VolumeDetail {
    #[serde(flatten)]
    pub volume: VolumeSummary,
    pub allocated_bytes: u64,
    pub available_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Special,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryCapabilities {
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
    pub can_rename: bool,
}

/// An entry name always includes `name_bytes_base64`; `name` is present only
/// when the exact bytes are valid UTF-8.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub entry_id: String,
    pub parent_entry_id: Option<String>,
    pub path: Option<String>,
    pub name: Option<String>,
    pub name_bytes_base64: String,
    pub kind: EntryKind,
    pub inode: u64,
    pub inode_decimal: String,
    pub generation: u64,
    pub generation_decimal: String,
    pub size: u64,
    pub size_decimal: String,
    pub allocated_bytes: u64,
    pub allocated_bytes_decimal: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub link_count: u64,
    pub link_count_decimal: String,
    pub created_at: String,
    pub modified_at: String,
    pub changed_at: String,
    pub accessed_at: String,
    pub readonly: bool,
    #[serde(flatten)]
    pub capabilities: EntryCapabilities,
    pub etag: String,
    pub symlink_target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryListResponse {
    pub view: ViewSelection,
    pub entry: Entry,
    pub entries: Vec<Entry>,
    pub next_page_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreateKind {
    File,
    Directory,
    Symlink,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateEntryRequest {
    pub parent_entry_id: String,
    pub name: String,
    pub kind: CreateKind,
    pub mode: Option<u32>,
    pub symlink_target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateEntryRequest {
    pub entry_id: String,
    pub destination_parent_entry_id: Option<String>,
    pub name: Option<String>,
    pub mode: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Copy,
    Move,
    Hardlink,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    Fail,
    Overwrite,
    KeepBoth,
    Skip,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationRequest {
    pub operation: OperationKind,
    pub source_entry_ids: Vec<String>,
    pub destination_parent_entry_id: String,
    pub conflict_policy: ConflictPolicy,
    pub preview: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationResult {
    pub operation_id: String,
    pub preview: bool,
    pub total_entries: u64,
    pub total_bytes: u64,
    pub completed_entries: u64,
    pub failed_entries: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct XattrValue {
    pub name: Option<String>,
    pub name_bytes_base64: String,
    pub value_base64: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct XattrListResponse {
    pub entry_id: String,
    pub xattrs: Vec<XattrValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view: Option<ViewSelection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateXattrsRequest {
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
    /// Lossless selectors for xattr names that are not valid UTF-8. Each set
    /// item carries base64-encoded name bytes and value bytes.
    #[serde(default)]
    pub set_bytes: Vec<SetXattrBytes>,
    #[serde(default)]
    pub remove_bytes_base64: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SetXattrBytes {
    pub name_bytes_base64: String,
    pub value_base64: String,
}
