use serde::{Deserialize, Serialize};

pub const BITSTRING_STATUS_LIST_ENTRY_TYPE: &str = "BitstringStatusListEntry";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusListEntry {
    pub id: String,

    #[serde(rename = "type")]
    pub status_type: String,

    pub status_purpose: String,

    pub status_list_index: String,

    pub status_list_credential: String,
}

impl StatusListEntry {
    pub fn bitstring(
        id: impl Into<String>,
        purpose: impl Into<String>,
        index: impl Into<String>,
        list_url: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status_type: BITSTRING_STATUS_LIST_ENTRY_TYPE.to_owned(),
            status_purpose: purpose.into(),
            status_list_index: index.into(),
            status_list_credential: list_url.into(),
        }
    }
}
