use serde::{Deserialize, Serialize};

/// Signed inventory manifest.
///
/// Unknown fields are rejected deliberately: a signed manifest must have one
/// unambiguous schema rather than silently ignoring fields it does not know.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub network: String,
    pub ticker: String,
    pub format_version: u32,
    pub total_coin_records: u64,
    pub inventory_domain_supply: u64,
    pub inventory_seed: String,
    pub files: Vec<FileEntry>,
}

/// One encrypted inventory file declared by the signed manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub file: String,
    pub first_slot: u64,
    pub last_slot: u64,
    pub coin_records: u32,
    pub encrypted_sha256: String,
    pub encryption: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest_json() -> &'static str {
        r#"{
            "network": "Nezora Test",
            "ticker": "NZR",
            "format_version": 2,
            "total_coin_records": 2,
            "inventory_domain_supply": 2,
            "inventory_seed": "0000000000000000000000000000000000000000000000000000000000000000",
            "files": [{
                "file": "block.01.enc",
                "first_slot": 0,
                "last_slot": 1,
                "coin_records": 2,
                "encrypted_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "encryption": "AES-256-GCM"
            }]
        }"#
    }

    #[test]
    fn accepts_manifest_with_exact_known_schema() {
        let manifest: Manifest = serde_json::from_str(valid_manifest_json()).unwrap();
        assert_eq!(manifest.network, "Nezora Test");
        assert_eq!(manifest.ticker, "NZR");
        assert_eq!(manifest.files.len(), 1);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let json = valid_manifest_json().replace(
            r#""ticker": "NZR","#,
            r#""ticker": "NZR", "unexpected": true,"#,
        );

        assert!(serde_json::from_str::<Manifest>(&json).is_err());
    }

    #[test]
    fn rejects_unknown_inventory_file_field() {
        let json = valid_manifest_json().replace(
            r#""coin_records": 2,"#,
            r#""coin_records": 2, "unexpected": "value","#,
        );

        assert!(serde_json::from_str::<Manifest>(&json).is_err());
    }

    #[test]
    fn serialization_round_trip_preserves_manifest() {
        let manifest: Manifest = serde_json::from_str(valid_manifest_json()).unwrap();
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let decoded: Manifest = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded, manifest);
    }
}
