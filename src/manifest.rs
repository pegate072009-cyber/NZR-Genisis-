use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};

use crate::{MAX_SUPPLY, NETWORK_NAME, TICKER};

const INVENTORY_FORMAT_VERSION: u32 = 2;
const TEST_NETWORK_NAME: &str = "Nezora Test";
const INVENTORY_ENCRYPTION: &str = "AES-256-GCM";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Manifest {
    pub network: String,
    pub ticker: String,
    pub format_version: u32,
    pub total_coin_records: u64,
    pub inventory_domain_supply: u64,
    pub inventory_seed: String,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FileEntry {
    pub file: String,
    pub first_slot: u64,
    pub last_slot: u64,
    pub coin_records: u32,
    pub encrypted_sha256: String,
    pub encryption: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestWire {
    network: String,
    ticker: String,
    format_version: u32,
    total_coin_records: u64,
    inventory_domain_supply: u64,
    inventory_seed: String,
    files: Vec<FileEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEntryWire {
    file: String,
    first_slot: u64,
    last_slot: u64,
    coin_records: u32,
    encrypted_sha256: String,
    encryption: String,
}

impl<'de> Deserialize<'de> for FileEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FileEntryWire::deserialize(deserializer)?;
        ensure_lower_hex::<D::Error>(&wire.encrypted_sha256, 64, "encrypted_sha256")?;
        if wire.coin_records == 0 {
            return Err(D::Error::custom("coin_records must be positive"));
        }
        if wire.last_slot < wire.first_slot {
            return Err(D::Error::custom("last_slot must not precede first_slot"));
        }
        let range_count = wire.last_slot.checked_sub(wire.first_slot)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| D::Error::custom("file slot range overflows"))?;
        if range_count != u64::from(wire.coin_records) {
            return Err(D::Error::custom("coin_records does not match slot range"));
        }
        if wire.encryption != INVENTORY_ENCRYPTION {
            return Err(D::Error::custom("unsupported inventory encryption"));
        }
        Ok(Self {
            file: wire.file,
            first_slot: wire.first_slot,
            last_slot: wire.last_slot,
            coin_records: wire.coin_records,
            encrypted_sha256: wire.encrypted_sha256,
            encryption: wire.encryption,
        })
    }
}

impl<'de> Deserialize<'de> for Manifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ManifestWire::deserialize(deserializer)?;
        if wire.format_version != INVENTORY_FORMAT_VERSION {
            return Err(D::Error::custom("unsupported inventory format version"));
        }
        if wire.ticker != TICKER {
            return Err(D::Error::custom("wrong ticker"));
        }
        if wire.inventory_domain_supply == 0 || wire.inventory_domain_supply > MAX_SUPPLY {
            return Err(D::Error::custom("inventory domain is outside allowed supply bounds"));
        }
        if wire.total_coin_records != wire.inventory_domain_supply {
            return Err(D::Error::custom("manifest total and inventory domain mismatch"));
        }
        match wire.network.as_str() {
            TEST_NETWORK_NAME => {}
            NETWORK_NAME if wire.inventory_domain_supply == MAX_SUPPLY => {}
            NETWORK_NAME => return Err(D::Error::custom(
                "production inventory must cover the full maximum supply",
            )),
            _ => return Err(D::Error::custom("unrecognized Nezora network in manifest")),
        }
        ensure_lower_hex::<D::Error>(&wire.inventory_seed, 64, "inventory_seed")?;
        if wire.files.is_empty() {
            return Err(D::Error::custom("manifest contains no inventory files"));
        }

        let mut expected_first_slot = 0u64;
        for (index, entry) in wire.files.iter().enumerate() {
            let expected_name = format!("block.{:02}.enc", index + 1);
            if entry.file != expected_name {
                return Err(D::Error::custom(format!(
                    "unexpected inventory filename: {}", entry.file
                )));
            }
            if entry.first_slot != expected_first_slot {
                return Err(D::Error::custom(
                    "inventory slot ranges must be contiguous and start at zero",
                ));
            }
            if entry.last_slot >= wire.inventory_domain_supply {
                return Err(D::Error::custom("inventory slot range exceeds declared domain"));
            }
            expected_first_slot = entry.last_slot.checked_add(1)
                .ok_or_else(|| D::Error::custom("inventory slot range overflows"))?;
        }
        if expected_first_slot != wire.inventory_domain_supply {
            return Err(D::Error::custom(
                "manifest files do not cover the full inventory domain",
            ));
        }

        Ok(Self {
            network: wire.network,
            ticker: wire.ticker,
            format_version: wire.format_version,
            total_coin_records: wire.total_coin_records,
            inventory_domain_supply: wire.inventory_domain_supply,
            inventory_seed: wire.inventory_seed,
            files: wire.files,
        })
    }
}

fn ensure_lower_hex<E: DeError>(value: &str, expected_len: usize, field: &str) -> Result<(), E> {
    if value.len() != expected_len
        || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(E::custom(format!(
            "{field} must be {expected_len} lowercase hexadecimal characters"
        )));
    }
    Ok(())
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
        assert_eq!(manifest.network, TEST_NETWORK_NAME);
        assert_eq!(manifest.ticker, TICKER);
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
    fn rejects_malformed_seed_and_checksum() {
        let bad_seed = valid_manifest_json().replace(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "GG00000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(serde_json::from_str::<Manifest>(&bad_seed).is_err());

        let bad_checksum = valid_manifest_json().replace(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(serde_json::from_str::<Manifest>(&bad_checksum).is_err());
    }

    #[test]
    fn rejects_invalid_slot_ranges_and_record_counts() {
        let bad_count = valid_manifest_json().replace(
            r#""coin_records": 2"#, r#""coin_records": 1"#
        );
        assert!(serde_json::from_str::<Manifest>(&bad_count).is_err());

        let out_of_domain = valid_manifest_json().replace(
            r#""last_slot": 1"#, r#""last_slot": 2"#
        );
        assert!(serde_json::from_str::<Manifest>(&out_of_domain).is_err());
    }

    #[test]
    fn rejects_production_manifest_with_test_supply() {
        let production = valid_manifest_json().replace("Nezora Test", "Nezora");
        assert!(serde_json::from_str::<Manifest>(&production).is_err());
    }

    #[test]
    fn serialization_round_trip_preserves_manifest() {
        let manifest: Manifest = serde_json::from_str(valid_manifest_json()).unwrap();
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let decoded: Manifest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, manifest);
    }
}
