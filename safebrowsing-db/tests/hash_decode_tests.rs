use prost::bytes::Bytes;
use prost::Message;
use safebrowsing_hash::{HashPrefix, HashPrefixSet};
use safebrowsing_proto::{CompressionType, RawHashes, RiceDeltaEncoding, ThreatEntrySet};

fn decode_hex(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("Failed to decode hex string")
}

#[test]
fn test_rice_hash_decoding_matches_go() {
    // Test vectors from Go implementation (hash_test.go)
    // These were randomly generated using the server-side Rice compression implementation
    let test_vectors = [(
            vec![
                "0802222308a08fcb6d101c18062218dda588628aad88f883e2421a66384d10bce123dd22030202",
                "08011219081512151c9e466c435e51f99f059ff356185c730351d2f2b6"
            ],
            vec![
                "17f15426",
                "1c9e466c435e51f99f059ff356185c730351d2f2b6",
                "47ba02b7",
                "573373a2",
                "a0c7b20d",
                "a19edd3e",
                "d2c60aef",
                "f1fa25a2"
            ]
        ),
        (
            vec![
                "08011212080e120e8f991dc48f98c8647137d508974b",
                "0801121c081812180c698b1fc286b46c5ef5b96640b68a490e5135deebe15d02",
                "08011223081f121f40481597e49bc0768efbb174ca457f1b25eca550b611dd7385b49526b221cc"
            ],
            vec![
                "0c698b1fc286b46c5ef5b96640b68a490e5135deebe15d02",
                "40481597e49bc0768efbb174ca457f1b25eca550b611dd7385b49526b221cc",
                "8f991dc48f98c8647137d508974b"
            ]
        ),
        (
            vec![
                "0801120908051205f22897e85b",
                "08011211080d120da1e5504a06c508adac0441dcf5",
                "08011217081312139ccb416162bf1971b4017f2194026e6c309c91",
                "0801123408181230198dc5cba24feb2a0fba67e49bb747a8e242a62a194f4b1dc9ce9fb201c883313059b3438daeedb25160b0cfb64dbca3",
                "08011220081c121cb9181bc30742d0e5d1fb1bfa8f11603f6c39b2adfc83d0a4061ea490"
            ],
            vec![
                "198dc5cba24feb2a0fba67e49bb747a8e242a62a194f4b1d",
                "9ccb416162bf1971b4017f2194026e6c309c91",
                "a1e5504a06c508adac0441dcf5",
                "b9181bc30742d0e5d1fb1bfa8f11603f6c39b2adfc83d0a4061ea490",
                "c9ce9fb201c883313059b3438daeedb25160b0cfb64dbca3",
                "f22897e85b"
            ]
        )];

    for (i, (inputs, expected_outputs)) in test_vectors.iter().enumerate() {
        let mut all_hashes = HashPrefixSet::new();

        // Process each input (ThreatEntrySet)
        for input_hex in inputs {
            let input_bytes = decode_hex(input_hex);
            let threat_entry_set =
                ThreatEntrySet::decode(&input_bytes[..]).expect("Failed to decode ThreatEntrySet");

            // Process the threat entry set
            process_threat_entry_set(&mut all_hashes, &threat_entry_set)
                .expect("Failed to process threat entry set");
        }

        // Convert to sorted vector
        let mut actual_hashes: Vec<String> = all_hashes
            .to_sorted_vec()
            .into_iter()
            .map(|h| hex::encode(h.as_bytes()))
            .collect();
        actual_hashes.sort();

        // Expected hashes (already sorted in test vectors)
        let mut expected_hashes: Vec<String> =
            expected_outputs.iter().map(|s| s.to_string()).collect();
        expected_hashes.sort();

        assert_eq!(
            actual_hashes, expected_hashes,
            "Test vector {i} failed. Expected: {expected_hashes:?}, Got: {actual_hashes:?}"
        );
    }
}

#[test]
fn test_checksum_computation_matches_go() {
    // Test that our checksum computation matches Go's hashPrefixes.SHA256() method
    let test_cases = vec![
        (
            vec![], // Empty hash list
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            vec!["xxxx", "yyyy", "zzzz"], // Example from Go tests
            "20ffb2c3e9532153b96b956845381adc06095f8342fa2db1aafba6b0e9594d68",
        ),
    ];

    for (hashes, expected_checksum) in test_cases {
        let mut hash_set = HashPrefixSet::new();

        for hash_str in hashes {
            let hash = HashPrefix::new(hash_str.as_bytes().to_vec())
                .expect("Failed to create hash prefix");
            hash_set.insert(hash);
        }

        let computed_checksum = hash_set.compute_checksum();
        let checksum_hex = hex::encode(computed_checksum.as_bytes());

        assert_eq!(
            checksum_hex, expected_checksum,
            "Checksum mismatch for hashes. Expected: {expected_checksum}, Got: {checksum_hex}"
        );
    }
}

#[test]
fn test_specific_checksum_fix() {
    // Test case that demonstrates the fix for the specific checksum mismatch
    // This uses a simple rice-encoded hash to verify little-endian conversion

    // Create a RiceDeltaEncoding with known values
    let rice_encoding = RiceDeltaEncoding {
        rice_parameter: 2,
        first_value: 0x12345678, // This will be converted differently in LE vs BE
        num_entries: 1,
        encoded_data: Bytes::from(vec![0x00]), // Simple encoding for delta=0
    };

    let mut hash_set = HashPrefixSet::new();
    process_rice_hashes(&mut hash_set, &rice_encoding).unwrap();

    // With little-endian, 0x12345678 becomes [0x78, 0x56, 0x34, 0x12]
    // With big-endian, 0x12345678 becomes [0x12, 0x34, 0x56, 0x78]
    let expected_le_bytes = vec![0x78, 0x56, 0x34, 0x12];
    let expected_hash = HashPrefix::new(expected_le_bytes).unwrap();

    let hashes = hash_set.to_sorted_vec();
    assert_eq!(hashes.len(), 1, "Should have exactly one hash");
    assert_eq!(
        hashes[0], expected_hash,
        "Hash should use little-endian conversion"
    );

    // Verify the checksum is computed correctly
    let checksum = hash_set.compute_checksum();
    let checksum_hex = hex::encode(checksum.as_bytes());

    // This checksum should be different from what we'd get with big-endian
    let mut be_hash_set = HashPrefixSet::new();
    let be_bytes = vec![0x12, 0x34, 0x56, 0x78];
    let be_hash = HashPrefix::new(be_bytes).unwrap();
    be_hash_set.insert(be_hash);
    let be_checksum = be_hash_set.compute_checksum();
    let be_checksum_hex = hex::encode(be_checksum.as_bytes());

    assert_ne!(
        checksum_hex, be_checksum_hex,
        "Little-endian and big-endian checksums should be different"
    );
}

#[test]
fn test_little_endian_rice_conversion() {
    // Test that Rice-decoded integers are converted to little-endian bytes
    // This is the key fix for the checksum mismatch issue

    let test_value: u32 = 0x12345678;
    let little_endian_bytes = test_value.to_le_bytes();
    let big_endian_bytes = test_value.to_be_bytes();

    // Verify they're different
    assert_ne!(little_endian_bytes, big_endian_bytes);

    // Verify little-endian is [0x78, 0x56, 0x34, 0x12]
    assert_eq!(little_endian_bytes, [0x78, 0x56, 0x34, 0x12]);

    // Verify big-endian is [0x12, 0x34, 0x56, 0x78]
    assert_eq!(big_endian_bytes, [0x12, 0x34, 0x56, 0x78]);

    // Our implementation should use little-endian to match Go
    let hash_le = HashPrefix::new(little_endian_bytes.to_vec()).unwrap();
    let hash_be = HashPrefix::new(big_endian_bytes.to_vec()).unwrap();

    assert_ne!(
        hash_le, hash_be,
        "Little-endian and big-endian hashes should be different"
    );
}

// Helper function to process ThreatEntrySet (mimics the database logic)
fn process_threat_entry_set(
    hash_set: &mut HashPrefixSet,
    threat_entry_set: &ThreatEntrySet,
) -> Result<(), Box<dyn std::error::Error>> {
    match threat_entry_set.compression_type {
        x if x == CompressionType::Raw as i32 => {
            if let Some(raw_hashes) = &threat_entry_set.raw_hashes {
                process_raw_hashes(hash_set, raw_hashes)?;
            }
        }
        x if x == CompressionType::Rice as i32 => {
            if let Some(rice_hashes) = &threat_entry_set.rice_hashes {
                process_rice_hashes(hash_set, rice_hashes)?;
            }
        }
        _ => {
            return Err(format!(
                "Unsupported compression type: {}",
                threat_entry_set.compression_type
            )
            .into());
        }
    }
    Ok(())
}

fn process_raw_hashes(
    hash_set: &mut HashPrefixSet,
    raw_hashes: &RawHashes,
) -> Result<(), Box<dyn std::error::Error>> {
    let prefix_size = raw_hashes.prefix_size as usize;
    let raw_data = &raw_hashes.raw_hashes;

    if raw_data.len() % prefix_size != 0 {
        return Err("Invalid raw hashes length".into());
    }

    for chunk in raw_data.chunks(prefix_size) {
        let hash = HashPrefix::new(chunk.to_vec())?;
        hash_set.insert(hash);
    }

    Ok(())
}

fn process_rice_hashes(
    hash_set: &mut HashPrefixSet,
    rice_hashes: &RiceDeltaEncoding,
) -> Result<(), Box<dyn std::error::Error>> {
    use safebrowsing_hash::rice::decode_rice_integers;

    let decoded_values = decode_rice_integers(
        rice_hashes.rice_parameter,
        rice_hashes.first_value,
        rice_hashes.num_entries,
        &rice_hashes.encoded_data,
    )?;

    for value in decoded_values {
        // Use little-endian to match Go implementation
        let hash_bytes = value.to_le_bytes().to_vec();
        let hash = HashPrefix::new(hash_bytes)?;
        hash_set.insert(hash);
    }

    Ok(())
}
