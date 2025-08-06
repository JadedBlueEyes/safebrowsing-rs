//! Integration tests for Rice-Golomb encoding/decoding functionality
//!
//! These tests demonstrate that the Rice encoding implementation works correctly
//! with realistic data patterns similar to what the Safe Browsing API uses.

use safebrowsing_hash::rice::{decode_rice_integers, BitReader, RiceDecoder};

#[test]
fn test_rice_encoding_integration() {
    // Test with a real-world example from the Go test suite
    // This represents encoded hash deltas with k=2
    let encoded_data = hex::decode("f702").unwrap();
    let decoded = decode_rice_integers(2, 0, 2, &encoded_data).unwrap();

    // Should decode to [0, 15, 24] (first value + two deltas)
    assert_eq!(decoded, vec![0, 15, 24]);
}

#[test]
fn test_bit_reader_integration() {
    // Test that BitReader correctly handles multi-byte sequences
    let data = vec![0xf7, 0x02]; // Same data as above test
    let mut reader = BitReader::new(&data);

    // Manually decode the first few bits to verify bit-level correctness
    // This helps ensure our bit reading matches the Go implementation
    // 0xf7 = 11110111 in binary, read LSB first: 1,1,1,0,1,1,1,1
    let first_bit = reader.read_bits(1).unwrap();
    let next_three_bits = reader.read_bits(3).unwrap();
    let next_four_bits = reader.read_bits(4).unwrap();

    // Verify we can read individual and groups of bits correctly
    assert_eq!(first_bit, 1); // LSB of 0xf7 = bit 0 = 1
    assert_eq!(next_three_bits, 3); // Next 3 bits: bits 1,2,3 = 1,1,0 = 011 = 3
    assert_eq!(next_four_bits, 15); // Next 4 bits: bits 4,5,6,7 = 1,1,1,1 = 1111 = 15
}

#[test]
fn test_rice_decoder_with_various_parameters() {
    // Test Rice decoding with different k values
    let test_cases = vec![
        // (k, hex_data, expected_first_value)
        (5, "00", 0),    // Simple case with k=5
        (2, "f702", 15), // More complex case with k=2
    ];

    for (k, hex_input, expected_first_decoded) in test_cases {
        let data = hex::decode(hex_input).unwrap();
        let mut reader = BitReader::new(&data);
        let decoder = RiceDecoder::new(k);

        let decoded_value = decoder.read_value(&mut reader).unwrap();
        assert_eq!(
            decoded_value, expected_first_decoded,
            "Failed for k={k}, input={hex_input}"
        );
    }
}

#[test]
fn test_end_to_end_rice_processing() {
    // Simulate processing hash deltas as they would come from Safe Browsing API
    let rice_parameter = 2;
    let first_value = 1000;
    let num_entries = 2;
    let encoded_data = hex::decode("f702").unwrap();

    // Decode the deltas
    let values =
        decode_rice_integers(rice_parameter, first_value, num_entries, &encoded_data).unwrap();

    // Should have first value plus decoded deltas
    assert_eq!(values.len(), 3); // first_value + num_entries
    assert_eq!(values[0], 1000); // first value
    assert!(values[1] > values[0]); // monotonically increasing
    assert!(values[2] > values[1]); // monotonically increasing
}

#[test]
fn test_rice_decoding_error_handling() {
    // Test that invalid parameters are properly rejected
    assert!(decode_rice_integers(-1, 0, 1, &[0]).is_err()); // Invalid k
    assert!(decode_rice_integers(33, 0, 1, &[0]).is_err()); // Invalid k
    assert!(decode_rice_integers(2, 0, -1, &[0]).is_err()); // Invalid num_entries

    // Test that insufficient data is handled
    let mut reader = BitReader::new(&[]);
    let decoder = RiceDecoder::new(2);
    assert!(decoder.read_value(&mut reader).is_err()); // Not enough data
}

// Helper function for hex decoding
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        Ok(super::hex_decode(s))
    }
}
