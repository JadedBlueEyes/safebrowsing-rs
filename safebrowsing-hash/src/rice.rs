//! Rice-Golomb encoding and decoding for Safe Browsing
//!
//! This module implements the Rice-Golomb encoding scheme used by the Safe Browsing API
//! for compressing hash prefixes and indices.

use crate::{HashError, Result};

// Helper function for hex decoding in tests
#[cfg(test)]
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Wrapper for compatibility with test
#[cfg(test)]
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        Ok(super::hex_decode(s))
    }
}

/// Bit reader for reading individual bits from a byte stream
pub struct BitReader<'a> {
    buf: &'a [u8],
    mask: u8,
}

impl<'a> BitReader<'a> {
    /// Create a new BitReader from byte data
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, mask: 0x01 }
    }

    /// Read the specified number of bits and return as u32
    /// Bits are read in little-endian order within each byte
    pub fn read_bits(&mut self, num_bits: u32) -> Result<u32> {
        if num_bits == 0 {
            return Ok(0);
        }
        if num_bits > 32 {
            return Err(HashError::InvalidFormat(
                "Cannot read more than 32 bits".to_string(),
            ));
        }

        let mut result = 0u32;

        for i in 0..num_bits {
            if self.buf.is_empty() {
                return Err(HashError::InvalidFormat(
                    "Unexpected end of data".to_string(),
                ));
            }

            if (self.buf[0] & self.mask) > 0 {
                result |= 1u32 << i;
            }

            self.mask <<= 1;
            if self.mask == 0 {
                self.buf = &self.buf[1..];
                self.mask = 0x01;
            }
        }

        Ok(result)
    }

    /// Get the number of bits remaining to be read
    pub fn bits_remaining(&self) -> usize {
        let mut n = 8 * self.buf.len();
        let mut m = self.mask | 1;
        while m != 1 {
            n -= 1;
            m >>= 1;
        }
        n
    }
}

/// Rice-Golomb decoder for the Safe Browsing API
///
/// In Rice encoding, each number n is encoded as q and r where n = (q << k) + r.
/// k is the Rice parameter (0..32).
///
/// The quotient q is encoded in unary: a sequence of q ones followed by a zero.
/// The remainder r is encoded as a k-bit unsigned integer.
pub struct RiceDecoder {
    k: u32,
}

impl RiceDecoder {
    /// Create a new Rice decoder with the given parameter k
    pub fn new(k: u32) -> Self {
        Self { k }
    }

    /// Read and decode a single value from the bit stream
    pub fn read_value(&self, bit_reader: &mut BitReader) -> Result<u32> {
        // Read quotient (unary encoding: count ones until we hit a zero)
        let mut quotient = 0u32;
        loop {
            let bit = bit_reader.read_bits(1)?;
            if bit == 0 {
                break;
            }
            quotient += 1;
        }

        // Read remainder (k bits)
        let remainder = if self.k > 0 {
            bit_reader.read_bits(self.k)?
        } else {
            0
        };

        // Combine quotient and remainder: n = (q << k) + r
        Ok((quotient << self.k) + remainder)
    }
}

/// Decode Rice-Golomb encoded integers from Safe Browsing format
pub fn decode_rice_integers(
    rice_parameter: i32,
    first_value: i64,
    num_entries: i32,
    encoded_data: &[u8],
) -> Result<Vec<u32>> {
    if !(0..=32).contains(&rice_parameter) {
        return Err(HashError::InvalidFormat(format!(
            "Invalid rice parameter: {rice_parameter}"
        )));
    }

    if num_entries < 0 {
        return Err(HashError::InvalidFormat(format!(
            "Invalid num_entries: {num_entries}"
        )));
    }

    // Start with the first value
    let mut values = vec![first_value as u32];

    // If no additional entries, just return the first value
    if num_entries == 0 {
        return Ok(values);
    }

    let mut bit_reader = BitReader::new(encoded_data);
    let rice_decoder = RiceDecoder::new(rice_parameter as u32);

    // Decode each delta and add to the running sum
    for i in 0..num_entries {
        let delta = rice_decoder.read_value(&mut bit_reader)?;
        let next_value = values[i as usize] + delta;
        values.push(next_value);
    }

    // Check that we consumed most of the input (allow up to 7 unused bits)
    if bit_reader.bits_remaining() >= 8 {
        return Err(HashError::InvalidFormat(
            "Unconsumed rice encoded data".to_string(),
        ));
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_reader_basic() {
        // Test data: 0b10110100, 0b11010011
        let data = vec![0b10110100, 0b11010011];
        let mut reader = BitReader::new(&data);

        // Read individual bits (LSB first within each byte)
        assert_eq!(reader.read_bits(1).unwrap(), 0); // bit 0 of first byte
        assert_eq!(reader.read_bits(1).unwrap(), 0); // bit 1 of first byte
        assert_eq!(reader.read_bits(1).unwrap(), 1); // bit 2 of first byte
        assert_eq!(reader.read_bits(1).unwrap(), 0); // bit 3 of first byte

        // Read multiple bits at once
        assert_eq!(reader.read_bits(4).unwrap(), 0b1011); // bits 4-7 of first byte

        // Cross byte boundary
        assert_eq!(reader.read_bits(4).unwrap(), 0b0011); // bits 0-3 of second byte
        assert_eq!(reader.read_bits(4).unwrap(), 0b1101); // bits 4-7 of second byte
    }

    #[test]
    fn test_bit_reader_empty() {
        let data = vec![];
        let mut reader = BitReader::new(&data);

        assert!(reader.read_bits(1).is_err());
        assert_eq!(reader.bits_remaining(), 0);
    }

    #[test]
    fn test_bit_reader_bits_remaining() {
        let data = vec![0xFF, 0xFF];
        let mut reader = BitReader::new(&data);

        assert_eq!(reader.bits_remaining(), 16);
        reader.read_bits(3).unwrap();
        assert_eq!(reader.bits_remaining(), 13);
        reader.read_bits(8).unwrap();
        assert_eq!(reader.bits_remaining(), 5);
        reader.read_bits(5).unwrap();
        assert_eq!(reader.bits_remaining(), 0);
    }

    #[test]
    fn test_rice_decoder_with_go_vectors() {
        // Test vectors from Go implementation
        let test_cases = vec![
            (2, "f702", vec![15, 9]),
            (5, "00", vec![0]),
            (
                28,
                "54607be70a5fc1dcee69defe583ca3d6a5f2108c4a595600",
                vec![
                    62763050, 1046523781, 192522171, 1800511020, 4442775, 582142548,
                ],
            ),
        ];

        for (k, hex_input, expected) in test_cases {
            let data = hex::decode(hex_input).unwrap();
            let mut bit_reader = BitReader::new(&data);
            let decoder = RiceDecoder::new(k);

            let mut results = Vec::new();
            for _ in 0..expected.len() {
                let value = decoder.read_value(&mut bit_reader).unwrap();
                results.push(value);
            }

            assert_eq!(results, expected, "Failed for k={k}, input={hex_input}");
        }
    }

    #[test]
    fn test_decode_rice_integers_empty() {
        let result = decode_rice_integers(2, 42, 0, &[]).unwrap();
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn test_decode_rice_integers_invalid_params() {
        assert!(decode_rice_integers(-1, 0, 1, &[0]).is_err());
        assert!(decode_rice_integers(33, 0, 1, &[0]).is_err());
        assert!(decode_rice_integers(2, 0, -1, &[0]).is_err());
    }

    #[test]
    fn test_decode_rice_integers_with_go_vectors() {
        // Test complete rice integer decoding with Go test vectors
        let test_cases = vec![
            (2, 0, 2, "f702", vec![0, 15, 24]), // first_value=0, num_entries=2
            (5, 42, 1, "00", vec![42, 42]),     // first_value=42, num_entries=1
        ];

        for (k, first_value, num_entries, hex_input, expected) in test_cases {
            let data = hex::decode(hex_input).unwrap();
            let result = decode_rice_integers(k, first_value, num_entries, &data).unwrap();
            assert_eq!(
                result, expected,
                "Failed for k={k}, first={first_value}, entries={num_entries}, input={hex_input}"
            );
        }
    }
}
