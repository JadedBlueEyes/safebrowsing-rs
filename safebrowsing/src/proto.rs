//! Generated protobuf types for Google Safe Browsing API v4

// Include the generated protobuf code
pub mod safebrowsing_proto {
    include!(concat!(env!("OUT_DIR"), "/safebrowsing_proto.rs"));
}

// Re-export for convenience
pub use safebrowsing_proto::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protobuf_enums() {
        // Test that protobuf enums can be converted to/from integers
        assert_eq!(safebrowsing_proto::ThreatType::Malware as i32, 1);
        assert_eq!(safebrowsing_proto::PlatformType::Windows as i32, 1);
        assert_eq!(safebrowsing_proto::ThreatEntryType::Url as i32, 1);
    }
}
