//! Protocol buffer definitions for the Google Safe Browsing API v4
//!
//! This crate provides the protobuf definitions for communicating with the
//! Safe Browsing API. The definitions are auto-generated from the proto file.

// Re-export the generated protobuf module
pub use self::safebrowsing_proto::*;

// Include the generated protobuf code
pub mod safebrowsing_proto {
    include!(concat!(env!("OUT_DIR"), "/safebrowsing_proto.rs"));

    use std::fmt;

    // Implement Display for ThreatType enum
    impl fmt::Display for ThreatType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ThreatType::Unspecified => write!(f, "UNSPECIFIED"),
                ThreatType::Malware => write!(f, "MALWARE"),
                ThreatType::SocialEngineering => write!(f, "SOCIAL_ENGINEERING"),
                ThreatType::UnwantedSoftware => write!(f, "UNWANTED_SOFTWARE"),
                ThreatType::PotentiallyHarmfulApplication => {
                    write!(f, "POTENTIALLY_HARMFUL_APPLICATION")
                }
            }
        }
    }

    // Implement Display for PlatformType enum
    impl fmt::Display for PlatformType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                PlatformType::Unspecified => write!(f, "UNSPECIFIED"),
                PlatformType::Windows => write!(f, "WINDOWS"),
                PlatformType::Linux => write!(f, "LINUX"),
                PlatformType::Android => write!(f, "ANDROID"),
                PlatformType::Osx => write!(f, "OSX"),
                PlatformType::Ios => write!(f, "IOS"),
                PlatformType::AnyPlatform => write!(f, "ANY_PLATFORM"),
                PlatformType::AllPlatforms => write!(f, "ALL_PLATFORMS"),
                PlatformType::Chrome => write!(f, "CHROME"),
            }
        }
    }

    // Implement Display for ThreatEntryType enum
    impl fmt::Display for ThreatEntryType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ThreatEntryType::Unspecified => write!(f, "UNSPECIFIED"),
                ThreatEntryType::Url => write!(f, "URL"),
                ThreatEntryType::Executable => write!(f, "EXECUTABLE"),
                ThreatEntryType::IpRange => write!(f, "IP_RANGE"),
            }
        }
    }

    // Implement Display for CompressionType enum
    impl fmt::Display for CompressionType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                CompressionType::Unspecified => write!(f, "UNSPECIFIED"),
                CompressionType::Raw => write!(f, "RAW"),
                CompressionType::Rice => write!(f, "RICE"),
            }
        }
    }
}

// Re-export the most commonly used types
pub use safebrowsing_proto::{
    ClientInfo, FetchThreatListUpdatesRequest, FetchThreatListUpdatesResponse,
    FindFullHashesRequest, FindFullHashesResponse, FindThreatMatchesRequest,
    FindThreatMatchesResponse, RawHashes, RawIndices, RiceDeltaEncoding, ThreatEntry,
    ThreatEntrySet, ThreatInfo, ThreatMatch,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_type_display() {
        let threat_type = safebrowsing_proto::ThreatType::Malware;
        assert_eq!(format!("{threat_type}"), "MALWARE");
    }

    #[test]
    fn test_platform_type_display() {
        let platform_type = safebrowsing_proto::PlatformType::AnyPlatform;
        assert_eq!(format!("{platform_type}"), "ANY_PLATFORM");
    }

    #[test]
    fn test_threat_entry_type_display() {
        let threat_entry_type = safebrowsing_proto::ThreatEntryType::Url;
        assert_eq!(format!("{threat_entry_type}"), "URL");
    }
}
