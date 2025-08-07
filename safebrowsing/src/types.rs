//! Core types for the Safe Browsing library

use serde::{Deserialize, Serialize};
use std::fmt;

// Re-export protobuf types for convenience
pub use safebrowsing_proto;

/// Types of threats that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    /// Malware threat type
    Malware = 1,
    /// Social engineering threat type  
    SocialEngineering = 2,
    /// Unwanted software threat type
    UnwantedSoftware = 3,
    /// Potentially harmful application threat type
    PotentiallyHarmfulApplication = 4,
}

impl fmt::Display for ThreatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatType::Malware => write!(f, "MALWARE"),
            ThreatType::SocialEngineering => write!(f, "SOCIAL_ENGINEERING"),
            ThreatType::UnwantedSoftware => write!(f, "UNWANTED_SOFTWARE"),
            ThreatType::PotentiallyHarmfulApplication => {
                write!(f, "POTENTIALLY_HARMFUL_APPLICATION")
            }
        }
    }
}

impl From<i32> for ThreatType {
    fn from(value: i32) -> Self {
        match value {
            1 => ThreatType::Malware,
            2 => ThreatType::SocialEngineering,
            3 => ThreatType::UnwantedSoftware,
            4 => ThreatType::PotentiallyHarmfulApplication,
            _ => ThreatType::Malware, // Default fallback
        }
    }
}

impl From<ThreatType> for i32 {
    fn from(threat_type: ThreatType) -> Self {
        threat_type as i32
    }
}

impl From<safebrowsing_proto::ThreatType> for ThreatType {
    fn from(proto_type: safebrowsing_proto::ThreatType) -> Self {
        match proto_type {
            safebrowsing_proto::ThreatType::Malware => ThreatType::Malware,
            safebrowsing_proto::ThreatType::SocialEngineering => ThreatType::SocialEngineering,
            safebrowsing_proto::ThreatType::UnwantedSoftware => ThreatType::UnwantedSoftware,
            safebrowsing_proto::ThreatType::PotentiallyHarmfulApplication => {
                ThreatType::PotentiallyHarmfulApplication
            }
            _ => ThreatType::Malware,
        }
    }
}

impl From<ThreatType> for safebrowsing_proto::ThreatType {
    fn from(threat_type: ThreatType) -> Self {
        match threat_type {
            ThreatType::Malware => safebrowsing_proto::ThreatType::Malware,
            ThreatType::SocialEngineering => safebrowsing_proto::ThreatType::SocialEngineering,
            ThreatType::UnwantedSoftware => safebrowsing_proto::ThreatType::UnwantedSoftware,
            ThreatType::PotentiallyHarmfulApplication => {
                safebrowsing_proto::ThreatType::PotentiallyHarmfulApplication
            }
        }
    }
}

/// Types of platforms that can be affected by threats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformType {
    /// Any platform
    AnyPlatform = 6,
    /// All platforms
    AllPlatforms = 7,
    /// Windows platform
    Windows = 1,
    /// Linux platform
    Linux = 2,
    /// Android platform
    Android = 3,
    /// OSX platform
    Osx = 4,
    /// iOS platform
    Ios = 5,
    /// Chrome browser
    Chrome = 8,
}

impl fmt::Display for PlatformType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformType::AnyPlatform => write!(f, "ANY_PLATFORM"),
            PlatformType::AllPlatforms => write!(f, "ALL_PLATFORMS"),
            PlatformType::Windows => write!(f, "WINDOWS"),
            PlatformType::Linux => write!(f, "LINUX"),
            PlatformType::Android => write!(f, "ANDROID"),
            PlatformType::Osx => write!(f, "OSX"),
            PlatformType::Ios => write!(f, "IOS"),
            PlatformType::Chrome => write!(f, "CHROME"),
        }
    }
}

impl From<i32> for PlatformType {
    fn from(value: i32) -> Self {
        match value {
            1 => PlatformType::Windows,
            2 => PlatformType::Linux,
            3 => PlatformType::Android,
            4 => PlatformType::Osx,
            5 => PlatformType::Ios,
            6 => PlatformType::AnyPlatform,
            7 => PlatformType::AllPlatforms,
            8 => PlatformType::Chrome,
            _ => PlatformType::AnyPlatform, // Default fallback
        }
    }
}

impl From<PlatformType> for i32 {
    fn from(platform_type: PlatformType) -> Self {
        platform_type as i32
    }
}

impl From<safebrowsing_proto::PlatformType> for PlatformType {
    fn from(proto_type: safebrowsing_proto::PlatformType) -> Self {
        match proto_type {
            safebrowsing_proto::PlatformType::Windows => PlatformType::Windows,
            safebrowsing_proto::PlatformType::Linux => PlatformType::Linux,
            safebrowsing_proto::PlatformType::Android => PlatformType::Android,
            safebrowsing_proto::PlatformType::Osx => PlatformType::Osx,
            safebrowsing_proto::PlatformType::Ios => PlatformType::Ios,
            safebrowsing_proto::PlatformType::AnyPlatform => PlatformType::AnyPlatform,
            safebrowsing_proto::PlatformType::AllPlatforms => PlatformType::AllPlatforms,
            safebrowsing_proto::PlatformType::Chrome => PlatformType::Chrome,
            _ => PlatformType::AnyPlatform,
        }
    }
}

impl From<PlatformType> for safebrowsing_proto::PlatformType {
    fn from(platform_type: PlatformType) -> Self {
        match platform_type {
            PlatformType::Windows => safebrowsing_proto::PlatformType::Windows,
            PlatformType::Linux => safebrowsing_proto::PlatformType::Linux,
            PlatformType::Android => safebrowsing_proto::PlatformType::Android,
            PlatformType::Osx => safebrowsing_proto::PlatformType::Osx,
            PlatformType::Ios => safebrowsing_proto::PlatformType::Ios,
            PlatformType::AnyPlatform => safebrowsing_proto::PlatformType::AnyPlatform,
            PlatformType::AllPlatforms => safebrowsing_proto::PlatformType::AllPlatforms,
            PlatformType::Chrome => safebrowsing_proto::PlatformType::Chrome,
        }
    }
}

/// Types of threat entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatEntryType {
    /// URL entry type
    Url = 1,
    /// Executable entry type
    Executable = 2,
    /// IP range entry type
    IpRange = 3,
}

impl fmt::Display for ThreatEntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatEntryType::Url => write!(f, "URL"),
            ThreatEntryType::Executable => write!(f, "EXECUTABLE"),
            ThreatEntryType::IpRange => write!(f, "IP_RANGE"),
        }
    }
}

impl From<i32> for ThreatEntryType {
    fn from(value: i32) -> Self {
        match value {
            1 => ThreatEntryType::Url,
            2 => ThreatEntryType::Executable,
            3 => ThreatEntryType::IpRange,
            _ => ThreatEntryType::Url, // Default fallback
        }
    }
}

impl From<ThreatEntryType> for i32 {
    fn from(entry_type: ThreatEntryType) -> Self {
        entry_type as i32
    }
}

impl From<safebrowsing_proto::ThreatEntryType> for ThreatEntryType {
    fn from(proto_type: safebrowsing_proto::ThreatEntryType) -> Self {
        match proto_type {
            safebrowsing_proto::ThreatEntryType::Url => ThreatEntryType::Url,
            safebrowsing_proto::ThreatEntryType::Executable => ThreatEntryType::Executable,
            safebrowsing_proto::ThreatEntryType::IpRange => ThreatEntryType::IpRange,
            _ => ThreatEntryType::Url,
        }
    }
}

impl From<ThreatEntryType> for safebrowsing_proto::ThreatEntryType {
    fn from(entry_type: ThreatEntryType) -> Self {
        match entry_type {
            ThreatEntryType::Url => safebrowsing_proto::ThreatEntryType::Url,
            ThreatEntryType::Executable => safebrowsing_proto::ThreatEntryType::Executable,
            ThreatEntryType::IpRange => safebrowsing_proto::ThreatEntryType::IpRange,
        }
    }
}

/// Describes a specific threat list by combining threat type, platform type, and entry type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThreatDescriptor {
    /// The type of threat
    pub threat_type: ThreatType,
    /// The platform type affected
    pub platform_type: PlatformType,
    /// The type of threat entry
    pub threat_entry_type: ThreatEntryType,
}

impl fmt::Display for ThreatDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.threat_type, self.platform_type, self.threat_entry_type
        )
    }
}

impl ThreatDescriptor {
    /// Create a new threat descriptor
    pub fn new(
        threat_type: ThreatType,
        platform_type: PlatformType,
        threat_entry_type: ThreatEntryType,
    ) -> Self {
        Self {
            threat_type,
            platform_type,
            threat_entry_type,
        }
    }
}

/// Represents a threat found for a specific URL pattern
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct URLThreat {
    /// The URL pattern that matched
    pub pattern: String,
    /// The threat descriptor that matched
    pub threat_descriptor: ThreatDescriptor,
}

impl URLThreat {
    /// Create a new URL threat
    pub fn new(pattern: String, threat_descriptor: ThreatDescriptor) -> Self {
        Self {
            pattern,
            threat_descriptor,
        }
    }
}

impl fmt::Display for URLThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.pattern, self.threat_descriptor)
    }
}

/// Compression types supported by the Safe Browsing API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressionType {
    /// Raw, uncompressed data
    Raw = 1,
    /// Rice-Golomb encoded data
    Rice = 2,
}

impl From<i32> for CompressionType {
    fn from(value: i32) -> Self {
        match value {
            1 => CompressionType::Raw,
            2 => CompressionType::Rice,
            _ => CompressionType::Raw,
        }
    }
}

impl From<CompressionType> for i32 {
    fn from(compression_type: CompressionType) -> Self {
        compression_type as i32
    }
}

impl From<safebrowsing_proto::CompressionType> for CompressionType {
    fn from(proto_type: safebrowsing_proto::CompressionType) -> Self {
        match proto_type {
            safebrowsing_proto::CompressionType::Raw => CompressionType::Raw,
            safebrowsing_proto::CompressionType::Rice => CompressionType::Rice,
            _ => CompressionType::Raw,
        }
    }
}

impl From<CompressionType> for safebrowsing_proto::CompressionType {
    fn from(compression_type: CompressionType) -> Self {
        match compression_type {
            CompressionType::Raw => safebrowsing_proto::CompressionType::Raw,
            CompressionType::Rice => safebrowsing_proto::CompressionType::Rice,
        }
    }
}

/// Default threat lists that cover the most common threats
pub const DEFAULT_THREAT_LISTS: &[ThreatDescriptor] = &[
    ThreatDescriptor {
        threat_type: ThreatType::Malware,
        platform_type: PlatformType::AnyPlatform,
        threat_entry_type: ThreatEntryType::Url,
    },
    ThreatDescriptor {
        threat_type: ThreatType::SocialEngineering,
        platform_type: PlatformType::AnyPlatform,
        threat_entry_type: ThreatEntryType::Url,
    },
    ThreatDescriptor {
        threat_type: ThreatType::UnwantedSoftware,
        platform_type: PlatformType::AnyPlatform,
        threat_entry_type: ThreatEntryType::Url,
    },
];

/// Android-specific threat lists
pub const ANDROID_THREAT_LISTS: &[ThreatDescriptor] = &[ThreatDescriptor {
    threat_type: ThreatType::PotentiallyHarmfulApplication,
    platform_type: PlatformType::Android,
    threat_entry_type: ThreatEntryType::Url,
}];

/// All available threat lists
pub const ALL_THREAT_LISTS: &[ThreatDescriptor] = &[
    ThreatDescriptor {
        threat_type: ThreatType::Malware,
        platform_type: PlatformType::AnyPlatform,
        threat_entry_type: ThreatEntryType::Url,
    },
    ThreatDescriptor {
        threat_type: ThreatType::SocialEngineering,
        platform_type: PlatformType::AnyPlatform,
        threat_entry_type: ThreatEntryType::Url,
    },
    ThreatDescriptor {
        threat_type: ThreatType::UnwantedSoftware,
        platform_type: PlatformType::AnyPlatform,
        threat_entry_type: ThreatEntryType::Url,
    },
    ThreatDescriptor {
        threat_type: ThreatType::PotentiallyHarmfulApplication,
        platform_type: PlatformType::Android,
        threat_entry_type: ThreatEntryType::Url,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_type_conversions() {
        assert_eq!(ThreatType::Malware as i32, 1);
        assert_eq!(ThreatType::from(1), ThreatType::Malware);
        assert_eq!(ThreatType::from(999), ThreatType::Malware); // Default fallback
    }

    #[test]
    fn test_platform_type_conversions() {
        assert_eq!(PlatformType::Windows as i32, 1);
        assert_eq!(PlatformType::from(1), PlatformType::Windows);
        assert_eq!(PlatformType::from(999), PlatformType::AnyPlatform); // Default fallback
    }

    #[test]
    fn test_threat_entry_type_conversions() {
        assert_eq!(ThreatEntryType::Url as i32, 1);
        assert_eq!(ThreatEntryType::from(1), ThreatEntryType::Url);
        assert_eq!(ThreatEntryType::from(999), ThreatEntryType::Url); // Default fallback
    }

    #[test]
    fn test_threat_descriptor() {
        let desc = ThreatDescriptor::new(
            ThreatType::Malware,
            PlatformType::AnyPlatform,
            ThreatEntryType::Url,
        );

        assert_eq!(desc.threat_type, ThreatType::Malware);
        assert_eq!(desc.platform_type, PlatformType::AnyPlatform);
        assert_eq!(desc.threat_entry_type, ThreatEntryType::Url);
    }

    #[test]
    fn test_url_threat() {
        let desc = ThreatDescriptor::new(
            ThreatType::Malware,
            PlatformType::AnyPlatform,
            ThreatEntryType::Url,
        );
        let threat = URLThreat::new("example.com/malicious".to_string(), desc);

        assert_eq!(threat.pattern, "example.com/malicious");
        assert_eq!(threat.threat_descriptor.threat_type, ThreatType::Malware);
    }

    #[test]
    fn test_display_implementations() {
        assert_eq!(ThreatType::Malware.to_string(), "MALWARE");
        assert_eq!(PlatformType::AnyPlatform.to_string(), "ANY_PLATFORM");
        assert_eq!(ThreatEntryType::Url.to_string(), "URL");

        let desc = ThreatDescriptor::new(
            ThreatType::Malware,
            PlatformType::AnyPlatform,
            ThreatEntryType::Url,
        );
        assert_eq!(desc.to_string(), "MALWARE/ANY_PLATFORM/URL");
    }

    #[test]
    fn test_default_threat_lists() {
        assert!(!DEFAULT_THREAT_LISTS.is_empty());
        assert!(DEFAULT_THREAT_LISTS.contains(&ThreatDescriptor {
            threat_type: ThreatType::Malware,
            platform_type: PlatformType::AnyPlatform,
            threat_entry_type: ThreatEntryType::Url,
        }));
    }
}
