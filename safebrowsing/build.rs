use std::io::Result;

fn main() -> Result<()> {
    let mut prost_build = prost_build::Config::new();

    // Configure prost to generate code without serde derives since prost_types::Duration doesn't support them
    prost_build.extern_path(".google.protobuf.Duration", "::prost_types::Duration");

    // Compile the proto file
    prost_build.compile_protos(&["proto/safebrowsing.proto"], &["proto/"])?;

    Ok(())
}
