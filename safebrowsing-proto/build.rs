use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get out_dir from Cargo
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);

    // Create proto directory in out_dir if it doesn't exist
    let proto_out_dir = out_path.join("proto");
    fs::create_dir_all(&proto_out_dir)?;

    // Specify the proto files to compile
    let proto_files = &["safebrowsing_proto.proto"];

    // Check if proto files exist in the current directory
    // If not, create them from embedded definitions
    for proto_file in proto_files {
        let proto_path = format!("src/{proto_file}");
        if !Path::new(&proto_path).exists() {
            // Create the proto file if it doesn't exist
            let proto_content = match *proto_file {
                "safebrowsing_proto.proto" => include_str!("src/safebrowsing_proto.proto"),
                _ => panic!("Unknown proto file: {proto_file}"),
            };
            fs::write(proto_path, proto_content)?;
        }
    }

    // Configure protobuf code generation
    let mut config = prost_build::Config::new();
    config.bytes(["."]);
    // Don't add debug since prost_derive will already implement it
    config.bytes(["."]);

    // Generate code from proto files
    config.compile_protos(
        &proto_files
            .iter()
            .map(|p| format!("src/{p}"))
            .collect::<Vec<_>>(),
        &["src"],
    )?;

    // Tell Cargo to rerun this build script if proto files change
    for proto_file in proto_files {
        println!("cargo:rerun-if-changed=src/{proto_file}");
    }

    Ok(())
}
