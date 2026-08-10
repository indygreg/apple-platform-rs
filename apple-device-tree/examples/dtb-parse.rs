use apple_device_tree::{serialize::string_for_node, DeviceTreeNode};
use clap::Parser;
use scroll::ctx::TryFromCtx;
use scroll::Endian;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::exit;

#[derive(Parser)]
struct Opts {
    #[clap(short, long)]
    file: String,
}

// Parse a device tree from a file
fn main() {
    let opts: Opts = Opts::parse();
    let path = Path::new(&opts.file);
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            exit(1);
        }
    };
    let mut buf = Vec::new();
    if let Err(e) = file.read_to_end(&mut buf) {
        eprintln!("Failed to read file: {}", e);
        exit(1);
    }

    match DeviceTreeNode::try_from_ctx(&buf, Endian::Little) {
        Ok((root_node, _)) => {
            let json_output = string_for_node(&root_node);
            println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
        }
        Err(e) => {
            eprintln!("Failed to parse device tree: {}", e);
            exit(1);
        }
    }
}
