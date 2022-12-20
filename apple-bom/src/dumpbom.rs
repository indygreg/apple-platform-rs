// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[allow(unused)]
mod error;
#[allow(unused)]
mod format;
#[allow(unused)]
mod path;

use {
    crate::{
        error::Error,
        format::{BomBlock, ParsedBom},
    },
    clap::{value_parser, Arg, ArgAction, Command},
    std::path::PathBuf,
};

type BomResult<T> = Result<T, error::Error>;

fn main_impl() -> BomResult<()> {
    let matches = Command::new("Apple BOM Dumper")
        .arg_required_else_help(true)
        .version("0.1")
        .author("Gregory Szorc <gregory.szorc@gmail.com>")
        .about("Show information about Apple BOM data structures")
        .arg(
            Arg::new("path")
                .action(ArgAction::Set)
                .value_parser(value_parser!(PathBuf))
                .num_args(1)
                .help("Path to BOM file"),
        )
        .arg(
            Arg::new("action")
                .action(ArgAction::Set)
                .value_parser([
                    "blocks-index",
                    "blocks",
                    "bom-info",
                    "header",
                    "hl-index",
                    "paths",
                    "paths-short",
                    "vars-index",
                    "size64",
                    "v-index",
                ])
                .default_value("header")
                .help("Which content to show"),
        )
        .get_matches();

    let path = matches
        .get_one::<PathBuf>("path")
        .expect("path should be required");
    let action = matches
        .get_one::<String>("action")
        .expect("action should be required");

    let bom_data = std::fs::read(path)?;
    let bom = ParsedBom::parse(&bom_data)?;

    match action.as_str() {
        "blocks-index" => {
            println!("{} total blocks", bom.blocks.count);
            for (i, entry) in bom.blocks.blocks.iter().enumerate() {
                println!("#{i}: {entry:?}");
            }
        }
        "blocks" => {
            println!("{} total blocks", bom.header.number_of_blocks);
            for i in 0..bom.header.number_of_blocks as usize + 1 {
                match BomBlock::try_parse(&bom, i) {
                    Ok(block) => {
                        println!("#{i}: {block:?}");
                    }
                    Err(_) => {
                        println!("#{}: (unknown) {}", i, hex::encode(bom.block_data(i)?));
                    }
                }
            }
        }
        "bom-info" => {
            println!("{:#?}", bom.bom_info()?);
        }
        "header" => {
            println!("{:#?}", bom.header);
        }
        "hl-index" => {
            println!("{:#?}", bom.hl_index()?);
        }
        "paths" => {
            println!("{:#?}", bom.paths()?);
        }
        "paths-short" => {
            for path in bom.paths()? {
                if let Some(link) = path.link_name() {
                    println!("{} {} -> {}", path.symbolic_mode(), path.path(), link);
                } else {
                    println!("{} {}", path.symbolic_mode(), path.path());
                }
            }
        }
        "size64" => {
            println!("{:#?}", bom.size64()?);
        }
        "vars-index" => {
            println!("{:#?}", bom.vars);
        }
        "v-index" => {
            println!("{:#?}", bom.vindex()?);
        }
        _ => {
            return Err(Error::CliBadArgs(format!("unhandled action: {action}")));
        }
    }

    Ok(())
}

fn main() {
    let exit_code = match main_impl() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Error: {err:?}");
            1
        }
    };

    std::process::exit(exit_code)
}
