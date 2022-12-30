// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use anyhow::Result;
use app_store_connect::cli::Args;
use clap::Parser;

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    if let Some(api_key) = args.api_key.as_ref() {
        args.command.run(api_key)
    } else {
        anyhow::bail!("missing --api-key");
    }
}
