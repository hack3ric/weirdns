mod config;
mod dns64;
mod glob;
mod instance;
mod transport;

use async_executor::LocalExecutor;
use futures_lite::future::block_on;
use std::rc::Rc;

use crate::config::{Cli, read_config};
use crate::instance::start_instance;

fn run() -> anyhow::Result<()> {
  let cli: Cli = argh::from_env();
  let configs = read_config(&cli)?;

  let ex = Rc::new(LocalExecutor::new());
  block_on(ex.run({
    let ex = ex.clone();
    async move {
      for config in configs {
        start_instance(ex.clone(), config).await?;
      }
      std::future::pending().await
    }
  }))
}

fn print_anyhow_error(error: &anyhow::Error) {
  eprintln!(
    "{}",
    error.chain().map(ToString::to_string).collect::<Vec<_>>().join(": ")
  );
}

fn main() {
  if run().inspect_err(print_anyhow_error).is_err() {
    std::process::exit(1);
  }
}
