#![feature(fs_try_exists)]
#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate log;

mod clients;
mod constants;
mod privesc;
mod privesc_bin;
mod recon;
mod recon_bin;
mod schemas;
mod server;
mod servers;
mod utils;
mod winapi;

use clap::{Arg, ArgAction, Command};

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = Command::new("riicli")
        .version("0.1.0")
        .author("wsxqaz")
        .about("riicli")
        .subcommand(Command::new("privesc").about("run privesc"))
        .subcommand(Command::new("recon").about("run recon"))
        .subcommand(Command::new("create_user").about("create new default user"))
        .subcommand(Command::new("server").about("run server"))
        .subcommand(Command::new("udp").about("run udp"))
        .subcommand(Command::new("tcp").about("run tcp"))
        .get_matches();

    match matches.subcommand() {
        Some(("privesc", _)) => {
            info!("running privesc...");
            privesc_bin::run().await;
        }
        Some(("recon", _)) => {
            info!("running recon...");
            recon_bin::run().await;
        }
        Some(("create_user", _)) => {
            info!("running create_user...");
            winapi::users::create_user().await;
        }
        Some(("server", _)) => {
            info!("running server...");
            server::run_server().await;
        }
        Some(("udp", _)) => {
            info!("running udp...");
            clients::udp::client().await;
        }
        Some(("tcp", _)) => {
            info!("running tcp...");
            clients::tcp::client().await;
        }
        _ => {
            info!("defaulting to cli...");
        }
    }
}
