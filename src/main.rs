pub mod common;
pub mod protocol;
pub mod tracker;
pub mod tls;

extern crate byteorder;
extern crate flate2;
extern crate http_muncher;
extern crate libc;
extern crate num;
extern crate pcap;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate nom;
#[macro_use]
extern crate serde_derive;
extern crate serde;
// #[macro_use]
extern crate docopt;
extern crate ring;
extern crate serde_json;

use pcap::{Capture, Device};
use protocol::{Ethernet, Protocol};
use std::default::Default;
use std::env;
use tracker::Tracker;
// use txwaf::add_rules_module;
// use tls::TlsData;

#[derive(Debug, Deserialize)]
pub struct Args {
    pub arg_config: Vec<String>,
}

fn main() {
    env_logger::init();

    // init local modules
    // add_rules_module(Box::new(TlsData::new()));

    let dev = match env::var("DEV") {
        Ok(val) => val,
        Err(_) => String::new(),
    };

    let mut device = match Device::lookup() {
        Ok(val) => val,
        Err(e) => {
            println!("Could not find a suitable device. Make sure the container is running in privilged mode. Err: {}", e);
            return;
        }
    };
    if !dev.is_empty() {
        let dev_list = match Device::list() {
            Ok(val) => val,
            Err(e) => {
                println!("Could not get device list. Make sure the container is running in privilged mode. Err: {}", e);
                vec![]
            }
        };
        let mut found = false;
        for d in dev_list {
            if d.name == dev {
                device = d;
                found = true;
                break;
            }
        }
        if !found {
            println!("Could not find device: {}. Make sure the container is running in privilged mode and device name is correct.", dev);
            return;
        }
    }

    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .unwrap();

    let mut tracker = Tracker::new();
    while let Ok(packet) = cap.next() {
        let mut ethernet = Ethernet::default();
        if let Err(err) = ethernet.process(packet.data) {
            panic!("Error encountered when sniffing: {}", err);
        }
        tracker.consume(&Box::new(Protocol::Ethernet(ethernet)));
    }
}
