use std::env::args;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

use csnmp::{ObjectIdentifier, Snmp2cClient};
use tracing_subscriber;


#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;


async fn run() -> ExitCode {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = args().collect();
    if args.len() != 3 {
        eprintln!("Usage: bulkwalk IPADDR COMMUNITY");
        return ExitCode::FAILURE;
    }

    let ip_addr: IpAddr = args[1].parse()
        .expect("failed to parse IP address");
    let sock_addr = SocketAddr::from((ip_addr, 161));

    let client_res = Snmp2cClient::new(
        sock_addr,
        Vec::from(args[2].as_bytes()),
        Some("0.0.0.0:0".parse().unwrap()),
        None,
    ).await;
    let client = client_res.expect("failed to create SNMP client");

    let results_res = client.walk_bulk(
        ObjectIdentifier::try_from(&[1, 3, 6, 1, 2, 1, 1][..]).unwrap(),
        0,
        10,
    ).await;
    let results = results_res.expect("failed to bulk-walk");

    for (oid, value) in results {
        println!("{}: {:?}", oid, value);
    }

    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let _profiler = dhat::Profiler::new_heap();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build runtime")
        .block_on(run())
}
