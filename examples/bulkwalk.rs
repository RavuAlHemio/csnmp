use std::env::args;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

use csnmp::{ObjectIdentifier, Snmp2cClient};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;


async fn run() -> ExitCode {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = args().collect();
    if args.len() != 4 {
        eprintln!("Usage: bulkwalk IPADDR COMMUNITY OID");
        return ExitCode::FAILURE;
    }

    let ip_addr: IpAddr = args[1].parse()
        .expect("failed to parse IP address");
    let sock_addr = SocketAddr::from((ip_addr, 161));

    let community = Vec::from(args[2].as_bytes());
    let top_oid: ObjectIdentifier = args[3].parse().expect("failed to parse OID");

    let client_res = Snmp2cClient::new(
        sock_addr,
        community,
        Some("0.0.0.0:0".parse().unwrap()),
        None,
        0,
    ).await;
    let client = client_res.expect("failed to create SNMP client");

    let results_res = client.walk_bulk(
        top_oid,
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
