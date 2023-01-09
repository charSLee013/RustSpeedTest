use std::collections::HashSet;
use std::net::IpAddr;

use futures::executor::block_on;
use input::Opts;

use scanner::Scanner;
use std::time::Duration;

mod input;
mod scanner;
mod utils;

fn main() {
    let opts: Opts = Opts::read();
    let ips = parse_addresses_from_opt(&opts);

    if ips.is_empty() {
        println!(
            "No IPs could be resolved, aborting scan.\n Please check arguments: {:?}",
            opts
        );
        std::process::exit(1);
    }

    let scanner = Scanner::new(
        ips,
        opts.number,
        Duration::from_millis(opts.timeout),
        opts.time,
        opts.port,
    );
    let mut result = block_on(scanner.run());
    result.sort();

    // write result to file
    match utils::write_to_csv(&opts.output, &result) {
        Ok(_) => {}
        Err(error) => {
            println!(
                "Warn: Cannot write result to {}\nError message:{}",
                &opts.output, error,
            );
        }
    }

    // display result
    for r in result.iter().take(opts.display) {
        println!("{}", r);
    }
}

fn parse_addresses_from_opt(opts: &Opts) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for arg in opts.args.iter() {
        match std::fs::read_to_string(arg) {
            Ok(content) => {
                ips.extend(utils::parse_addresses(&content));
            }
            Err(_) => {
                ips.extend(utils::parse_addresses(arg));
            }
        }
    }

    let set: HashSet<IpAddr> = ips.into_iter().collect();
    set.into_iter().collect()
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use super::scanner;

    use super::utils;
    use async_std::task::block_on;
    use rand::seq::SliceRandom;

    #[test]
    // / Makes sure the network is available
    pub fn speedtest_from_cloudflare() {
        let ips_v4 = "173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22";
        let ips = utils::parse_addresses(ips_v4);
        assert!(!ips.is_empty());

        // 随机测试5000个IP以免耗费过长时间
        let scan_ips: Vec<IpAddr> = ips
            .choose_multiple(&mut rand::thread_rng(), 5958)
            .cloned()
            .collect();
        let scan =
            scanner::Scanner::new(scan_ips, 500, std::time::Duration::from_millis(5000), 4, 80);
        let mut result = block_on(scan.run());
        result.sort();
        assert!(!result.is_empty());
    }
}
