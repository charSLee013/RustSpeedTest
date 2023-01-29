use rand::seq::index::sample;
use std::collections::HashSet;
use std::net::IpAddr;
use url::quirks::host;

use async_std::io::ReadExt;
use download::Downloader;
use futures::executor::block_on;
use input::Opts;

use scanner::Scanner;
use std::time::Duration;

mod download;

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
        opts.avg_delay_upper,
        opts.avg_delay_lower,
    );
    let mut result = block_on(scanner.run());
    result.sort();

    // display result
    for r in result.iter().take(opts.display) {
        println!("{}", r);
    }

    if opts.disable_download.is_some() {
        println!("Disable download speed test.exiting...");
        return;
    }

    let download_ips: Vec<std::net::IpAddr> = result
        .iter()
        .take(opts.download_number)
        .map(|x| x.ip)
        .collect();

    let domain: String = match utils::get_domain_from_url(opts.download_url.as_str()) {
        Ok(h) => h,
        Err(e) => {
            println!("Cannot get host for speed test url;\nError message: {}", e);
            std::process::exit(1);
        }
    };

    // download speed test
    let downloader: Downloader = Downloader::new(
        &download_ips,
        4,
        domain,
        Duration::from_secs(10),
        Duration::from_millis(5000),
        opts.download_port,
        opts.download_url.to_string(),
    );

    let mut speedtest_result = downloader.run();
    speedtest_result.sort();

    for r in speedtest_result.iter() {
        println!("{}", r);
    }

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
}

fn parse_addresses_from_opt(opts: &Opts) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for arg in opts.args.iter() {
        let content: String = match std::fs::read_to_string(arg) {
            Ok(text) => text,
            Err(_) => arg.to_string(),
        };
        let parse_ips = utils::parse_addresses(&content);
        let sample_size = if opts.random_number > 0 && opts.random_number < parse_ips.len() {
            opts.random_number
        } else {
            parse_ips.len()
        };

        let parse_ips: Vec<IpAddr> = sample(&mut rand::thread_rng(), parse_ips.len(), sample_size)
            .into_iter()
            .map(|i| parse_ips[i])
            .collect();
        ips.extend(parse_ips.iter());
    }

    let set: HashSet<IpAddr> = ips.into_iter().collect();
    set.into_iter().collect()
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    use crate::download::Downloader;

    use super::scanner;

    use super::utils;
    use async_std::task::block_on;
    use rand::seq::SliceRandom;
    use tokio::runtime::Runtime;

    fn default_test_ips() -> String {
        return "173.245.48.0/20
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
        131.0.72.0/22"
            .to_string();
    }

    #[test]
    #[ignore]
    pub fn tcpdelay_from_cloudflare() {
        let ips_v4 = default_test_ips();
        let ips = utils::parse_addresses(&ips_v4);
        assert!(!ips.is_empty());

        // 随机测试4096个IP以免耗费过长时间
        let scan_ips: Vec<IpAddr> = ips
            .choose_multiple(&mut rand::thread_rng(), 4096)
            .cloned()
            .collect();
        let scan = scanner::Scanner::new(
            scan_ips,
            500,
            std::time::Duration::from_millis(5000),
            4,
            443,
            9999,
            0,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut result = rt.block_on(scan.run());
        result.sort();
        assert!(!result.is_empty());

        // show top 10
        for r in result.iter().take(10) {
            println!("{}", r);
        }
    }

    #[ignore]
    #[test]
    // / Makes sure the network is available
    pub fn fulltest_from_cloudflare() {
        let ips_v4 = &default_test_ips();
        let ips = utils::parse_addresses(&ips_v4);
        assert!(!ips.is_empty());

        // 随机测试1024个IP以免耗费过长时间
        let scan_ips: Vec<IpAddr> = ips
            .choose_multiple(&mut rand::thread_rng(), 1024)
            .cloned()
            .collect();
        let scan = scanner::Scanner::new(
            scan_ips,
            200,
            std::time::Duration::from_millis(5000),
            4,
            443,
            9999,
            0,
        );
        let mut result = block_on(scan.run());
        result.sort();
        assert!(!result.is_empty());

        let mut speed_test_ips = Vec::new();
        for r in result.iter().take(15) {
            println!("{}", r);
            speed_test_ips.push(r.ip);
        }

        // download speed test
        let downloader: Downloader = Downloader::new(
            &speed_test_ips,
            4,
            "speed.cloudflare.com".to_string(),
            Duration::from_secs(10),
            Duration::from_millis(5000),
            80,
            "http://speed.cloudflare.com/__down?bytes=2000000000".to_string(),
        );

        for r in downloader.run().iter() {
            println!("{}", r);
        }
    }

    #[test]
    #[ignore]
    fn downloadtest_from_cloudflare() {
        let speed_test_ips = vec![
            IpAddr::from_str("173.245.58.109").unwrap(),
            IpAddr::from_str("173.245.59.176").unwrap(),
            IpAddr::from_str("173.245.59.148").unwrap(),
            IpAddr::from_str("173.245.59.176").unwrap(),
        ];

        // download speed test
        let downloader: Downloader = Downloader::new(
            &speed_test_ips,
            4,
            "speed.cloudflare.com".to_string(),
            Duration::from_secs(30),
            Duration::from_millis(5000),
            443,
            "https://speed.cloudflare.com/__down?bytes=2000000000".to_string(),
        );

        for r in downloader.run().iter() {
            println!("{}", r);
        }
    }
}
