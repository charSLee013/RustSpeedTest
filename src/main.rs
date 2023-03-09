use rand::seq::index::sample;
use std::collections::HashSet;
use std::net::IpAddr;


use download::Downloader;
use routes::CloudflareChecker;

use input::Opts;

use scanner::{Delay, Scanner};
use std::time::Duration;

mod download;
mod input;
mod routes;
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

    // create a tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .global_queue_interval(u32::MAX)
        .event_interval(31)
        .build()
        .unwrap();

    let result = rt.block_on(run_scanner(ips, &opts));

    // display result
    for r in result.iter().take(opts.display) {
        println!("{}", r);
    }

    // 检查路由是否跳动
    let mut result_ips: Vec<IpAddr> = result.iter().map(|x| x.ip).collect();
    if opts.check_reoutes {
        result_ips = rt.block_on(run_checker(result_ips, &opts));
        println!(
            "After filtering out router jitter, there are still {} - {} = {} left.",
            result.len(),
            result.len() - result_ips.len(),
            result_ips.len()
        );
    }

    if !opts.enable_download {
        println!("Disable download speed test.exiting...");

        if let Err(e) = utils::write_to_csv(&opts.output, result, None) {
            println!(
                "Warn: Cannot write result to {}\nError message:{}",
                &opts.output, e,
            );
        }
        return;
    }

    let result_ips: Vec<IpAddr> = if opts.download_number != 0 {
        result_ips.into_iter().take(opts.download_number).collect()
    } else {
        result_ips
    };

    let domain: String = match utils::get_domain_from_url(opts.download_url.as_str()) {
        Ok(h) => h,
        Err(e) => {
            println!("Cannot get host for speed test url;\nError message: {}", e);
            std::process::exit(1);
        }
    };

    // download speed test
    let downloader: Downloader = Downloader::new(
        &result_ips,
        4,
        domain,
        Duration::from_secs(opts.download_timeout),
        Duration::from_millis(opts.timeout),
        opts.download_port,
        opts.download_url.to_string(),
    );

    let mut speedtest_result = rt.block_on(downloader.run());
    speedtest_result.sort();

    for r in speedtest_result.iter() {
        println!("{}", r);
    }

    // write result to file
    match utils::write_to_csv(&opts.output, result, Some(speedtest_result)) {
        Ok(_) => {}
        Err(error) => {
            println!(
                "Warn: Cannot write result to {}\nError message:{}",
                &opts.output, error,
            );
        }
    }
}

async fn run_scanner(ips: Vec<IpAddr>, opts: &Opts) -> Vec<Delay> {
    let scanner = Scanner::new(
        ips,
        opts.number,
        Duration::from_millis(opts.timeout),
        opts.time,
        opts.port,
        opts.avg_delay_upper,
        opts.avg_delay_lower,
    );

    let mut result = scanner.run().await;
    result.sort();
    result
}

async fn run_checker(ips: Vec<IpAddr>, opts: &Opts) -> Vec<IpAddr> {
    let checker = CloudflareChecker::new(
        ips,
        10,
        Duration::from_millis(opts.timeout),
        80,
        opts.number,
    );

    let result = checker.check_routes().await;
    result
}

fn parse_addresses_from_opt(opts: &Opts) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for arg in opts.args.iter() {
        let content: String = match std::fs::read_to_string(arg) {
            Ok(text) => text,
            Err(_) => arg.to_string(),
        };
        let parse_ips = utils::parse_addresses(&content);
        ips.extend(parse_ips.iter());
    }

    let set: HashSet<IpAddr> = ips.into_iter().collect();
    let uniq_ips: Vec<IpAddr> = set.into_iter().collect();

    let sample_size = if opts.random_number > 0 && opts.random_number < uniq_ips.len() {
        opts.random_number
    } else {
        uniq_ips.len()
    };

    sample(&mut rand::thread_rng(), uniq_ips.len(), sample_size)
        .into_iter()
        .map(|i| uniq_ips[i])
        .collect()
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use std::time::Duration;

    use crate::download::Downloader;
    use crate::input::Opts;
    use crate::parse_addresses_from_opt;
    use crate::utils::parse_addresses;

    use super::scanner;

    use super::utils;

    use rand::seq::SliceRandom;

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

        let scan = scanner::Scanner::new(
            ips,
            2000,
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
            Duration::from_millis(2000),
            443,
            "https://speed.cloudflare.com/__down?bytes=2000000000".to_string(),
        );
        let rt = tokio::runtime::Runtime::new().unwrap();

        for r in rt.block_on(downloader.run()).iter() {
            println!("{}", r);
        }
    }

    #[test]
    #[ignore]
    fn downloadtest_from_cloudflare() {
        let speed_test_ips: Vec<IpAddr> = parse_addresses(&default_test_ips())
            .into_iter()
            .take(10)
            .collect();

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
        let rt = tokio::runtime::Runtime::new().unwrap();
        for r in rt.block_on(downloader.run()).iter() {
            println!("{}", r);
        }
    }

    #[test]
    fn test_parse_addresses_from_opt() {
        let mut opts = Opts::default();
        opts.random_number = 0;
        opts.args = vec!["192.168.1.1/24".to_string(), "192.168.1.1/28".to_string()];

        let ips = parse_addresses_from_opt(&opts);
        assert_eq!(ips.len(), 256);

        opts.random_number = 50;
        let ips = parse_addresses_from_opt(&opts);
        assert_eq!(ips.len(), opts.random_number);

        opts.random_number = 9999;
        let ips = parse_addresses_from_opt(&opts);
        assert_eq!(ips.len(), 256);
    }
}
