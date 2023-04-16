use httping::{HttpingChecker, HttpingResult};
use rand::seq::index::sample;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use download::{Downloader, Speed};
use routes::{CFCDNCheckResult, CloudflareChecker};

use input::Opts;
use scanner::{Delay, Scanner};

mod download;
mod httping;
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

    // tcp 测试结果
    let mut tcping_result: Option<Vec<Delay>> = None;
    // http 测试结果
    let mut httping_result: Option<Vec<HttpingResult>> = None;
    // http cf-ray 结果
    let mut cfcdn_result: Option<Vec<CFCDNCheckResult>> = None;
    // 可用IP地址集合
    let mut valis_ips: Vec<IpAddr> = Vec::new();
    // 测速结果
    let mut speedtest_result: Option<Vec<Speed>> = None;

    // tcp 和 http 和 cfhttp 选择其中一个
    if opts.cfhttping {
        cfcdn_result = Some(rt.block_on(run_checker(ips, &opts)));
        if let Some(ref record) = cfcdn_result {
            valis_ips = record.iter().map(|r| r.ip).collect();
        }
    } else if opts.httping {
        httping_result = Some(async_std::task::block_on(run_httping(ips, &opts)));
        if let Some(ref record) = httping_result {
            valis_ips = record.iter().map(|r| r.ip).collect();
        }
    } else {
        tcping_result = Some(rt.block_on(run_scanner(ips, &opts)));
        if let Some(ref record) = tcping_result {
            valis_ips = record.iter().map(|r| r.ip).collect();
        }
    }

    // 是否启用下载测速
    if !opts.enable_download {
        println!("Disable download speed test.exiting...");
    } else {
        speedtest_result = Some(rt.block_on(run_downloader(&valis_ips, &opts)));
    }

    // 简单显示结果
    if opts.display != 0 {
        display_results(&tcping_result, &cfcdn_result, &speedtest_result, &opts);
    }

    // 写入到csv文件中
    match utils::write_to_csv(
        &valis_ips,
        tcping_result,
        // httping_result,
        cfcdn_result,
        speedtest_result,
        &opts,
    ) {
        Ok(_) => {}
        Err(error) => {
            println!(
                "Warn: Cannot write result to {}\nError message:{}",
                &opts.output, error,
            );
        }
    }
}

fn display_results(
    tcping_result: &Option<Vec<Delay>>,
    cfcdn_result: &Option<Vec<CFCDNCheckResult>>,
    speedtest_result: &Option<Vec<Speed>>,
    opts: &Opts,
) {
    if let Some(ref results) = speedtest_result {
        println!("Download speed test results:");
        println!("{:<16} {:<12}", "IP Address", "Download Speed (MB/s)");
        for record in results.iter().take(opts.display) {
            let download_speed = record.total_download as f64
                / 1024.0
                / 1024.0
                / record.consume.as_secs_f32() as f64;
            println!("{:<16} {:<12.2}", record.ip, download_speed);
        }
    } else if let Some(ref results) = tcping_result {
        println!("TCP scan results:");
        println!(
            "{:<16} {:<9} {:<9} {:<8} {:<14}",
            "IP Address", "Sent", "Received", "Loss", "Avg Delay (ms)"
        );
        for record in results.iter().take(opts.display) {
            let delay_ms = record.average_delay.as_millis();
            let loss_percent = 100.0 * (1.0 - record.success as f64 / opts.time as f64);
            println!(
                "{:<16} {:<9} {:<9} {:<8} {:<14}",
                record.ip,
                opts.time,
                record.success,
                format!("{:.1}%", loss_percent),
                delay_ms
            );
        }
    } else if let Some(ref results) = cfcdn_result {
        println!("HTTP routing check results:");
        println!(
            "{:<16} {:<9} {:<9} {:<8}",
            "IP Address", "Status", "Location", ""
        );
        for record in results.iter().take(opts.display) {
            let status_code = match record.route_status {
                routes::RouteStatus::Normal => 200,
                routes::RouteStatus::DiffLocation => 404,
                routes::RouteStatus::NoLocation => 500,
            };
            println!(
                "{:<16} {:<9} {:<9} {:<8}",
                record.ip, status_code, record.location_code, ""
            );
        }
    }
}

async fn run_httping(ips: Vec<IpAddr>, opts: &Opts) -> Vec<HttpingResult> {
    let httping_checker = HttpingChecker::new(
        opts.time,
        Duration::from_millis(opts.timeout),
        opts.port,
        opts.number,
        "",
    );

    httping_checker.run(ips).await
}

async fn run_downloader(ips: &[IpAddr], opts: &Opts) -> Vec<Speed> {
    let domain: String = match utils::get_domain_from_url(opts.download_url.as_str()) {
        Ok(h) => h,
        Err(e) => {
            println!("Cannot get host for speed test url;\nError message: {}", e);
            std::process::exit(1);
        }
    };

    // download speed test
    let downloader: Downloader = Downloader::new(
        ips.to_owned(),
        4,
        domain,
        Duration::from_secs(opts.download_timeout),
        Duration::from_millis(opts.timeout),
        opts.download_port,
        opts.download_url.to_string(),
        opts.download_number,
    );

    let mut speedtest_result = downloader.run().await;
    speedtest_result.sort();
    speedtest_result
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

async fn run_checker(ips: Vec<IpAddr>, opts: &Opts) -> Vec<CFCDNCheckResult> {
    let checker = CloudflareChecker::new(
        ips,
        10,
        Duration::from_millis(opts.timeout),
        80,
        opts.number,
    );
    let mut result = checker.check_routes().await;
    result.sort();
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
        let len = speed_test_ips.len();
        let downloader: Downloader = Downloader::new(
            speed_test_ips,
            4,
            "speed.cloudflare.com".to_string(),
            Duration::from_secs(10),
            Duration::from_millis(2000),
            443,
            "https://speed.cloudflare.com/__down?bytes=2000000000".to_string(),
            len,
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
        let len = speed_test_ips.len();
        let downloader: Downloader = Downloader::new(
            speed_test_ips,
            4,
            "speed.cloudflare.com".to_string(),
            Duration::from_secs(30),
            Duration::from_millis(5000),
            443,
            "https://speed.cloudflare.com/__down?bytes=2000000000".to_string(),
            len,
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
