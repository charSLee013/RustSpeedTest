use rand::seq::index::sample;
use std::collections::HashSet;
use std::net::IpAddr;

use download::{Downloader, Speed};
use routes::{CloudflareCheckResult, CloudflareChecker};

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

    // let result = rt.block_on(run_scanner(ips, &opts));

    // let mut result = if opts.httping{
    //     rt.block_on(run_checker(ips, &opts));
    // } else {
    //     rt.block_on(run_scanner(ips, &opts));
    // };

    // tcp 测试结果
    let mut tcping_result: Option<Vec<Delay>> = None;
    // http cf-ray 结果
    let mut httping_result: Option<Vec<CloudflareCheckResult>> = None;
    // 可用IP地址集合
    let mut valis_ips: Vec<IpAddr> = Vec::new();
    // 测速结果
    let mut speedtest_result: Option<Vec<Speed>> = None;

    // tcp 和 http 测试二选一
    if opts.httping {
        httping_result = Some(rt.block_on(run_checker(ips, &opts)));
        if let Some(httping_result) = httping_result {
            valis_ips = httping_result.iter().map(|r| r.ip_address).collect();
        }
    } else {
        tcping_result = Some(rt.block_on(run_scanner(ips, &opts)));
        if let Some(tcping_result) = tcping_result{
            valis_ips = tcping_result.iter().map(|r| r.ip).collect();
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
        display_results(
            &valis_ips,
            &tcping_result,
            &httping_result,
            &speedtest_result,
            &opts,
        );
    }

    // 写入到csv文件中
    // match utils::write_to_csv(&opts.output, result, Some(speedtest_result)) {
    //     Ok(_) => {}
    //     Err(error) => {
    //         println!(
    //             "Warn: Cannot write result to {}\nError message:{}",
    //             &opts.output, error,
    //         );
    //     }
    // }
}

fn display_results(
    valis_ips: &[IpAddr],
    tcping_result: &Option<Vec<Delay>>,
    httping_result: &Option<Vec<CloudflareCheckResult>>,
    speedtest_result: &Option<Vec<Speed>>,
    opts: &Opts,
) {
    if let Some(tcping_result) = tcping_result {
        println!("TCP 扫描结果：");
        println!("{:<20} {:<20} {:<10}", "IP", "平均延迟", "丢包率");
        for result in tcping_result.iter().take(opts.display) {
            let loss_rate = 1.0 - (result.success as f64 / opts.time as f64);
            println!(
                "{:<20} {:<20.2}ms {:<10.1}%",
                result.ip,
                result.consume.as_millis(),
                loss_rate * 100.0,
            );
        }
        println!();
    }

    if let Some(httping_result) = httping_result {
        println!("HTTP 路由检查结果：");
        println!("{:<20} {:<20} {:<10}", "IP", "状态码", "区域");
        for result in httping_result.iter().take(opts.display) {
            println!(
                "{:<20} {:<20} {:<10}",
                result.ip_address,
                match result.route_status {
                    routes::CheckRouteStatus::None => {
                        "Normal"
                    }
                    routes::CheckRouteStatus::Diff => {
                        "Diff"
                    }
                    routes::CheckRouteStatus::Empty => {
                        "Empty"
                    }
                },
                result.location_code.as_deref().unwrap_or("N/A"),
            );
        }
        println!();
    }

    if let Some(speedtest_result) = speedtest_result {
        println!("下载测速结果：");
        println!("{:<20} {:<20}", "IP", "平均下载速度");
        for result in speedtest_result.iter().take(opts.display) {
            println!(
                "{:<20} {:<20.2}MB/s",
                result.ip,
                result.total_download as f64 / 1024.0 / 1024.0 / result.consume.as_secs_f64(),
            );
        }
        println!();
    }

    if !valis_ips.is_empty() {
        let mut headers = Vec::new(); // 定义一个存放表头信息的数组
        headers.push("IP".to_owned()); // 添加 IP 表头

        // 如果已经对 IP 进行了 TCP 扫描
        if let Some(tcping_result) = tcping_result {
            headers.push("Loss".to_owned()); // 添加丢包率表头
            headers.push("Delay".to_owned()); // 添加延时表头
        }

        // 如果已经对 IP 进行了 HTTP 路由检查
        if let Some(httping_result) = httping_result {
            headers.push("Status".to_owned()); // 添加状态码表头
            headers.push("Area".to_owned()); // 添加区域表头
        }

        // 如果已经对 IP 进行了下载测速
        if let Some(speedtest_result) = speedtest_result {
            headers.push("Speed".to_owned()); // 添加下载速度表头
        }

        let mut rows = Vec::new(); // 定义一个存放表格数据的数组

        // 遍历 IP 地址
        for ip in valis_ips.iter().take(opts.display) {
            let mut row = Vec::new(); // 定义一行表格数据

            row.push(ip.to_string()); // 添加 IP 地址

            // 如果已经对 IP 进行了 TCP 扫描
            if let Some(tcping_result) = tcping_result {
                // 查找 TCP 测试结果中与当前 IP 相同的记录
                if let Some(record) = tcping_result.iter().find(|r| r.ip == *ip) {
                    let loss_rate = 1.0 - (record.success as f64 / opts.time as f64);
                    row.push(format!("{:.1}%", loss_rate)); // 添加丢包率
                    row.push(format!("{:.2}ms", record.consume.as_millis())); // 添加延时
                } else {
                    row.push("-".to_owned()); // 对应的 TCP 测试结果不存在，使用占位符代替
                    row.push("-".to_owned());
                }
            }

            // 如果已经对 IP 进行了 HTTP 路由检查
            if let Some(httping_result) = httping_result {
                // 查找 HTTP 路由检查结果中与当前 IP 相同的记录
                if let Some(record) = httping_result.iter().find(|r| r.ip_address == *ip) {
                    row.push(match record.route_status {
                        routes::CheckRouteStatus::None => (&"Normal").to_string(),
                        routes::CheckRouteStatus::Diff => (&"Diff").to_string(),
                        routes::CheckRouteStatus::Empty => (&"Empty").to_string(),
                    }); // 添加状态码
                    row.push(record.location_code.clone().unwrap_or("None".to_string()));
                // 添加区域信息
                } else {
                    row.push("-".to_owned()); // 对应的 HTTP 路由检查结果不存在，使用占位符代替
                    row.push("-".to_owned());
                }
            }

            // 如果已经对 IP 进行了下载测速
            if let Some(speedtest_result) = speedtest_result {
                // 查找下载测速结果中与当前 IP 相同的记录
                if let Some(record) = speedtest_result.iter().find(|r| r.ip == *ip) {
                    row.push(format!(
                        "{:.2}MB/s",
                        record.total_download as f64
                            / 1024.0
                            / 1024.0
                            / record.consume.as_secs_f64()
                    )); // 添加平均下载速度
                } else {
                    row.push("-".to_owned()); // 对应的下载测速结果不存在，使用占位符代替
                }
            }

            rows.push(row); // 将一行数据添加到表格数据中
        }

        // 打印表格
        print_table(headers, rows);
    }
}

pub fn print_table(headers: Vec<String>, rows: Vec<Vec<String>>) {
    let num_columns = headers.len();
    let max_widths: Vec<_> = (0..num_columns)
        .map(|col_index| {
            let mut max_width = headers[col_index].len();
            for row in &rows {
                if row[col_index].len() > max_width {
                    max_width = row[col_index].len();
                }
            }
            max_width
        })
        .collect();

    let divider: String = max_widths
        .iter()
        .map(|max_width| "-".repeat(max_width + 2))
        .collect::<Vec<_>>()
        .join("+");

    let header_str: String = headers
        .iter()
        .enumerate()
        .map(|(i, header)| format!("{0:<1$} | ", header, max_widths[i]))
        .collect();

    println!("{}\n| {}|", divider, header_str);

    for row in rows {
        let row_str: String = row
            .into_iter()
            .enumerate()
            .map(|(i, cell)| format!("{0:<1$} | ", cell, max_widths[i]))
            .collect();
        println!("{}\n| {}|", divider, row_str);
    }

    println!("{}", divider);
}

async fn run_downloader(ips: &Vec<IpAddr>, opts: &Opts) -> Vec<Speed> {
    let domain: String = match utils::get_domain_from_url(opts.download_url.as_str()) {
        Ok(h) => h,
        Err(e) => {
            println!("Cannot get host for speed test url;\nError message: {}", e);
            std::process::exit(1);
        }
    };

    // download speed test
    let downloader: Downloader = Downloader::new(
        ips.clone(),
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

async fn run_checker(ips: Vec<IpAddr>, opts: &Opts) -> Vec<CloudflareCheckResult> {
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
            speed_test_ips.len(),
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
            speed_test_ips.len(),
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
