use std::{
    cmp::{min, max},
    collections::HashSet,
    fmt::Write,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    os::fd::AsRawFd,
    time::Duration,
};

use indicatif::{HumanDuration, ProgressBar, ProgressState, ProgressStyle};
use io_uring::{types::Timespec, IoUring, Probe};
use ipnet::Ipv4Net;
use iprange::IpRange;
use nix::sys::{resource, socket::SockaddrIn};
use rand::seq::index::sample;

use crate::{
    input::Opts,
    scan_iouring::{can_push, http::ScanHttp, tcp::ScanTcpConnect, Scan},
};

mod input;
mod new_utils;
mod ring;
mod scan_iouring;

fn main() -> io::Result<()> {
    // 初始化日志
    #[cfg(not(debug_assertions))]
    simple_logger::init_with_env().expect("Failed to init logger");

    #[cfg(debug_assertions)]
    // only warn on debug model
    simple_logger::init_with_level(log::Level::Warn).unwrap();

    // 接收参数
    let mut opts: Opts = Opts::read();
    log::trace!("command line: {:?}", opts);

    // 并发数必须是2的倍数
    if opts.number < 2 {
        opts.number = 2;
    }


    // 增加打开文件数限制
    let (soft_limit, hard_limit) = resource::getrlimit(resource::Resource::RLIMIT_NOFILE)?;
    resource::setrlimit(resource::Resource::RLIMIT_NOFILE, hard_limit, hard_limit)?;
    log::info!("Bumped RLIMIT_NOFILE from {soft_limit} to {hard_limit}");

    // 创建一个 ring buffer
    let mut iorings = IoUring::new(16384)?;

    // 根据命令行参数选择对应的扫描类型
    let mut scan: Box<dyn Scan> = match &opts.scan_opts {
        input::ScanOptions::Http(scan_opts) => Box::new(ScanHttp::new(scan_opts)),
        input::ScanOptions::Tcp(_) => Box::new(ScanTcpConnect::new()),
    };

    // 创建 Probe 并检查所选的扫描类型是否支持 io_uring 提供的操作
    let mut probe: Probe = Probe::new();
    iorings.submitter().register_probe(&mut probe)?;
    scan.check_supported(&probe);

    // 初始化 RingAllocator 以跟踪 ring buffer 的状态
    let mut ring_allocator = ring::RingAllocator::new(
        min(opts.number.next_power_of_two(),16384/scan.ops_per_ip()) * scan.ops_per_ip(), // 操作所需条目数*并发数 或者是 16384/操作所需条目数
        32,
        scan.max_tx_size(),
        &iorings.submitter(),
    );

    // 生成将要扫描的 IP 列表，并为每个 IP 地址创建 SockaddrIn 结构表示地址
    // ip_ranges 是收集全部的 CIDRs 后再生成新的 CIDRs，顺便去重了
    // let ip_range: IpRange<Ipv4Net> = ["173.245.48.0/20"]
    //     .iter()
    //     .map(|s| s.parse().unwrap())
    //     .collect();

    let ips = parse_addresses_from_opt(&opts);
    let total = ips.len() * opts.time as usize;
    // // 将IpAddr 转成 Ipv4Addr 迭代器 
    // let mut ip_iter = ips.into_iter().filter_map(|ip| {
    //     if let IpAddr::V4(ipv4_addr) = ip {
    //         Some(ipv4_addr)
    //     } else {
    //         None
    //     }
    // });

    // let mut total = 0;
    // for ip in ip_range.iter().flat_map(|r| r.hosts()) {
    //     // println!("{}", ip);
    //     total += 1;
    // }

    println!("All hosts num {}", total);
    // let mut ip_iter = ip_range.iter().flat_map(|r| r.hosts());

    let progress = ProgressBar::new(total as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template(
                "Scanning IPs {msg} {wide_bar} {pos}/{len} ({smoothed_per_sec}) ETA {smoothed_eta}",
            )
            .unwrap()
            .with_key(
                "smoothed_eta",
                |s: &ProgressState, w: &mut dyn Write| match (s.pos(), s.len()) {
                    (pos, Some(len)) => write!(
                        w,
                        "{:#}",
                        HumanDuration(Duration::from_millis(
                            (s.elapsed().as_millis() * (len as u128 - pos as u128) / (pos as u128))
                                as u64
                        ))
                    )
                    .unwrap(),
                    _ => write!(w, "-").unwrap(),
                },
            )
            .with_key(
                "smoothed_per_sec",
                |s: &ProgressState, w: &mut dyn Write| match (s.pos(), s.elapsed().as_millis()) {
                    (pos, elapsed_ms) if elapsed_ms > 0 => {
                        write!(w, "{:.2}/s", pos as f64 * 1000_f64 / elapsed_ms as f64).unwrap()
                    }
                    _ => write!(w, "-").unwrap(),
                },
            ),
    );

    // 创建超时选项
    let timeouts = scan_iouring::Timeouts {
        connect: Timespec::new().sec(max(opts.timeout/1000,1)),
        read: Timespec::new().sec(max(opts.timeout/1000,1)),
        write: Timespec::new().sec(max(opts.timeout/1000,1)),
    };

    // 循环次数
    for _ in 0..max(opts.time, 1) {
    // 将IpAddr 转成 Ipv4Addr 迭代器 
    let mut ip_iter_inter =ips.clone().into_iter().filter_map(|ip| {
        if let IpAddr::V4(ipv4_addr) = ip {
            Some(ipv4_addr)
        } else {
            None
        }
    });

        let mut done = false;
        // 进入 while 循环，只要 done 标志为 false，则继续循环。
        while !done {
            // 内部 while 循环中调用 `can_push` 函数，
            // 该函数用于检查 Ring Buffer 是否可以推入下一个操作，而不会阻塞。如果可以，则执行以下操作。
            while can_push(&iorings.submission(), &*scan, &ring_allocator) {
                // 调用 `ip_iter.next()` 从 IP 地址列表中获取下一个地址，
                if let Some(ip_addr) = ip_iter_inter.next() {
                    // 使用 SockaddrIn 结构体表示该 IP 地址和端口，
                    let addr: SockaddrIn =
                        SockaddrIn::from(SocketAddrV4::new(ip_addr, opts.port));
                    // 调用 `scan.socket()` 获取一个 socket 对象。
                    let sckt = scan.socket();
                    // 记录 socket id，用于调试。
                    log::trace!("New socket: {}", sckt);

                    // 执行 `scan.push_scan_ops` 方法，将 socket 和 SockaddrIn 对象推入 Ring Buffer 中，
                    // 并设置超时选项，该方法在添加操作时可能会阻塞。
                    scan.push_scan_ops(
                        sckt.as_raw_fd(),
                        &addr,
                        &mut iorings.submission(),
                        &mut ring_allocator,
                        &timeouts,
                    )
                    .expect("Failed to push ring ops");
                    // 如果没有已经分配的空间，即整个Ring Buffer 都是空的
                    // 则将 `done` 标志设置为 true，然后跳出内部 while 循环。

                    // 比较激进的提交任务到内核
                    iorings.submit().unwrap();
                } else if ring_allocator.allocated_entry_count() == 0 {
                    done = true;
                    break;
                } else {
                    break;
                }
            }

            // 记录已经完成的操作数。
            let completed_count = iorings.completion().len();
            // log::debug!("Completed count before wait: {completed_count}");

            // // 调用 `iorings.submit_and_wait` 将 Ring Buffer 中未完成的事件提交到内核，
            // // 并阻塞等待至少一个完成事件。
            // iorings.submit_and_wait(min(
            //     opts.ring_batch_size,
            //     ring_allocator.allocated_entry_count() - completed_count,
            // ))?;

            // 阻塞等待至少一个完成事件或者没有事件可以退出了
            iorings.submit_and_wait(min(
                1,
                ring_allocator.allocated_entry_count() - completed_count,
            ))?;

            // 输出当前完成任务数量。
            log::debug!("Completed count after wait: {}", iorings.completion().len());

            // 遍历完成的事件，调用 `scan.process_completed_entry` 处理完成的事件并更新进度条。
            for ce in iorings.completion() {
                // 调用 `ring_allocator.get_entry` 函数获取相关的扫描项，
                let entry: &ring::EntryInfo = ring_allocator.get_entry(ce.user_data()).unwrap();
                // 调用 `scan.process_completed_entry` 处理完成的事件并更新进度条。
                if scan.process_completed_entry(&ce, entry, &ring_allocator) {
                    progress.inc(1);
                }
                // 调用 `ring_allocator.free_entry` 释放扫描项。
                ring_allocator.free_entry(ce.user_data());
            }
        }
    }
    
    progress.finish();

    Ok(())
}

// 从配置选项中解析CIDR或者IP地址或者IP文件
fn parse_addresses_from_opt(opts: &Opts) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for arg in opts.address.iter() {
        let content: String = match std::fs::read_to_string(arg) {
            Ok(text) => text,
            Err(_) => arg.to_string(),
        };
        let parse_ips = new_utils::parse_addresses(&content);
        ips.extend(parse_ips.iter());
    }

    // 去重
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
    use super::*;

    #[test]
    fn test_parse_addresses_from_opt() {
        let mut opts = Opts::default();
        opts.random_number = 0;
        opts.address = vec!["192.168.1.1/24".to_string(), "192.168.1.1/28".to_string()];

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
