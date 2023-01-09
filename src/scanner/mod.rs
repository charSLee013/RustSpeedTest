use std::{
    cmp::Ordering,
    fmt,
    num::NonZeroU8,
    time::{Duration, Instant},
};

use async_std::io;
use async_std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use async_std::prelude::*;
use futures::stream::FuturesUnordered;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug)]
// 扫描基本设置
pub struct Scanner {
    // 测试IP地址集合
    ips: Vec<IpAddr>,
    // 同时测试的最大数量
    batch_size: u16,
    // 同个IP测试的次数
    times: NonZeroU8,
    // 超时设置
    timeout: Duration,
    // 设定端口
    port: u16,
}

impl Scanner {
    pub fn new(ips: Vec<IpAddr>, batch_size: u16, timeout: Duration, times: u8, port: u16) -> Self {
        let batch_size = if batch_size == 0 { 1 } else { batch_size };

        let times = if times == 0 { 1 } else { times };

        let port = if port == 0 { 80 } else { port };

        let timeout = if timeout.as_nanos() == 0 {
            Duration::from_millis(10)
        } else {
            timeout
        };

        Self {
            ips,
            batch_size,
            timeout,
            times: NonZeroU8::new(times).unwrap_or(NonZeroU8::new(1).unwrap()),
            port,
        }
    }

    pub async fn run(&self) -> Vec<Delay> {
        // 创建socketAddr的迭代器
        let mut socket_addrs = self.ips.iter().map(|ip| SocketAddr::new(*ip, self.port));

        let mut res: Vec<Delay> = Vec::new();
        let mut ftrs = FuturesUnordered::new();

        // 这里创建连接池的大小为 batch_size
        for _ in 0..self.batch_size {
            if let Some(socket) = socket_addrs.next() {
                ftrs.push(self.tcp_socket(socket));
            }
        }

        // 进度条
        let total = self.ips.len();
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
            )
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );

        // 只有连接池有空余才塞入任务
        while let Some(result) = ftrs.next().await {
            if let Some(socket) = socket_addrs.next() {
                ftrs.push(self.tcp_socket(socket));
            }

            match result {
                Ok(delay) => {
                    pb.set_message(format!("Addr: {}", delay.ip));
                    pb.inc(1);

                    res.push(delay);
                }
                Err(_) => {
                    pb.inc(1);
                }
            }
        }
        pb.finish_with_message("finshed");

        res
    }

    async fn tcp_socket(&self, socket: SocketAddr) -> std::io::Result<Delay> {
        let mut total_duration = Duration::new(0, 0);
        let mut successful_calls = 0;
        let times = self.times.get();

        for _ in 1..=times {
            let start = Instant::now();
            let result = self.connect(socket).await;
            let elapsed = start.elapsed();

            match result {
                Ok(tcp_stream) => {
                    let _ = tcp_stream.shutdown(Shutdown::Both);

                    successful_calls += 1;
                    total_duration += elapsed;
                }

                Err(e) => {
                    let error_string = e.to_string();

                    if error_string.to_lowercase().contains("too many open files") {
                        panic!("Too many open files. Please reduce batch size.The current size is {}\nPlease try to reduce this value and then try to run again.",self.batch_size);
                    }
                }
            }
        }

        Ok(Delay {
            ip: socket.ip(),
            consume: total_duration,
            success: successful_calls,
        })
    }

    async fn connect(&self, socket: SocketAddr) -> io::Result<TcpStream> {
        let stream = io::timeout(
            self.timeout,
            async move { TcpStream::connect(socket).await },
        )
        .await?;
        Ok(stream)
    }
}

#[derive(Debug)]
pub struct Delay {
    pub ip: IpAddr,
    pub consume: Duration,
    pub success: i32,
}

impl Ord for Delay {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.success == 0 {
            return Ordering::Greater;
        }

        if self.success > other.success {
            return Ordering::Less;
        }

        (self.consume.as_nanos() / self.success as u128)
            .cmp(&(other.consume.as_nanos() / other.success as u128))
    }
}

impl PartialOrd for Delay {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Delay {
    fn eq(&self, other: &Self) -> bool {
        self.consume == other.consume && self.success == other.success && self.ip == other.ip
    }
}

impl Eq for Delay {}

impl std::fmt::Display for Delay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IP:{:>15} {:>10.6}ms {:>5} success",
            self.ip,
            self.consume.as_millis(),
            self.success
        )
    }
}

#[cfg(test)]
mod test {
    use std::{net::IpAddr, num::NonZeroU8, str::FromStr, time::Duration};

    use async_std::task::block_on;

    // use crate::scanner::sort_delays;

    use super::{Delay, Scanner};

    #[test]
    fn test_config() {
        let scan = Scanner::new(
            vec!["192.168.1.1".parse().unwrap()],
            0,
            Duration::from_nanos(0),
            0,
            0,
        );

        assert!(scan.batch_size > 0);
        assert!(scan.timeout.as_nanos() > 0);
        assert_eq!(scan.times, NonZeroU8::new(1).unwrap());
        assert!(scan.port > 0);
    }

    #[test]
    fn scanner_run() {
        // Makes sure the network is available
        let addrs = vec![IpAddr::from_str("1.1.1.1").unwrap()];

        let scanner = Scanner::new(addrs, 1000, Duration::from_millis(5000), 4, 443);
        let result = block_on(scanner.run());
        // let result = sort_delays(result);
        assert!(!result.is_empty());

        // display top 10
        for delay in result.into_iter().take(10) {
            println!(
                "IP:{}\t consume:{} \t success: {}",
                delay.ip.to_string(),
                delay.consume.as_millis(),
                delay.success
            );
        }
    }

    #[test]
    fn test_delay_sort() {
        let delay1 = Delay {
            ip: "127.0.0.1".parse().unwrap(),
            consume: Duration::from_secs(1),
            success: 0,
        };

        let delay2 = Delay {
            ip: "127.0.0.2".parse().unwrap(),
            consume: Duration::from_secs(2),
            success: 1,
        };

        let delay3 = Delay {
            ip: "127.0.0.3".parse().unwrap(),
            consume: Duration::from_secs(3),
            success: 2,
        };

        let delay4 = Delay {
            ip: "127.0.0.4".parse().unwrap(),
            consume: Duration::from_secs(5),
            success: 2,
        };

        let mut delays = vec![&delay1, &delay2, &delay3, &delay4];
        delays.sort();
        assert!(delays[0].eq(&delay3));
        assert!(delays[1].eq(&delay4));
        assert!(delays[2].eq(&delay2));
        assert!(delays[3].eq(&delay1));
    }
}
