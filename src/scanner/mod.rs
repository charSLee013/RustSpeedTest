use std::{
    cmp::{self, Ordering},
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZeroU8,
    time::{Duration, Instant},
};

use indicatif::{ProgressBar, ProgressStyle};
use tokio::{io::AsyncWriteExt, sync::mpsc};

#[derive(Debug)]
// 扫描基本设置
pub struct Scanner {
    // 测试IP地址集合
    ips: Vec<IpAddr>,
    // 同时测试的最大数量
    batch_size: usize,
    // 同个IP测试的次数
    times: NonZeroU8,
    // 超时设置
    timeout: Duration,
    // 设定端口
    port: u16,
    // 平均延迟上限
    avg_delay_upper: u128,
    // 平均延迟下限
    avg_delay_lower: u128,
}

impl Scanner {
    pub fn new(
        ips: Vec<IpAddr>,
        batch_size: usize,
        timeout: Duration,
        times: u8,
        port: u16,
        avg_delay_upper: u128,
        avg_delay_lower: u128,
    ) -> Self {
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
            avg_delay_upper,
            avg_delay_lower,
        }
    }

    pub async fn run(&self) -> Vec<Delay> {
        // create a channel for sending tasks to the pool
        let (tx, mut rx) = mpsc::channel(self.batch_size);

        let mut res = Vec::new();
        let total = self.ips.len();
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
            )
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );

        let mut ips_iter = self.ips.clone().into_iter();

        for _ in 0..cmp::min(self.ips.len(), self.batch_size) {
            let ip = ips_iter.next().unwrap();
            let tx = tx.clone();
            let socket = SocketAddr::new(ip, self.port);
            let times = self.times;
            let timeout = self.timeout;

            tokio::spawn(async move {
                let delay = Scanner::tcp_socket(times, timeout, socket);
                tx.send(delay.await).await.unwrap();
            });
        }

        for _ in 0..total {
            if let Some(Ok(delay)) = rx.recv().await {
                pb.set_message(format!("Addr: {}", delay.ip));

                let delay_millis = delay.consume.as_millis();
                if delay_millis < self.avg_delay_upper && delay_millis > self.avg_delay_lower {
                    res.push(delay);
                }
            }

            pb.inc(1);
            if let Some(ip) = ips_iter.next() {
                let tx = tx.clone();
                let socket = SocketAddr::new(ip, self.port);
                let times = self.times;
                let timeout = self.timeout;

                tokio::spawn(async move {
                    let delay = Scanner::tcp_socket(times, timeout, socket);
                    tx.send(delay.await).await.unwrap();
                });
            }
        }

        pb.finish_with_message("finshed");

        res
    }

    async fn tcp_socket(
        times: NonZeroU8,
        timeout: Duration,
        socket: SocketAddr,
    ) -> std::io::Result<Delay> {
        let mut total_duration = Duration::new(0, 0);
        let mut successful_calls = 0;

        for _ in 1..=times.get() {
            let start = Instant::now();
            let result = Scanner::connect(timeout, socket).await;
            let elapsed = start.elapsed();

            match result {
                Ok(mut tcp_stream) => {
                    tokio::spawn(async move {
                        match tcp_stream.shutdown().await {
                            _ => {}
                        }
                    });

                    successful_calls += 1;
                    total_duration += elapsed;
                }

                Err(e) => {
                    let error_string = e.to_string();

                    if error_string.to_lowercase().contains("too many open files") {
                        panic!("Too many open files. Please reduce batch size\nPlease try to reduce this value and then try to run again.");
                    }
                }
            }
        }

        Ok(Delay {
            ip: socket.ip(),
            consume: if successful_calls != 0 {
                Duration::from_nanos((total_duration.as_nanos() / successful_calls as u128) as u64)
            } else {
                Duration::from_secs(0)
            },
            success: successful_calls,
        })
    }


    #[inline]
    async fn connect(
        timeout: Duration,
        socket: SocketAddr,
    ) -> tokio::io::Result<tokio::net::TcpStream> {
        let stream = tokio::time::timeout(timeout, async move {
            tokio::net::TcpStream::connect(socket).await
        })
        .await??;
        Ok(stream)
    }
}

#[derive(Debug)]
pub struct Delay {
    /// IP 地址
    pub ip: IpAddr,
    /// 平均延迟
    pub consume: Duration,
    /// 成功次数
    pub success: u8,
}

impl Delay {
    pub fn to_map(delays: Vec<Delay>) -> HashMap<IpAddr, Delay> {
        let mut map = HashMap::new();
        for delay in delays {
            map.insert(delay.ip, delay);
        }
        map
    }
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
            9999,
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

        let scanner = Scanner::new(addrs, 1000, Duration::from_millis(5000), 4, 443, 9999, 0);

        let rt = tokio::runtime::Builder::new_multi_thread().build().unwrap();

        let result = rt.block_on(scanner.run());
        assert!(!result.is_empty());
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
