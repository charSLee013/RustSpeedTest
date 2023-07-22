use std::{cmp, net::IpAddr, time::Duration};

use async_std::{io, net::TcpStream};
use futures::{stream::FuturesUnordered, AsyncReadExt, AsyncWriteExt, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use rand::seq::SliceRandom;

#[derive(Debug, PartialEq)]
pub struct HttpingChecker<'a> {
    // ips: Vec<IpAddr>,          // List of IP addresses to check
    tries_per_ip: u8,          // Number of times to check each IP address
    request_timeout: Duration, // HTTP request timeout
    request_port: u16,         // HTTP request port
    batch_size: usize,         // Batch size for concurrent requests
    headers: &'a str,          // custom http header
}

const USER_AGENTS: [&str; 5] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/16.16299",
];

const REQUEST_TEMPLATE: &str = "GET / HTTP/1.1\r\n\
                                Accept: */*\r\n\
                                Connection: close\r\n\
                                Host: {}\r\n
                                User-Agent: {}\r\n\
                                {}\r\n\r\n";

impl<'a> HttpingChecker<'a> {
    pub fn new(
        // ips_to_check: Vec<IpAddr>,
        tries_per_ip: u8,
        request_timeout: Duration,
        request_port: u16,
        batch_size: usize,
        headers: &'a str,
    ) -> Self {
        HttpingChecker {
            // ips: ips_to_check,
            tries_per_ip,
            request_timeout,
            request_port,
            batch_size,
            headers,
        }
    }

    pub async fn run(&self, ips: Vec<IpAddr>) -> Vec<HttpingResult> {
        let mut valid_result = Vec::new();

        // use async-std
        let mut ftrs = FuturesUnordered::new();

        // let (tx, mut rx) = mpsc::channel(self.batch_size);
        let total = ips.len();
        let mut ips_iter = ips.into_iter();

        // process bar
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
            )
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );

        // Concurrently check the routes of IP addresses
        for _ in 0..cmp::min(self.batch_size, total) {
            if let Some(ip) = ips_iter.next() {
                ftrs.push(self.spawn_checker_task(ip.to_owned()));
            }
        }

        let mut good: usize = 0;
        let mut bad: usize = 0;
        while let Some(result) = ftrs.next().await {
            if result.valid {
                good += 1;
                valid_result.push(result);
                pb.inc(1);
            } else {
                bad += 1;
                pb.inc(1);
            }
            if let Some(ip_address) = ips_iter.next() {
                ftrs.push(self.spawn_checker_task(ip_address.to_owned()));
            }
        }

        pb.finish_with_message("finished");

        // summary all http status
        println!(
            "total: {} \t good: {} \t bad: {}",
            valid_result.len(),
            good,
            bad
        );

        valid_result
    }

    async fn connect_with_retry(&self, addr: &str) -> Option<TcpStream> {
        for _ in 1..=self.tries_per_ip {
            if let Ok(stream) = self.tcp_connect(addr).await {
                return Some(stream);
            }
        }
        None
    }

    #[inline]
    async fn spawn_checker_task(&'a self, ip_address: IpAddr) -> HttpingResult {
        let address = format!("{}:{}", &ip_address, &self.request_port);
        let mut http_result = HttpingResult {
            ip: ip_address,
            valid: false,
        };

        // try to connect to the host
        let mut stream = match self.connect_with_retry(&address).await {
            Some(tcp_stream) => tcp_stream,
            None => {
                return http_result;
            }
        };

        // Send HTTP GET request
        let user_agent = USER_AGENTS.choose(&mut rand::thread_rng()).unwrap();
        let request = REQUEST_TEMPLATE
            .replace("{}", &ip_address.to_string())
            .replace("{}", user_agent)
            .replace("{}", self.headers);

        if self
            .write_with_timeout(&mut stream, request.as_bytes())
            .await
            .is_err()
        {
            return http_result;
        }

        // Read HTTP response
        let mut buf = Vec::with_capacity(1024);
        if self.read_with_timeout(&mut stream, &mut buf).await.is_err() {
            return http_result;
        }

        // Shutdown TCP stream
        match stream.shutdown(std::net::Shutdown::Both) {
            Ok(_) => (),
            Err(_) => (),
        } 

        // Check if the server returned a valid HTTP response
        let response = String::from_utf8_lossy(&buf);
        if response.starts_with("HTTP/1.") {
            http_result.valid = true;
        }

        http_result
    }

    #[inline]
    async fn write_with_timeout(&self, stream: &mut TcpStream, buf: &[u8]) -> io::Result<()> {
        tokio::time::timeout(
            self.request_timeout,
            async move { stream.write_all(buf).await },
        )
        .await??;
        Ok(())
    }

    #[inline]
    async fn read_with_timeout(
        &self,
        stream: &mut TcpStream,
        buf: &mut Vec<u8>,
    ) -> io::Result<usize> {
        tokio::time::timeout(self.request_timeout, async move {
            stream.read_to_end(buf).await
        })
        .await?
    }

    #[inline]
    async fn tcp_connect(&self, address: &str) -> io::Result<TcpStream> {
        let stream = io::timeout(self.request_timeout, async move {
            TcpStream::connect(address).await
        })
        .await?;
        Ok(stream)
    }
}

#[derive(Clone)]
pub struct HttpingResult {
    pub ip: IpAddr, // IP address
    pub valid: bool,
}
