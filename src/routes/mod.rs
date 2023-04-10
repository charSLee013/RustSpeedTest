use std::net::IpAddr;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

/// Checker struct, used to check the Cloudflare CDN IP routes
pub struct CloudflareChecker {
    ips_to_check: Vec<IpAddr>, // List of IP addresses to check
    tries_per_ip: u64,         // Number of times to check each IP address
    request_timeout: Duration, // HTTP request timeout
    request_port: u16,         // HTTP request port
    batch_size: usize,         // Batch size for concurrent requests
}

impl CloudflareChecker {
    /// Create a new CloudflareChecker instance
    #[inline]
    pub fn new(
        ips_to_check: Vec<IpAddr>,
        tries_per_ip: u64,
        request_timeout: Duration,
        request_port: u16,
        batch_size: usize,
    ) -> Self {
        CloudflareChecker {
            ips_to_check,
            tries_per_ip,
            request_timeout,
            request_port,
            batch_size,
        }
    }

    /// Check if the Cloudflare CDN IP's location code is consistent across multiple HTTP requests
    pub async fn check_routes(&self) -> Vec<CloudflareCheckResult> {
        let mut valid_result = Vec::new();
        let (tx, mut rx) = mpsc::channel(self.batch_size);
        let total = self.ips_to_check.len();
        let mut ips_iter = self.ips_to_check.clone().into_iter();

        // process bar
        let total = total;
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
            )
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );

        // Concurrently check the routes of IP addresses
        for _ in 0..std::cmp::min(total, self.batch_size) {
            let ip_address = ips_iter.next().unwrap();
            let tx = tx.clone();
            let tries_per_ip = self.tries_per_ip;
            let request_port = self.request_port;
            let request_timeout = self.request_timeout;

            tokio::spawn(async move {
                let check_result = CloudflareChecker::check_cloudflare_routes(
                    ip_address,
                    tries_per_ip,
                    request_port,
                    request_timeout,
                )
                .await;
                tx.send(check_result).await.unwrap();
            });
        }

        let mut iter_empty = false;

        let mut empty: usize = 0;
        let mut diff: usize = 0;
        // Handle the check results
        for _ in 0..total {
            if let Some(ip_status) = rx.recv().await {
                match ip_status.route_status {
                    CheckRouteStatus::None => {
                        pb.set_message(format!("Addr: {}", ip_status.ip_address));
                        valid_result.push(ip_status);
                    }
                    CheckRouteStatus::Diff => {
                        diff += 1;
                    }
                    CheckRouteStatus::Empty => {
                        empty += 1;
                    }
                }
            }
            pb.inc(1);

            if let Some(ip_address) = ips_iter.next() {
                let tx = tx.clone();
                let tries_per_ip = self.tries_per_ip;
                let request_port = self.request_port;
                let request_timeout = self.request_timeout;

                tokio::spawn(async move {
                    let check_result = CloudflareChecker::check_cloudflare_routes(
                        ip_address,
                        tries_per_ip,
                        request_port,
                        request_timeout,
                    )
                    .await;
                    tx.send(check_result).await.unwrap();
                });
            } else {
                if !iter_empty {
                    println!("All task push in queue");
                    iter_empty = true;
                }
            }
        }
        pb.finish_with_message("finshed");

        // summary all ip routes status
        println!(
            "vaild: {} \t empty: {} \t diff: {}",
            valid_result.len(),
            empty,
            diff
        );

        valid_result
    }

    /// Check the route of a specified IP address
    async fn check_cloudflare_routes(
        ip_address: IpAddr,
        tries_per_ip: u64,
        request_port: u16,
        request_timeout: Duration,
    ) -> CloudflareCheckResult {
        let mut result = CloudflareCheckResult {
            ip_address: ip_address,
            route_status: CheckRouteStatus::None,
            location_code:None,
        };
        let mut location_code = String::new();
        let mut count = 0;

        // Check the route information of the IP address multiple times to get a stable result
        for _ in 0..tries_per_ip {
            count += 1;
            if let Some(code) =
                CloudflareChecker::get_location_code(&ip_address, request_port, request_timeout)
                    .await
            {
                location_code = code;
                break;
            }
        }

        if location_code.is_empty() {
            result.route_status = CheckRouteStatus::Empty;
            // println!("{} cannot get location code", ip_address);
            return result;
        } else {
            result.location_code = Some(location_code.clone()); // 更新地区码
        }

        // Check the route information of the IP address again to ensure the accuracy of the result
        for _ in count..tries_per_ip {
            if let Some(code) =
                CloudflareChecker::get_location_code(&ip_address, request_port, request_timeout)
                    .await
            {
                if code != location_code {
                    // println!(
                    //     "{} has different location code by {} and {}",
                    //     ip_address, location_code, code
                    // );
                    result.route_status = CheckRouteStatus::Diff;
                    return result;
                }
            }
        }
        result
    }

    #[inline]
    async fn tcp_connect(address: String, request_timeout: Duration) -> io::Result<TcpStream> {
        let stream =
            tokio::time::timeout(
                request_timeout,
                async move { TcpStream::connect(address).await },
            )
            .await??;
        Ok(stream)
    }

    #[inline]
    async fn write_with_timeout(
        stream: &mut TcpStream,
        buf: &[u8],
        timeout: Duration,
    ) -> io::Result<()> {
        tokio::time::timeout(timeout, async move { stream.write_all(buf).await }).await??;
        Ok(())
    }

    #[inline]
    async fn read_with_timeout(
        stream: &mut TcpStream,
        buf: &mut [u8],
        timeout: Duration,
    ) -> io::Result<usize> {
        let fut = tokio::time::timeout(timeout, async move { stream.read(buf).await }).await?;
        fut
    }

    /// Get the route information of a specified IP address
    async fn get_location_code(
        ip_address: &IpAddr,
        request_port: u16,
        request_timeout: Duration,
    ) -> Option<String> {
        let address = format!("{}:{}", ip_address, request_port);
        // Connect to host:80
        let mut stream = match CloudflareChecker::tcp_connect(address, request_timeout).await {
            Ok(stream) => stream,
            Err(_) => {
                return None;
            }
        };
        // Write an HTTP GET request
        if let Err(_) = CloudflareChecker::write_with_timeout(
            &mut stream,
            format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                ip_address
            )
            .as_bytes(),
            request_timeout,
        )
        .await
        {
            return None;
        }
        // Read the response from the stream into a buffer
        let mut buffer = [0; 1024];
        if let Err(_) =
            CloudflareChecker::read_with_timeout(&mut stream, &mut buffer, request_timeout).await
        {
            return None;
        }
        // shutdown tcpStream
        tokio::spawn(async move {
            match stream.shutdown().await {
                _ => {}
            }
        });
        // Convert the buffer into a string
        let response = String::from_utf8_lossy(&buffer);
        // Split the response into lines
        let lines: Vec<&str> = response.split("\r\n").collect();
        // Find the line that starts with CF-ray header
        let cf_ray_line = if let Some(line) = lines.iter().find(|line| line.starts_with("CF-RAY")) {
            line
        } else {
            return None;
        };

        // Get the last three letters of the CF-ray value as the location code
        let location_code = &cf_ray_line[cf_ray_line.len() - 3..];
        // Return the location code as a String
        return Some(location_code.to_string());
    }
}

/// CloudflareCheckResult struct, used to represent the check result of an IP address routeed
#[derive(Debug)]
pub struct CloudflareCheckResult {
    pub ip_address: IpAddr,             // IP address
    pub route_status: CheckRouteStatus, // Whether the route is consistent
    pub location_code: Option<String>, 
}


#[derive(Debug, PartialEq)]
pub enum CheckRouteStatus {
    /// normal
    None,
    /// get not any location code
    Empty,
    /// get diff location code
    Diff,
}

#[cfg(test)]
mod tests {
    use tokio::time;

    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_check_cloudflare_routes_ipv4() {
        let ip_v4 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        let check_result_v4 =
            CloudflareChecker::check_cloudflare_routes(ip_v4, 2, 80, Duration::from_secs(5)).await;
        assert_eq!(check_result_v4.ip_address, ip_v4);
        assert_eq!(check_result_v4.route_status,CheckRouteStatus::None);
    }

    #[tokio::test]
    async fn test_get_location_code_ipv4() {
        let ip_v4 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        let location_code_v4 =
            CloudflareChecker::get_location_code(&ip_v4, 80, Duration::from_secs(5)).await;
        assert!(location_code_v4.is_some());
    }

    #[tokio::test]
    async fn test_check_routes_single_ip() {
        let ips_to_check = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];

        let checker = CloudflareChecker::new(ips_to_check, 2, Duration::from_secs(5), 80, 10);

        let valid_ips = checker.check_routes().await;
        assert_eq!(valid_ips.len(), 1);
    }

    #[tokio::test]
    async fn test_check_routes_multiple_ips() {
        let ips_to_check = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
        ];

        let checker = CloudflareChecker::new(ips_to_check, 2, Duration::from_secs(5), 80, 10);

        let valid_ips = checker.check_routes().await;
        assert_eq!(valid_ips.len(), 1);
    }

    #[tokio::test]
    async fn test_timeout() {
        // Create a future that will complete after 2 seconds
        let long_running_future = async {
            time::sleep(Duration::from_secs(2)).await;
            "completed"
        };

        // Wrap the future in a timeout of 1 second
        let result = time::timeout(Duration::from_secs(1), long_running_future).await;

        // Check that the future timed out
        assert!(result.is_err());
    }
}
