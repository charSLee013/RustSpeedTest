use async_std::stream::StreamExt;
use reqwest::{Client, ClientBuilder, Url};
use std::{
    cmp::Ordering,
    fmt::{self},
    io::{Error, ErrorKind},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

pub struct Downloader {
    ips: Vec<IpAddr>,
    tries: u8,
    host: String,
    timeout: Duration,
    connect_timeout: Duration,
    port: u16,
    url: String,
}

impl Downloader {
    pub fn new(
        ips: &[IpAddr],
        tries: u8,
        host: String,
        timeout: Duration,
        connect_timeout: Duration,
        port: u16,
        url: String,
    ) -> Self {
        Downloader {
            ips: ips.to_owned(),
            tries,
            host,
            timeout,
            connect_timeout,
            port,
            url,
        }
    }

    pub fn run(&self) -> Vec<Speed> {
        let mut speeds = Vec::new();
        if self.ips.is_empty() {
            println!("No measureable IP addresss");
            return speeds;
        }

        let socket_addrs = self.ips.iter().map(|ip| SocketAddr::new(*ip, self.port));
        let url = self
            .create_url()
            .unwrap_or_else(|_| panic!("Cannot parse url: {}", self.url));

        for socket_addr in socket_addrs {
            for _ in 1..=self.tries {
                match async_std::task::block_on(
                    self.measure_download_speed(socket_addr, url.clone()),
                ) {
                    Ok(speed) => {
                        speeds.push(speed);
                        break;
                    }
                    Err(e) => {
                        println!("Some thing wrong: {}", e);
                    }
                }
            }
        }

        speeds
    }

    pub async fn measure_download_speed(
        &self,
        addr: SocketAddr,
        url: Url,
    ) -> Result<Speed, Box<dyn std::error::Error>> {
        let client = self.create_client().resolve(&self.host, addr).build()?;
        let start_time = Instant::now();
        let response = self.make_request(client, url).await?;
        self.handle_response(response, start_time, addr.ip()).await
    }

    fn create_url(&self) -> Result<Url, url::ParseError> {
        Url::parse(&self.url)
    }

    fn create_client(&self) -> ClientBuilder {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .redirect(reqwest::redirect::Policy::limited(10))
        // .resolve(&self.host, addr)
        // .build()
    }

    async fn make_request(
        &self,
        client: Client,
        url: Url,
    ) -> Result<reqwest::Response, reqwest::Error> {
        client
            .get(url)
            .header(reqwest::header::USER_AGENT, "curl/7.82.0-DEV")
            .send()
            .await
    }

    async fn handle_response(
        &self,
        response: reqwest::Response,
        start_time: Instant,
        ip: IpAddr,
    ) -> Result<Speed, Box<dyn std::error::Error>> {
        if response.status().is_success() {
            //using copy_to_xxx instead of copy_to
            let mut stream = response.bytes_stream();
            let mut bytes_downloaded = 0;
            while let Some(result) = stream.next().await {
                match result {
                    Ok(buffer) => {
                        bytes_downloaded += buffer.len();
                    }
                    Err(e) => {
                        if e.to_string().contains("timed out") {
                            break;
                        }
                        return Err(Box::new(e));
                    }
                }
            }

            let elapsed_time = start_time.elapsed();
            Ok(Speed {
                ip,
                total_download: bytes_downloaded,
                consume: elapsed_time,
            })
        } else {
            Err(Box::new(Error::new(
                ErrorKind::Other,
                format!("Download failed: {:?}", response),
            )))
        }
    }
}

pub struct Speed {
    pub ip: IpAddr,
    pub total_download: usize,
    pub consume: Duration,
}

impl Ord for Speed {
    fn cmp(&self, other: &Self) -> Ordering {
        other.total_download.cmp(&self.total_download)
    }
}

impl PartialOrd for Speed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Speed {
    fn eq(&self, other: &Self) -> bool {
        self.consume == other.consume
            && self.total_download == other.total_download
            && self.ip == other.ip
    }
}

impl Eq for Speed {}

impl fmt::Display for Speed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IP: {}\t Download Speed: {}",
            self.ip,
            super::utils::human_readable_size(
                (self.total_download / self.consume.as_secs() as usize) as f64
            )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_create_url() {
        let downloader = Downloader {
            ips: Vec::new(),
            tries: 3,
            host: "www.example.com".to_string(),
            timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            port: 80,
            url: "https://www.example.com/test".to_string(),
        };

        let url = downloader.create_url();
        assert!(url.is_ok());
        assert_eq!(url.unwrap().as_str(), "https://www.example.com/test");
    }
}
