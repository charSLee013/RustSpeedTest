use async_std::{task::block_on, stream::StreamExt};
use reqwest::{Client, Url};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub struct Downloader {
    ips: Vec<IpAddr>,
    tries: u8,
    host: String,
    timeout: Duration,
    buffsize: usize,
    port: u16,
    path: String,
}

impl Downloader {
    pub async fn measure_download_speed(
        &self,
        url: &str,
        ip: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let addr: SocketAddr = format!("{}:{}", ip, self.port).parse().unwrap();

        let url = Url::parse(url)?;

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(self.timeout)
            .connect_timeout(Duration::from_millis(5000))
            .redirect(reqwest::redirect::Policy::limited(10))
            .resolve(&self.host, addr)
            .build()?;

        let start_time = Instant::now();
        let response = client
            .get(url)
            .header(reqwest::header::USER_AGENT, "curl/7.82.0-DEV")
            .send()
            .await?;
        

        if response.status().is_success() {
            println!(
                "Your set IP:{} <=> request remote addr: {}",
                ip,
                response.remote_addr().unwrap().ip()
            );

            //using copy_to_xxx instead of copy_to
            let mut stream = response.bytes_stream();
            let mut bytes_downloaded = 0;
            while let Some(chunk) = stream.next().await {
                if let Ok(buffer) = chunk{
                    bytes_downloaded+=buffer.len();
                }
            }

            let elapsed_time = start_time.elapsed();
            let total_download_f64 = bytes_downloaded as f64;
            let bytes_per_sec = total_download_f64 / elapsed_time.as_secs_f64();
            println!(
                "Download speed: {}/s",
                self.human_readable_size(bytes_per_sec)
            );

            println!(
                "Total Download size: {})",
                self.human_readable_size(total_download_f64)
            );
        } else {
            println!("Download failed: {:?}", response);
        }

        Ok(())
    }

    fn human_readable_size(&self, size: f64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
        let mut size = size;
        let mut idx = 0;
        while size > 1024.0 {
            size /= 1024.0;
            idx += 1;
        }
        format!("{:.2} {}", size, units[idx])
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::executor::block_on;

    use super::Downloader;

    #[test]
    fn test_download_file() {
        let downloader = Downloader {
            ips: vec![],
            tries: 4,
            host: String::from("cf-speedtest.hollc.cn"),
            timeout: Duration::from_secs(5),
            buffsize: 4096,
            port: 443,
            path: String::from("/1gb.test"),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        if let Err(e) = rt.block_on(
            downloader
                .measure_download_speed("https://cf-speedtest.hollc.cn/1gb.test", "104.22.78.54"),
        ) {
            panic!("Error: {}", e);
        }

        // if let Err(e) = downloader.download_file(&downloader.host, &String::from("104.21.33.129")) {
        //     println!("Error: {}", e);
        // }
    }
}
