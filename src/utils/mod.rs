use cidr_utils::cidr::IpCidr;

use std::error::Error;

use std::fs;
use std::io::BufRead;
use std::{io, net::IpAddr};

use crate::download::Speed;
use crate::input::Opts;
use crate::routes::{CloudflareCheckResult, self};
use crate::scanner::Delay;

/// 根据字符串解析成ip 地址
pub fn parse_addresses(ips_str: &str) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    let reader = io::Cursor::new(ips_str.as_bytes());

    reader.lines().map(|r| r.unwrap()).for_each(|line| {
        IpCidr::from_str(line)
            .map(|cidr| ips.extend(cidr.iter_as_ip_addr()))
            .ok();
    });
    ips
}

pub fn write_to_csv(
    valis_ips: &[IpAddr],
    tcping_result: Option<Vec<Delay>>,
    httping_result: Option<Vec<CloudflareCheckResult>>,
    speedtest_result: Option<Vec<Speed>>,
    opts: &Opts,
) -> Result<(), Box<dyn Error>> {
    let mut csv = String::new();
    let mut titel = String::with_capacity(200);
    titel.push_str("IP");

    // tcp 测速标题
    if tcping_result.is_some() {
        titel.push_str(",Loss,Delay(ms)");
    }
    if httping_result.is_some() {
        titel.push_str(",Status,Area");
    }

    if speedtest_result.is_some() {
        titel.push_str(",Speed(MB/s)");
    }
    titel.push('\n');

    // add title
    csv.push_str(&titel);

    let tcping_map = if tcping_result.is_some(){
        Some(Delay::to_map(tcping_result.unwrap_or(vec![])))
    } else {
        None
    };

    let httping_map = if httping_result.is_some(){
        Some(CloudflareCheckResult::to_map(httping_result.unwrap_or(vec![])))
    } else {
        None
    };

    let speed_map = if speedtest_result.is_some(){
        Some(Speed::to_map(speedtest_result.unwrap_or(vec![])))
    } else {
        None
    };

    // push data to csv
    for ip in valis_ips.iter(){
        let mut line = String::with_capacity(1024);
        line.push_str(&ip.to_string());

        // push tcp result
        if let Some(ref record) = tcping_map{
            if record.contains_key(ip){
                let value = record.get(ip).unwrap();
                let loss_rate = 1.0 - (value.success as f64 / opts.time as f64);
                line.push_str(&format!(",{:.1},{:.2}", loss_rate,value.consume.as_millis()));
            }
        }

        // push http result
        if let Some(ref recrod) = httping_map{
            if recrod.contains_key(ip){
                let value = recrod.get(ip).unwrap();
                line.push_str(match value.route_status {
                    routes::CheckRouteStatus::None => ",Normal,",
                    routes::CheckRouteStatus::Diff => ",Diff,",
                    routes::CheckRouteStatus::Empty => ",Empty,",
                });
                line.push_str(&value.location_code.clone());
            }
        }

        if let Some(ref record) = speed_map{
            if record.contains_key(ip){
                let value = record.get(ip).unwrap();
                line.push_str(&format!(
                    ",{:.2}",
                    value.total_download as f64
                        / 1024.0
                        / 1024.0
                        / value.consume.as_secs_f64()
                ));
            }
        }
        line.push('\n');
        csv.push_str(&line);
    }

    fs::write(&opts.output, csv)?;
    Ok(())
}

pub fn human_readable_size(size: f64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    let mut size = size;
    let mut idx = 0;
    while size >= 1024.0 {
        size /= 1024.0;
        idx += 1;
    }
    format!("{:.2} {}", size, units[idx])
}

pub fn get_domain_from_url(input: &str) -> Result<String, url::ParseError> {
    match url::Url::parse(input) {
        Ok(url) => {
            if let Some(domain) = url.domain() {
                Ok(domain.to_string())
            } else {
                Err(url::ParseError::InvalidDomainCharacter)
            }
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod test {
    use crate::{
        input::Opts,
        parse_addresses_from_opt,
        utils::{human_readable_size, parse_addresses},
    };

    use super::get_domain_from_url;

    #[test]
    /// Makes sure the network is available
    pub fn parse_cidr() {
        let cidr_str = "192.168.1.1/24";
        let ips = parse_addresses(&cidr_str);
        assert!(ips.len() == 256);
    }

    #[test]
    pub fn parse_nothing_string() {
        let cidr_str = "# nothing";
        let ips = parse_addresses(cidr_str);
        assert!(ips.len() == 0);
    }

    #[test]
    pub fn test_human_readable_size() {
        assert_eq!(human_readable_size(0.0), "0.00 B");
        assert_eq!(human_readable_size(100.0), "100.00 B");
        assert_eq!(human_readable_size(1024.0), "1.00 KB");
        assert_eq!(human_readable_size(1048576.0), "1.00 MB");
        assert_eq!(human_readable_size(1073741824.0), "1.00 GB");
        assert_eq!(human_readable_size(1099511627776.0), "1.00 TB");
        assert_eq!(human_readable_size(1125899906842624.0), "1.00 PB");
        assert_eq!(human_readable_size(1152921504606846976.0), "1.00 EB");
        assert_eq!(human_readable_size(1180591620717411303424.0), "1.00 ZB");
        assert_eq!(human_readable_size(1208925819614629174706176.0), "1.00 YB");
    }

    #[test]
    pub fn test_get_domain_from_url() {
        let result = get_domain_from_url("https://127.0.0.1/");
        assert!(result.is_err());

        let result = get_domain_from_url("mailto:rms@example.net");
        assert!(result.is_err());

        let result = get_domain_from_url("https://example.com/");
        assert!(result.is_ok());
    }
    #[test]
    fn test_parse_addresses_from_opt() {
        let opts = Opts {
            args: vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
            random_number: 0,
            ..Default::default() // 初始化其他参数为默认值
        };
        let result = parse_addresses_from_opt(&opts);
        assert_eq!(result.len(), 16777472);

        let opts = Opts {
            args: vec!["192.168.1.0/24".to_string()],
            random_number: 50,
            ..Default::default() // 初始化其他参数为默认值
        };
        let result = parse_addresses_from_opt(&opts);
        assert_eq!(result.len(), 50);

        let opts = Opts {
            args: vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
            random_number: 50,
            ..Default::default() // 初始化其他参数为默认值
        };
        let result = parse_addresses_from_opt(&opts);
        assert_eq!(result.len(), 50);
    }

    
}
