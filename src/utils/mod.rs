use cidr_utils::cidr::IpCidr;
use std::error::Error;

use std::fs;
use std::io::BufRead;
use std::{io, net::IpAddr};

use crate::download::Speed;
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
    filename: &str,
    delays: Vec<Delay>,
    speeds: Option<Vec<Speed>>,
) -> Result<(), Box<dyn Error>> {
    let mut csv = String::new();
    let titel = "IP,Delay,Success,Speedtest\n".to_string();

    // add title
    csv.push_str(&titel);

    if let Some(speeds) = speeds {
        if !speeds.is_empty() {
            let map = Delay::to_map(delays);
            for speed in speeds {
                let delay = map.get(&speed.ip).unwrap();
                csv.push_str(&format!(
                    "{},{},{},{}\n",
                    speed.ip,
                    delay.consume.as_millis(),
                    delay.success,
                    if speed.consume.as_secs() != 0 {
                        super::utils::human_readable_size(
                            (speed.total_download / speed.consume.as_secs() as usize) as f64,
                        )
                    } else {
                        "0".to_string()
                    }
                ))
            }
        } else {
            // If all speed tests fail
            for delay in delays {
                csv.push_str(&format!(
                    "{},{},{},0\n",
                    delay.ip,
                    delay.consume.as_millis(),
                    delay.success
                ));
            }
        }
    } else {
        for delay in delays {
            csv.push_str(&format!(
                "{},{},{},0\n",
                delay.ip,
                delay.consume.as_millis(),
                delay.success
            ));
        }
    }

    fs::write(filename, csv)?;
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
        assert_eq!(result.len(), 100);
    }
}
