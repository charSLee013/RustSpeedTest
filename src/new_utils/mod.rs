use std::{net::IpAddr, io::{self, BufRead}};

use cidr_utils::cidr::IpCidr;


/// 将字符串解析成ip 地址
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

#[cfg(test)]
mod test {
    use crate::{input::Opts, parse_addresses_from_opt};

    use super::*;

    #[test]
    fn test_parse_addresses_from_opt() {
        let opts = Opts {
            address: vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
            random_number: 0,
            ..Default::default() // 初始化其他参数为默认值
        };
        let result = parse_addresses_from_opt(&opts);
        assert_eq!(result.len(), 16777472);

        let opts = Opts {
            address: vec!["192.168.1.0/24".to_string()],
            random_number: 50,
            ..Default::default() // 初始化其他参数为默认值
        };
        let result = parse_addresses_from_opt(&opts);
        assert_eq!(result.len(), 50);

        let opts = Opts {
            address: vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
            random_number: 50,
            ..Default::default() // 初始化其他参数为默认值
        };
        let result = parse_addresses_from_opt(&opts);
        assert_eq!(result.len(), 50);
    }
}
