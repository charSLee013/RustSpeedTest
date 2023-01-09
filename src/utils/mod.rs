use cidr_utils::cidr::IpCidr;
use std::error::Error;
use std::fs;
use std::io::BufRead;
use std::{io, net::IpAddr};

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

pub fn write_to_csv(filename: &str, vec: &Vec<Delay>) -> Result<(), Box<dyn Error>> {
    let mut csv = String::new();

    // add title
    csv.push_str("IP,Consume,Success");
    for delay in vec {
        csv.push_str(&format!(
            "{},{},{}\n",
            delay.ip,
            delay.consume.as_millis(),
            delay.success
        ));
    }
    fs::write(filename, csv)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::utils::parse_addresses;

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
}
