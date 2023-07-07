use std::str::FromStr;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "rustspeedtest",version=env!("CARGO_PKG_VERSION"),about="network speedtest by rust",setting = structopt::clap::AppSettings::TrailingVarArg)]
pub struct Opts {
    /// The number of threads for speedtest. More threads mean faster speedtest, but may not be suitable for weak devices (e.g. routers). (max: ulimit -n)
    #[structopt(short = "n", long, default_value = "200")]
    pub number: usize,

    /// The number of delay times for speedtest. The number of times to delay test a single IP.
    #[structopt(long, default_value = "4")]
    pub time: u8,

    /// The port to use for delay test.
    #[structopt(short = "p", long, default_value = "443")]
    pub port: u16,

    /// The number of results to display. The number of results to display after speedtest, set to 0 to not display results and exit directly.
    #[structopt(short = "d", long, default_value = "10")]
    pub display: usize,

    /// The timeout in milliseconds before a test is assumed to be failed.
    #[structopt(long, default_value = "1000")]
    pub timeout: u64,

    /// Warmup with the specified number of iterations (default is 0).
    #[structopt(long, default_value = "0")]
    pub warmup:u8,
    
    /// The file to write the results to.
    #[structopt(short = "o", long, default_value = "result.csv")]
    pub output: String,

    /// Enable download speed test
    #[structopt(short, long)]
    pub enable_download: bool,

    /// The number of download speed test. 0 is all test.
    #[structopt(long, default_value = "10")]
    pub download_number: usize,

    /// The port to use for download speedtest;
    #[structopt(long, default_value = "443")]
    pub download_port: u16,

    /// Random count of IPs to test for all CIDR. 0 is all.
    #[structopt(short = "rn", long, default_value = "0")]
    pub random_number: usize,

    /// The average delay upper limit to filter the IPs, unit is ms.
    #[structopt(long, default_value = "9999")]
    pub au: u128,

    /// The average delay lower limit to filter the IPs, unit is ms.
    #[structopt(long, default_value = "0")]
    pub al: u128,

    /// The download url for download speed test
    #[structopt(
        short = "u",
        long,
        default_value = "https://speed.cloudflare.com/__down?bytes=200000000"
    )]
    pub download_url: String,

    /// speed test timeout;
    #[structopt(long, default_value = "5")]
    pub download_timeout: u64,

    /// Check if Cloudflare routes are in the same region.
    #[structopt(short, long)]
    pub cfhttping: bool,

    /// Check routes times
    #[structopt(long,default_value = "5")]
    pub check_times:u64,

    /// Check http ping
    #[structopt(long)]
    pub httping: bool,

    /// Address or file path
    /// The files or CIDRs to process [default=ip.txt].
    #[structopt(short = "a",long = "address")]
    pub address: Vec<String>,

    /// try enable io_uring if system support
    #[structopt(long, help = "Enable iouring")]
    pub enable_iouring: bool,

    /// Scan specific options
    #[structopt(subcommand)]
    pub scan_opts: ScanOptions,
}

/// Scan spcific options
#[derive(Debug, structopt::StructOpt)]
pub enum ScanOptions {
    Http(HttpScanOptions),
    Tcp(TcpConnectOptions),
}


/// TCP connect scan
#[derive(Debug, Clone, structopt::StructOpt)]
pub struct TcpConnectOptions {}

const HTTP_METHOD: [&str; 9] = [
    "GET","POST","PUT","DELETE","HEAD","OPTIONS","TRACE","CONNECT","PATCH"
];

/// HTTP Scan header match or filter
#[derive(Debug, Clone, structopt::StructOpt)]
pub struct HttpScanOptions{
    #[structopt(long = "method",default_value = "GET", possible_values(&HTTP_METHOD))]
    pub method: String,

    #[structopt(long = "version",default_value = "1.1", )]

    #[structopt(long = "path",default_value = "/")]
    pub path: String,

    #[structopt(long = "headers" , help = "The headers parameter is a list of HTTP headers specified in the format \"key: value\".")]
    pub headers: Vec<RequestHttpHeader>,

    #[structopt(long = "match", help = "Regular expression used to match response headers for the HTTP scanner. Example: 'Server:\\s*Apache/\\d\\.\\d\\.\\d'")]
    pub resp_header_match:Option<ResponseHttpHeaderRegex>,

    #[structopt(long = "filter", help = "Regular expression used to filter out response headers for the HTTP scanner. Example: 'X-Debug-Info: \\d{4}-\\d{2}-\\d{2}'")]
    pub resp_header_filter:Option<ResponseHttpHeaderRegex>,
}

#[derive(Debug, Clone)]
pub struct RequestHttpHeader {
    pub key: String,
    pub val: String,
}


// FromStr trait 的实现，用于从字符串中解析出一个 RequestHttpHeader 结构体对象。
//
// 这个方法将输入字符串分隔成两部分，第一部分为请求头名称，第二部分为请求头值。
// 然后使用这些值创建一个新的 `RequestHttpHeader` 结构体。
// 如果解析失败，返回一个包含错误信息的 Result。
impl FromStr for RequestHttpHeader {
    // 定义一个错误类型为 String
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.splitn(2, ':').collect();

        // 如果分割后的部分数量不等于 2，则返回一个 err 值，指示无效请求头格式。
        if parts.len() != 2 {
            return Err(format!("Invalid request header format: {:?}", s));
        }

        // 通过对分割前半部分进行转换得到请求头名称（key），
        // 对分割后半部分进行修剪后得到请求头值（val）。
        let key = parts[0].to_string();
        let val = parts[1].trim_start().to_string();

        // 最后，用这两个值创建一个新的 `RequestHttpHeader` 结构体，并将其包装在 Ok 中返回。
        // 如果在解析过程中遇到错误，则返回 Err，并包含一个描述错误的字符串。
        Ok(Self { key, val })
    }
}


#[derive(Debug, Clone, structopt::StructOpt)]
pub struct ResponseHttpHeaderRegex {
    pub val_regex: regex::bytes::Regex,
}

// 实现 FromStr trait，用于从字符串中解析出一个 ResponseHttpHeaderRegex 结构体对象。
impl FromStr for ResponseHttpHeaderRegex {
    // 定义一个错误类型为 String
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 将输入字符串作为正则表达式进行编译。
        let val_regex: regex::bytes::Regex = regex::bytes::Regex::new(s)
            .map_err(|e| format!("Invalid regex {:?}: {}", s, e))?;

        // 使用编译后的正则表达式创建一个新的 ResponseHttpHeaderRegex 结构体。
        Ok(Self { val_regex })
    }
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            number: 200,
            time: 4,
            port: 443,
            display: 10,
            timeout: 9999,
            output: "result.csv".to_string(),
            enable_download: true,
            download_port: 443,
            download_number: 10,
            random_number: 0,
            warmup:0,
            au: 9999,
            al: 0,
            download_url: "https://speed.cloudflare.com/__down?bytes=200000000".to_string(),
            download_timeout: 5,
            cfhttping:false,
            check_times:10,
            httping:false,
            enable_iouring:false,
            address: vec![],
            scan_opts: ScanOptions::Tcp(TcpConnectOptions{}),
        }
    }
}

impl Opts {
    pub fn read() -> Self {
        let mut opts = Opts::from_args();

        if opts.address.is_empty() {
            opts.address = vec!["ip.txt".to_string()];
        }

        opts
    }
}


// 定义测试用例
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_http_header_regex() {
        let test_cases = vec![
            ("Content-Type:.*text/html.*", "Content-Type: text/html"),
            ("Content-Length:\\s*(\\d+)", "Content-Length: 123"),
            ("Server:\\s*Apache/\\d\\.\\d\\.\\d", "Server: Apache/2.4.41"),
            ("ETag:\\s*\".*\"", "ETag: \"abcd1234\""),
            ("Transfer-Encoding:\\s*chunked", "Transfer-Encoding: chunked"),
            ("Connection:\\s*(keep-alive|close)", "Connection: keep-alive"),
        ];

        for (regex_str, header_str) in test_cases {
            let header_regex = ResponseHttpHeaderRegex::from_str(regex_str).unwrap();

            assert!(header_regex.val_regex.is_match(header_str.as_bytes()));
        }
    }
}