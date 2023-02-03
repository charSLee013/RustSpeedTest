use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "rustspeedtest",setting = structopt::clap::AppSettings::TrailingVarArg)]
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
    #[structopt(long, default_value = "9999")]
    pub timeout: u64,

    /// The file to write the results to.
    #[structopt(short = "o", long, default_value = "result.csv")]
    pub output: String,

    /// Enable download speed test
    #[structopt(short, long)]
    pub enable_download: bool,

    /// The number of download speed test.
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
    pub avg_delay_upper: u128,

    /// The average delay lower limit to filter the IPs, unit is ms.
    #[structopt(long, default_value = "0")]
    pub avg_delay_lower: u128,

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

    /// The files or CIDRs to process [default=ip.txt].
    /// Example: 'rustspeedtest -n 2500 -d 20 -- 192.168.1.1/24'.
    #[structopt(last = true)]
    pub args: Vec<String>,
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
            avg_delay_upper: 9999,
            avg_delay_lower: 0,
            download_url: "https://speed.cloudflare.com/__down?bytes=200000000".to_string(),
            download_timeout: 5,
            args: vec![],
        }
    }
}

impl Opts {
    pub fn read() -> Self {
        let mut opts = Opts::from_args();

        if opts.args.is_empty() {
            opts.args = vec!["ip.txt".to_string()];
        }

        opts
    }
}
