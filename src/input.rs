use structopt::{StructOpt};

#[derive(StructOpt, Debug)]
#[structopt(name = "rustspeedtest",setting = structopt::clap::AppSettings::TrailingVarArg)]
pub struct Opts {
    /// The number of threads for speedtest. More threads mean faster speedtest, but may not be suitable for weak devices (e.g. routers). (max: ulimit -n)
    #[structopt(short, long, default_value = "200")]
    pub number: u16,

    /// The number of delay times for speedtest. The number of times to delay test a single IP.
    #[structopt(long, default_value = "4")]
    pub time: u8,

    /// The port to use for speedtest. The port used for delay test/download test.
    #[structopt(short = "p", long, default_value = "443")]
    pub port: u16,

    /// The number of results to display. The number of results to display after speedtest, set to 0 to not display results and exit directly.
    #[structopt(short, long, default_value = "10")]
    pub display: usize,

    /// Print version information.
    #[structopt(short, long)]
    pub version: bool,

    /// The timeout in milliseconds before a test is assumed to be failed.
    #[structopt(long, default_value = "9999")]
    pub timeout: u64,

    /// The file to write the results to.
    #[structopt(short = "o", long, default_value = "result.csv")]
    pub output: String,

    /// The files or CIDRs to process [default=ip.txt].
    /// Example: 'rustspeedtest -n 2500 -d 20 -- 192.168.1.1/24'.
    #[structopt(last = true)]
    pub args: Vec<String>,
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
