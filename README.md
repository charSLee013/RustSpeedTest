# rustspeedtest 🚀

---

This tool is used to test the TCP latency and download speed(TODO) within different CIDR blocks.

[中文说明](https://github.com/charSLee013/RustSpeedTest/README-zh.md)

## Usage 🔨

Use the following command to run the tool:

```bash
cargo run -- CIDR
```

For example, to test the TCP latency within the `192.0.2.0/24` block, use the following command:

```bash
cargo run -- 192.0.2.0/24
```

Or, to test the TCP latency of all the CIDR blocks listed in `ip.txt`, use the following command:

```bash
cargo run -- ip.txt
```

## Help ℹ️

```bash
cargo run -- -h

USAGE:
    rustspeedtest [OPTIONS] [-- <args>...]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Print version information

OPTIONS:
    -d, --display <display>    The number of results to display. The number of results to display after speedtest, set
                               to 0 to not display results and exit directly [default: 10]
    -n, --number <number>      The number of threads for speedtest. More threads mean faster speedtest, but may not be
                               suitable for weak devices (e.g. routers). (max: ulimit -n) [default: 200]
    -o, --output <output>      The file to write the results to [default: result.csv]
    -p, --port <port>          The port to use for speedtest. The port used for delay test/download test [default: 443]
        --time <time>          The number of delay times for speedtest. The number of times to delay test a single IP
                               [default: 4]
        --timeout <timeout>    The timeout in milliseconds before a test is assumed to be failed [default: 9999]

ARGS:
    <args>...    The files or CIDRs to process [default=ip.txt]. Example: 'rustspeedtest -n 2500 -d 20 --
                 192.168.1.1/24'
```

## Features and Limitations ⚡️

- TCP latency testing within blocks is supported
- Results are sorted by latency time
- Low CPU and memory usage
- TODO: Download speed testing for low latency IPs

## License 📜

This tool is licensed under the MIT license. For more details, see the [LICENSE](https://github.com/charSLee013/RustSpeedTest/LICENSE) file.

## Developers 👨‍💻

- [charSLee013](https://github.com/charSLee013) - Initial development and maintenance
