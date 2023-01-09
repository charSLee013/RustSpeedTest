# rustspeedtest 🚀

---

这个工具用于测速不同CIDR域内的TCP 延迟和下载速度。

## 使用 🔨

使用以下命令运行工具：

```bash
cargo run -- CIDR
```

其中 `CIDR` 是你想要测速的 CIDR 域。此外，你也可以指定一个包含要测速的 CIDR 域列表的文件路径，如下所示：

例如，要测速 `192.0.2.0/24` 域内的 TCP 延迟，请使用以下命令：

```bash
cargo run -- 192.0.2.0/24
```

或者，要测速 `ip.txt` 中列出的所有 CIDR 域的 TCP 延迟，请使用以下命令：

```bash
cargo run -- ip.txt
```

## 帮助信息 ℹ️

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

## 特点和局限性 ⚡️

- 支持在域内测速 TCP 延迟
- 结果按照延迟时间排序
- TODO: 为延迟低的 IP 测速下载速度

## 协议 📜

这个工具使用 MIT 协议。有关更多细节，请参见 [LICENSE](https://github.com/charSLee013/RustSpeedTest/LICENSE) 文件。

## 开发人员 👨‍💻

- [charSLee013](https://github.com/charSLee013) - 初始开发和维护
