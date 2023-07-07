use crate::input::HttpScanOptions;
use crate::ring::{BufferDirection, BufferInfo, EntryInfo, RingAllocator};
use crate::scan_iouring::{check_op_supported, PushError, RawFd, Scan, SockaddrIn, Timeouts};
use bstr::ByteSlice;
use io_uring::{cqueue, opcode, squeue, types::Fd, Probe};
use nix::{
    errno::Errno,
    libc,
    sys::socket::{socket, AddressFamily, SockFlag, SockType, SockaddrLike},
    unistd,
};
use std::fmt::Write;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::time::Instant;
pub struct ScanHttp {
    opts: HttpScanOptions,
    tx_buf_size: Option<usize>,
}

#[derive(Debug)]
enum EntryStep {
    Connect = 0,
    ConnectTimeout,
    Send,
    SendTimeout,
    Recv,
    RecvTimeout,
    Close,
}
impl From<u8> for EntryStep {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Connect,
            1 => Self::ConnectTimeout,
            2 => Self::Send,
            3 => Self::SendTimeout,
            4 => Self::Recv,
            5 => Self::RecvTimeout,
            6 => Self::Close,
            _ => unreachable!(),
        }
    }
}

impl ScanHttp {
    // 处理 HTTP 响应报文的函数,buf 表示响应报文的内容,检查报文是否匹配规则
    fn handle_response(&self, buf: &[u8]) -> bool {
        let mut has_valid_header = false; // 标记是否至少有一行符合标准的 HTTP 响应头部
        for line in buf.lines() {
            if let Some((hdr_key, hdr_value)) = Self::parse_header_line(line) {
                // 如果该行能解析成键值对，则进行以下处理
                has_valid_header = true; // 标记至少有一行符合标准的 HTTP 响应头部
                if let Some(filter) = &self.opts.resp_header_filter {
                    // 如果设置了 resp_header_filter
                    if filter.val_regex.is_match(hdr_value) {
                        // 如果符合过滤条件，直接返回 false
                        return false;
                    }
                }
                if let Some(matcher) = &self.opts.resp_header_match {
                    // 如果设置了 resp_header_match
                    if matcher.val_regex.is_match(hdr_value) {
                        // 如果符合匹配条件，直接返回 true
                        return true;
                    }
                }
            }
        }
        // 如果没有设置 resp_header_match 或者在检查 HTTP 头部的时候没有一例通过检查的话，则返回 false
        // 或者在函数的最后返回 true
        has_valid_header || self.opts.resp_header_match.is_none()
    }

    pub fn new(opts: &HttpScanOptions) -> Self {
        Self {
            opts: opts.to_owned(),
            tx_buf_size: None,
        }
    }

    pub fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
        // 从末尾开始找到第一个非 ASCII 空格字符的位置
        let start = bytes
            .iter()
            .rposition(|&b| !b.is_ascii_whitespace())
            .unwrap_or(0);
        // 从开头开始找到第一个非 ASCII 空格字符的位置
        let end = bytes
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .unwrap_or(bytes.len());
        
        // 返回经过 trim 操作的 byte slice
        if start >= end {
            &[]
        } else {
            &bytes[start..end]
        }
        // &bytes[start..end]
    }

    fn parse_header_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
        if let Some((key, value)) = line.split_once_str(":") {
            let key = ScanHttp::trim_ascii_whitespace(key);
            let value = ScanHttp::trim_ascii_whitespace(value);
            Some((key, value))
        } else {
            None
        }
    }

    fn format_request(&self, addr: &SockaddrIn) -> String {
        let mut s = if let Some(size_hint) = self.tx_buf_size {
            String::with_capacity(size_hint)
        } else {
            String::new()
        };
        write!(
            &mut s,
            "{} {} HTTP/1.1\r\n",
            self.opts.method, self.opts.path,
        )
        .unwrap();

        // 遍历 headers 并写入头信息，如果发现 Host 存在，记录其值
        let mut has_host = false;
        for hdr in &self.opts.headers {
            write!(&mut s, "{}: {}\r\n", hdr.key, hdr.val).unwrap();
            if hdr.key == "Host" {
                has_host = true;
            }
        }

        // Host 不存在，补充 Host 头消息并写入请求
        if !has_host {
            write!(&mut s, "Host: {}\r\n", addr).unwrap();
        }

        write!(&mut s, "\r\n").unwrap();
        s
    }
}

impl Scan for ScanHttp {
    fn check_supported(&self, probe: &Probe) -> bool {
        check_op_supported(probe, opcode::Connect::CODE, "connect")
            && check_op_supported(probe, opcode::LinkTimeout::CODE, "link timeout")
            && check_op_supported(probe, opcode::WriteFixed::CODE, "write fixed")
            && check_op_supported(probe, opcode::ReadFixed::CODE, "read fixed")
            && check_op_supported(probe, opcode::Close::CODE, "close")
    }
    fn max_tx_size(&mut self) -> Option<usize> {
        let sz = self
            .format_request(&SockaddrIn::new(255, 255, 255, 255, u16::MAX))
            .len();
        self.tx_buf_size = Some(sz);
        Some(sz)
    }
    fn ops_per_ip(&self) -> usize {
        7
    }
    fn process_completed_entry(
        &self,
        cq_entry: &cqueue::Entry,
        entry_info: &EntryInfo,
        ring_allocator: &RingAllocator,
    ) -> bool {
        let step = EntryStep::from(entry_info.step);
        let errno = Errno::from_i32(-cq_entry.result());
        log::debug!(
            "op #{} ({:?} {}) returned {} ({:?})",
            cq_entry.user_data(),
            step,
            entry_info.ip,
            cq_entry.result(),
            errno
        );
        if let Some(buf) = entry_info.buf.as_ref() {
            log::debug!(
                "buf: {:?}",
                String::from_utf8_lossy(ring_allocator.get_buf(buf.idx))
            );
        }
        match step {
            EntryStep::Recv => {
                if cq_entry.result() > 0 {
                    self.handle_response(
                        // &entry_info.ip,
                        ring_allocator.get_buf(entry_info.buf.as_ref().unwrap().idx),
                    );
                }
                false
            }
            EntryStep::Close => {
                if cq_entry.result() == -libc::ECANCELED {
                    unistd::close(entry_info.fd).unwrap();
                }
                true
            }
            _ => false,
        }
    }
    fn push_scan_ops(
        &mut self,
        sckt: RawFd,
        addr: &SockaddrIn,
        squeue: &mut io_uring::squeue::SubmissionQueue,
        allocator: &mut RingAllocator,
        timeouts: &Timeouts,
    ) -> Result<usize, PushError> {
        let addr = Rc::new(addr.to_owned());
        let entry_connect_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::Connect as u8,
                buf: None,
                fd: sckt,
                start: Instant::now(),
            })
            .unwrap();
        let op_connect = opcode::Connect::new(Fd(sckt), addr.as_ptr(), addr.len())
            .build()
            .flags(squeue::Flags::IO_LINK | squeue::Flags::ASYNC)
            .user_data(entry_connect_idx);
        let entry_connect_timeout_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::ConnectTimeout as u8,
                buf: None,
                fd: sckt,
                start: Instant::now(),
            })
            .unwrap();
        let op_connect_timeout = opcode::LinkTimeout::new(&timeouts.connect)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_connect_timeout_idx);
        let req = self.format_request(&addr);
        let tx_buffer = allocator.alloc_buf(BufferDirection::TX, Some(req.as_bytes()));
        let op_send_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::Send as u8,
                buf: Some(BufferInfo {
                    idx: tx_buffer.idx,
                    direction: BufferDirection::TX,
                }),
                fd: sckt,
                start: Instant::now(),
            })
            .unwrap();
        let op_send = opcode::WriteFixed::new(
            Fd(sckt),
            tx_buffer.iov.iov_base.cast::<u8>(),
            tx_buffer.iov.iov_len as u32,
            tx_buffer.idx as u16,
        )
        .build()
        .flags(squeue::Flags::IO_LINK)
        .user_data(op_send_idx);
        let entry_send_timeout_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::SendTimeout as u8,
                buf: None,
                fd: sckt,
                start: Instant::now(),
            })
            .unwrap();
        let op_send_timeout = opcode::LinkTimeout::new(&timeouts.write)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_send_timeout_idx);
        let rx_buffer: crate::ring::Buffer = allocator.alloc_buf(BufferDirection::RX, None);
        let op_recv_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::Recv as u8,
                buf: Some(BufferInfo {
                    idx: rx_buffer.idx,
                    direction: BufferDirection::RX,
                }),
                fd: sckt,
                start: Instant::now(),
            })
            .unwrap();
        let op_recv = opcode::ReadFixed::new(
            Fd(sckt),
            rx_buffer.iov.iov_base.cast::<u8>(),
            rx_buffer.iov.iov_len as u32,
            rx_buffer.idx as u16,
        )
        .build()
        .flags(squeue::Flags::IO_LINK)
        .user_data(op_recv_idx);
        let entry_recv_timeout_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::RecvTimeout as u8,
                buf: None,
                fd: sckt,
                start: Instant::now(),
            })
            .unwrap();
        let op_recv_timeout = opcode::LinkTimeout::new(&timeouts.read)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_recv_timeout_idx);
        let entry_close_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::Close as u8,
                buf: None,
                fd: sckt,
                start: Instant::now(),
            })
            .unwrap();
        let op_close = opcode::Close::new(Fd(sckt))
            .build()
            .user_data(entry_close_idx);
        let ops = [
            op_connect,
            op_connect_timeout,
            op_send,
            op_send_timeout,
            op_recv,
            op_recv_timeout,
            op_close,
        ];
        log::trace!("Pushing: {ops:#?}");
        unsafe {
            squeue.push_multiple(&ops).expect("Failed to push ops");
        }
        Ok(ops.len())
    }
    fn socket(&self) -> RawFd {
        socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .expect("Failed to create TCP socket")
    }
}

mod tests {
    use crate::input::{HttpScanOptions, RequestHttpHeader};
    use crate::scan_iouring::http::ScanHttp;
    use crate::scan_iouring::SockaddrIn;
    use std::net::Ipv4Addr;

    #[test]
    fn test_format_request() {
        let opts = HttpScanOptions {
            method: String::from("POST"),
            path: String::from("/submit?name=foo&age=20"),
            headers: vec![
                RequestHttpHeader {
                    key: String::from("X-Custom-Header"),
                    val: String::from("my-custom-value"),
                },
                RequestHttpHeader {
                    key: String::from("Accept-Encoding"),
                    val: String::from("gzip, deflate"),
                },
            ],
            resp_header_match: None,
            resp_header_filter: None,
        };
        let scan_http = ScanHttp::new(&opts);

        // Test with IPv4 address
        let addr = SockaddrIn::new(192, 0, 2, 1, 80);
        let request = scan_http.format_request(&addr);

        assert_eq!(
            request,
            "POST /submit?name=foo&age=20 HTTP/1.1\r\n\
            X-Custom-Header: my-custom-value\r\n\
            Accept-Encoding: gzip, deflate\r\n\
            Host: 192.0.2.1:80\r\n\
            \r\n"
        );

        // Test with headers containing special characters
        let opts = HttpScanOptions {
            method: String::from("GET"),
            path: String::from("/"),
            headers: vec![RequestHttpHeader {
                key: String::from(r#"User-Agent"#),
                val: String::from(r#"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)"#),
            }],
            resp_header_match: None,
            resp_header_filter: None,
        };
        let scan_http = ScanHttp::new(&opts);
        let addr = SockaddrIn::new(192, 0, 2, 1, 443);
        let request = scan_http.format_request(&addr);

        assert_eq!(
            request,
            "GET / HTTP/1.1\r\n\
            User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)\r\n\
            Host: 192.0.2.1:443\r\n\
            \r\n"
        );
    }

    #[test]
    fn test_trim_ascii_whitespace() {
        // 测试输入为全空格的 byte slice
        assert_eq!(ScanHttp::trim_ascii_whitespace(b"  \t   "), b"");

        // 测试输入只有前后空格的 byte slice
        assert_eq!(
            ScanHttp::trim_ascii_whitespace(b"  \t  hello world  \n "),
            b"hello world"
        );

        // 测试输入只有一个字面量字符的 byte slice
        assert_eq!(ScanHttp::trim_ascii_whitespace(b"a"), b"a");

        // 测试输入包含中间空格的 byte slice
        assert_eq!(
            ScanHttp::trim_ascii_whitespace(b"hello   world!"),
            b"hello   world!"
        );

        // 测试输入为空的 byte slice
        assert_eq!(ScanHttp::trim_ascii_whitespace(b""), b"");

        // 测试输入中只有 ASCII 字母和数字的 byte slice
        assert_eq!(
            ScanHttp::trim_ascii_whitespace(b"  \t  hello123  \n "),
            b"hello123"
        );
    }
}
