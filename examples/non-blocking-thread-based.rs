use std::io::{Error, ErrorKind, Read, Write};
use std::mem::{size_of, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::io::FromRawFd;
use std::str;
use std::{thread, time};

use httparse::{Header, Request, EMPTY_HEADER};
use bstr::{B, ByteSlice};

enum ParseError {
    Incomplete,
    NoHeaders,
    HttparseError(httparse::Error)
}

fn main() {
    let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8888);

    let domain = match sock_addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    let socket_type = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;

    let socket = unsafe { libc::socket(domain, socket_type, 0) };
    if socket == -1 {
        println!("socket errno {}", Error::last_os_error());
        return;
    }

    // according to mio this wont cause endian-ness problems:
    let sin_addr = match sock_addr {
        SocketAddr::V4(ref addr) => libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        SocketAddr::V6(ref _addr) => {
            panic!("v6 not implemented");
        }
    };

    let sockaddr_in = match sock_addr {
        SocketAddr::V4(ref addr) => libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: addr.port().to_be(),
            sin_addr,
            sin_zero: [0; 8],
        },
        SocketAddr::V6(ref _addr) => {
            panic!("v6 not implemented");
        }
    };

    unsafe {
        if libc::bind(
            socket,
            &sockaddr_in as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) == -1
        {
            println!("bind errno {}", Error::last_os_error());
            return;
        }

        if libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1 as *const libc::c_int as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        ) == -1
        {
            println!("setsockopt errno {}", Error::last_os_error());
            return;
        }

        if libc::listen(socket, i32::max_value()) == -1 {
            println!("listen errno {}", Error::last_os_error());
            return;
        }
    }

    let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let mut addr: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::uninit();

    loop {
        let conn_fd = unsafe {
            libc::accept4(
                socket,
                addr.as_mut_ptr() as *mut _,
                &mut length,
                // libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::SOCK_CLOEXEC,
            )
        };
        if conn_fd == -1 {
            continue;
        }

        let mut stream = unsafe { TcpStream::from_raw_fd(conn_fd) };

        thread::spawn(move || -> () {
            let addr = addr.as_ptr() as *const libc::sockaddr_in;
            let (ip, port) = unsafe { (((*addr).sin_addr.s_addr).to_be(), (*addr).sin_port) };
            let ip_addr = Ipv4Addr::new(
                (ip >> 24) as u8,
                (ip >> 16) as u8,
                (ip >> 8) as u8,
                ip as u8,
            );
            let sock_addr = SocketAddr::new(std::net::IpAddr::V4(ip_addr), port);
            println!(
                "Got connection from addr {}, port {}",
                sock_addr.ip(),
                sock_addr.port()
            );

            let mut received_data = Vec::new();
            loop {
                let mut buf = vec![0; 4096];
                if let Err(e) = stream.read(&mut buf) {
                    match e.kind() {
                        ErrorKind::WouldBlock => {
                            thread::sleep(time::Duration::from_millis(10));
                            continue;
                        }
                        _ => {
                            println!("Read error: {}", e);
                            break;
                        }
                    };
                }

                buf.iter()
                    .take_while(|i| **i != 0)
                    .for_each(|i| received_data.push(*i));

                debug_print(&received_data);

                let mut headers = [httparse::EMPTY_HEADER; 128];
                match parse_req(&received_data, &mut headers) {
                    Ok(req) => {
                        print_request(&req);
                        write_response(&mut stream, &req);
                        break;
                    }
                    Err(ParseError::Incomplete) => { continue; }
                    Err(ParseError::HttparseError(e)) => {
                        println!("Parse error: {}", e);
                        break;
                    }
                    Err(ParseError::NoHeaders) => {
                        println!("No headers passed");
                        break;
                    }
                }
            }

            unsafe { libc::close(conn_fd) };
        });
    }
}

// FIXME -- what if multiple reads required for chunked or something
fn parse_req<'headers, 'buf>(
    buf: &'buf [u8],
    header_buf: &'headers mut [Header<'buf>],
) -> Result<Request<'headers, 'buf>, ParseError> {

    let mut req = httparse::Request::new(header_buf);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(_)) => {
            println!("httparse thinks its done");
            if req.headers.len() == 0 {
                return Err(ParseError::NoHeaders);
            }
            Ok(req)
        },
        Ok(httparse::Status::Partial) => Err(ParseError::Incomplete),
        Err(err) => Err(ParseError::HttparseError(err))
    }
}

fn write_response<'headers, 'buf>(
    stream: &mut TcpStream,
    req: &Request<'headers, 'buf>) {

    /*
    . Server
    . Date
    . Content-Type
    . Content-Length
    text/html;charset=utf-8
    or
    application/octet-stream
    */

    if let Some(method) = req.method {
        let resp_status = match method.to_uppercase().as_ref() {
          "POST"|"PUT"|"DELETE"|"PATCH" => B("HTTP/1.1 403 Forbidden\r\n"),
          _ => B("HTTP/1.1 200 OK\r\n")
        };

        stream.write(resp_status);
        stream.write(b"Server: aol-server\r\n");
        // Date: Sat, 15 Jan 2022 05:54:28 GMT
        stream.write(b"Date: ");
        stream.write(
            chrono::Utc::now()
                .format("%a, %d %b %Y %T GMT")
                .to_string()
                .as_bytes(),
        );
        stream.write(b"\r\n");
        stream.write(b"Content-Length: 0\r\n");
    }
}

fn print_request(req: &Request) {
    println!("request print");
    println!(
        "{} {} {}",
        req.method.unwrap(),
        req.path.unwrap(),
        req.version.unwrap()
    );
    req.headers.iter().for_each(|x| {
        if let Ok(val) = str::from_utf8(x.value) {
            println!("{}: {}", x.name, val)
        }
    });
}

fn debug_print(buf: &[u8]) {
    println!("debug print");
    buf.iter().take_while(|i| **i != 0).for_each(|i| {
        let k = vec![*i];
        let j = std::str::from_utf8(&k).unwrap();
        if j == "\n" || j == "\r" {
            print!("_");
        } else {
            print!("{}", j);
        }
    });
    println!("");
}
