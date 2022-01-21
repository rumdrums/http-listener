use std::io::Error;
use std::mem::{size_of, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn main() {
    let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8888);

    let domain = match sock_addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    let socket_type = libc::SOCK_STREAM;

    // FIXME -- error handling
    let socket = unsafe { libc::socket(domain, socket_type, 0) };

    println!("socket result: {}", socket);

    // according to mio this wont cause endian-ness problems:
    let sin_addr = match sock_addr {
        SocketAddr::V4(ref addr) => libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        SocketAddr::V6(ref addr) => {
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
        SocketAddr::V6(ref addr) => {
            panic!("v6 not implemented");
        }
    };

    // FIXME -- error handling
    unsafe {
        let bind_ret = libc::bind(
            socket,
            &sockaddr_in as *const libc::sockaddr_in as *const libc::sockaddr,
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );

        println!("bind result: {}", bind_ret);
        if bind_ret < 0 {
            println!("bind errno {}", Error::last_os_error());
        }
        let listen_ret = libc::listen(socket, i32::max_value());
        println!("listen result: {}", listen_ret);
    }

    let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let mut addr: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::uninit();

    loop {
        let accept_ret = unsafe { libc::accept(socket, addr.as_mut_ptr() as *mut _, &mut length) };
        println!("result: {}", accept_ret);
    }
}
