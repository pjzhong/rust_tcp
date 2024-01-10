use std::{
    collections::HashMap,
    io::{self, Write},
};

use tcp::{Connection, Quad};

mod err;
mod tcp;

const TUNP_HEADER_LEN: usize = 0;
const TCP_PROTO: u8 = 0x06;
const IPV4: u16 = 0x0800;

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, Connection> = HashMap::new();
    let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;

    let mut buf = [0u8; 1504];

    loop {
        let nbyte = nic.recv(&mut buf[..])?;

        // let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if eth_proto != IPV4 {
        //     continue;
        // }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[TUNP_HEADER_LEN..nbyte]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();
                let proto = ip_header.protocol();

                if proto != TCP_PROTO {
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[TUNP_HEADER_LEN + ip_header.slice().len()..nbyte],
                ) {
                    //(src_ip, src_port, dst_ip, dest_port)
                    Ok(tcp_header) => {
                        let data_idx =
                            TUNP_HEADER_LEN + ip_header.slice().len() + tcp_header.slice().len();
                        use std::collections::hash_map::Entry;
                        match connections.entry(Quad {
                            src: (src, tcp_header.source_port()),
                            dst: (dst, tcp_header.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                if let Err(e) = c.get_mut().on_packet(
                                    &mut nic,
                                    &ip_header,
                                    &tcp_header,
                                    &buf[data_idx..nbyte],
                                ) {
                                    eprintln!("error:{:?}", e);
                                }
                            }
                            Entry::Vacant(entry) => {
                                match Connection::accpect(
                                    &mut nic,
                                    &ip_header,
                                    &tcp_header,
                                    &buf[data_idx..nbyte],
                                ) {
                                    Ok(Some(c)) => {
                                        entry.insert(c);
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        eprintln!("Accept connection error:{:?}", e);
                                    }
                                };
                            }
                        }
                    }
                    Err(e) => eprintln!("ignoring weired tcp packet {:?}", e),
                }
            }
            Err(e) => eprintln!("ignoring weired packet {:?}", e),
        };
    }

    Ok(())
}
