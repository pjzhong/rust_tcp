pub mod err;
pub mod tcp;

use std::{
    collections::{HashMap, VecDeque},
    io::{self, Error, ErrorKind, Read, Write},
    net::Ipv4Addr,
    ops::DerefMut,
    sync::{Arc, Condvar, Mutex},
    thread,
};

use err::TcpErr;
use tcp::Connection;

use crate::tcp::Available;

//type InterfaceHandle = mpsc::Sender<InterfaceRequest>;
type InterfaceHandle = Arc<Foobar>;

type Result<T> = std::result::Result<T, TcpErr>;

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> Result<()> {
    const TUNP_HEADER_LEN: usize = 0;
    const TCP_PROTO: u8 = 0x06;

    let mut buf = [0u8; 1504];

    loop {
        // TODO set a timeout for this recv for TCP timer or ConnectionManager::terminate
        let nbyte = nic.recv(&mut buf[..])?;

        // TODO if self.terminated && Arc::get_strong_refs(ih) == 1; then tear down all connections and return

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
                    eprintln!("Bad PROTO");
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[TUNP_HEADER_LEN + ip_header.slice().len()..nbyte],
                ) {
                    //(src_ip, src_port, dst_ip, dest_port)
                    Ok(tcph) => {
                        let datai = TUNP_HEADER_LEN + ip_header.slice().len() + tcph.slice().len();
                        let mut cmg = ih.manager.lock().unwrap();
                        let cm = cmg.deref_mut();
                        let q = Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        };
                        use std::collections::hash_map::Entry;
                        match cm.connections.entry(q) {
                            Entry::Occupied(mut c) => {
                                let a = c.get_mut().on_packet(
                                    &mut nic,
                                    &ip_header,
                                    &tcph,
                                    &buf[datai..nbyte],
                                )?;

                                drop(cmg);
                                if a.contains(tcp::Available::Read) {
                                    ih.rcv_var.notify_all();
                                }

                                if a.contains(tcp::Available::Write) {
                                    ih.rcv_var.notify_all();
                                }
                            }
                            Entry::Vacant(entry) => {
                                if let Some(pending) = cm.pending.get_mut(&tcph.destination_port())
                                {
                                    if let Some(c) = Connection::accpect(
                                        &mut nic,
                                        &ip_header,
                                        &tcph,
                                        &buf[datai..nbyte],
                                    )? {
                                        entry.insert(c);
                                        pending.push_back(q);
                                        drop(cmg);
                                        ih.pending_var.notify_all();

                                        //TODO: wake up pending accept
                                    };
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("ignoring weired tcp packet {:?}", e),
                }
            }
            Err(e) => eprintln!("ignoring weired packet {:?}", e),
        };
    }
}

#[derive(Default)]
struct Foobar {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    rcv_var: Condvar,
}

pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<()>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminated = true;
        self.jh
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap();
    }
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let tx: InterfaceHandle = Arc::default();

        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        let jh = {
            let cm = tx.clone();
            thread::spawn(move || {
                let nic = nic;
                let cm = cm;
                if let Err(e) = packet_loop(nic, cm) {
                    eprintln!("packet_loop, error:{:?}", e)
                }
            })
        };

        //let (tx, rx) = mpsc::channel();
        // let jh = thread::spawn(move || tx.run_on(tx));
        Ok(Interface {
            ih: Some(tx),
            jh: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;
        let mut cm = self.ih.as_ref().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(Default::default());
            }
            Entry::Occupied(_) => {
                return Err(Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("port:{} already bound", port),
                )
                .into());
            }
        }
        // TODO something to start accepting SYN packets on 'port'
        drop(cm);
        Ok(TcpListener {
            port,
            ih: self.ih.as_ref().unwrap().clone(),
        })
    }
}

#[derive(Default)]
pub struct ConnectionManager {
    terminated: bool,
    connections: HashMap<Quad, Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}
pub struct TcpStream {
    quad: Quad,
    ih: InterfaceHandle,
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut cm = self.ih.manager.lock().unwrap();
        loop {
            let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    "stream was terminated unexpectedly",
                )
            })?;

            if c.is_rcv_closed() && c.incoming.is_empty() {
                // no more data to read, and no need to block, because there won't be any more
                return Ok(0);
            }

            if !c.incoming.is_empty() {
                // TODO detect FIN and return nread == 0;

                let mut nread = 0;
                let (head, tail) = c.incoming.as_slices();
                for slice in [head, tail] {
                    let read = buf.len().saturating_sub(nread).min(slice.len());
                    buf.copy_from_slice(&slice[..read]);
                    nread += read;
                }
                drop(c.incoming.drain(..nread));
                return Ok(nread);
            }
            cm = self.ih.rcv_var.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut cm = self.ih.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.len() >= SENDQUEUE_SIZE {
            //TODO block
            return Err(Error::new(ErrorKind::WouldBlock, "too many bytes buffered"));
        }

        let nwrite = SENDQUEUE_SIZE
            .saturating_add(c.unacked.len())
            .min(buf.len());
        c.unacked.extend(&buf[..nwrite]);

        //TODO wake up write
        Ok(nwrite)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut cm = self.ih.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            Error::new(
                ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.is_empty() {
            return Ok(());
        } else {
            //TODO block
            return Err(Error::new(ErrorKind::WouldBlock, "too many bytes buffered"));
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // TODO send FIN on cm.connections(quad)
        // TODO eventually remove self.quad from cm.connections
        // let mut cm = self.ih.manager.lock().unwrap();
        // if let Some(_c) = cm.connections.remove(&self.quad) {
        //     //  unimplemented!("send FIN on c")
        // }
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        unimplemented!()
    }
}

pub struct TcpListener {
    port: u16,
    ih: InterfaceHandle,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.ih.manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active");

        for quad in pending {
            //TODO terminated cm.connections[quad]
            unimplemented!("terminated cm.connections[quad]")
        }
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> Result<TcpStream> {
        let mut cm = self.ih.manager.lock().unwrap();
        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("port closed while listener still active")
                .pop_front()
            {
                return Ok(TcpStream {
                    quad,
                    ih: self.ih.clone(),
                });
            }

            cm = self.ih.pending_var.wait(cm).unwrap();
        }
    }
}
