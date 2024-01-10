use std::net::Ipv4Addr;

use etherparse::{ip_number, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

use crate::{err::TcpErr, tcp};

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

impl Default for State {
    fn default() -> Self {
        Self::Listen
    }
}

impl Connection {
    pub fn accpect(
        ipface: &mut tun_tap::Iface,
        ip_header: &Ipv4HeaderSlice,
        tcp_header: &TcpHeaderSlice,
        data: &[u8],
    ) -> Result<Option<Self>, TcpErr> {
        if !tcp_header.syn() {
            // only expected syn packet
            return Ok(None);
        }

        let iss = 0;
        let connecton = Connection {
            state: State::SynRcvd,
            recv: ReceiveSequenceSpace {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                up: 0,
            },
            send: SendSeuquenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: tcp_header.window_size(),
                up: 0,
                wl1: 0,
                wl2: 0,
            },
        };

        let mut syn_ack = TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            connecton.send.iss,
            connecton.send.wnd,
        );
        syn_ack.acknowledgment_number = connecton.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        let ip = Ipv4Header::new(
            syn_ack.header_len(),
            64,
            ip_number::TCP,
            ip_header.destination(),
            ip_header.source(),
        );

        let mut buffer = [0u8; 1500];
        let written = {
            let len = buffer.len();
            let mut slice = &mut buffer[..];
            ip.write(&mut slice)?;
            syn_ack.write(&mut slice)?;

            len - slice.len()
        };

        ipface.send(&buffer[..written])?;
        Ok(Some(connecton))
    }

    pub fn on_packet(
        &mut self,
        ipface: &mut tun_tap::Iface,
        ip_header: &Ipv4HeaderSlice,
        tcp_header: &TcpHeaderSlice,
        data: &[u8],
    ) -> Result<usize, TcpErr> {
        Ok(0)
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

/// Send Sequence Variables
/// SND.UNA - send unacknowledged
/// SND.NXT - send next
/// SND.WND - send window
/// SND.UP  - send urgent pointer
/// SND.WL1 - segment sequence number used for last window update
/// SND.WL2 - segment acknowledgment number used for last window
///           update
/// ISS     - initial send sequence number
///
/// Send Sequence Space
//     1         2          3          4
// ----------|----------|----------|----------
//        SND.UNA    SND.NXT    SND.UNA
//                             +SND.WND

// 1 - old sequence numbers which have been acknowledged
// 2 - sequence numbers of unacknowledged data
// 3 - sequence numbers allowed for new data transmission
// 4 - future sequence numbers which are not yet allowed
#[derive(Debug)]
pub struct SendSeuquenceSpace {
    una: u32,
    nxt: u32,
    wnd: u16,
    up: u16,
    wl1: usize,
    wl2: usize,
    iss: u32,
}

/// RCV.NXT - receive next
/// RCV.WND - receive window
/// RCV.UP  - receive urgent pointer
/// IRS     - initial receive sequence number
///
///  Receive Sequence Space
//      1          2          3
// ----------|----------|----------
//        RCV.NXT    RCV.NXT
//                  +RCV.WND

// 1 - old sequence numbers which have been acknowledged
// 2 - sequence numbers allowed for new reception
// 3 - future sequence numbers which are not yet allowed
#[derive(Debug)]
pub struct ReceiveSequenceSpace {
    nxt: u32,
    wnd: u16,
    up: u16,
    irs: u32,
}

pub struct Connection {
    state: State,
    recv: ReceiveSequenceSpace,
    send: SendSeuquenceSpace,
}
