use std::{cell::Ref, net::Ipv4Addr, rc::Rc};

use etherparse::{ip_number, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

use crate::{err::TcpErr, tcp};

pub enum State {
    //Closed,
    //Listen,
    SynRcvd,
    Estab,
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
        let mut connecton = Connection {
            state: State::SynRcvd,
            rcv: ReceiveSequenceSpace {
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
            ip: Ipv4Header::new(
                0,
                64,
                ip_number::TCP,
                ip_header.destination(),
                ip_header.source(),
            ),
        };

        let mut syn_ack = TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            connecton.send.iss,
            connecton.send.wnd,
        );
        syn_ack.acknowledgment_number = connecton.rcv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        connecton
            .ip
            .set_payload_len(syn_ack.header_len() as usize)?;
        // the kernel is nice and does this for us
        // syn_ack.checksum = syn_ack.calc_checksum_ipv4(&ip, &[])?;

        let mut buffer = [0u8; 1500];
        let written = {
            let len = buffer.len();
            let mut slice = &mut buffer[..];
            connecton.ip.write(&mut slice)?;
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
    ) -> Result<(), TcpErr> {
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but wrapping around
        let ackn = tcp_header.acknowledgment_number();
        if !is_between_wrapping(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            return Ok(());
        }

        // A segment is judged to occupy a portion of valid receive sequence
        // space if
        //    RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // or
        //    RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        let seqn = tcp_header.sequence_number();
        let slen = {
            // SEG.LEN = the number of octets occupied by the data in the segment
            // (counting SYN and FIN)

            let mut len = data.len();
            if tcp_header.syn() {
                len += 1;
            }

            if tcp_header.fin() {
                len += 1;
            }

            len as u32
        };
        if slen == 0 && !tcp_header.syn() && !tcp_header.fin() {
            if self.rcv.wnd == 0 {
                if seqn != self.rcv.nxt {
                    return Ok(());
                } else if !is_between_wrapping(
                    self.rcv.nxt.wrapping_sub(1),
                    seqn,
                    self.rcv.nxt.wrapping_add(self.rcv.wnd as u32),
                ) {
                    return Ok(());
                }
            }
        } else if self.rcv.wnd == 0 {
            return Ok(());
        } else if !is_between_wrapping(
            self.rcv.nxt.wrapping_sub(1),
            seqn,
            self.rcv.nxt.wrapping_add(self.rcv.wnd as u32),
        ) || !is_between_wrapping(
            self.rcv.nxt.wrapping_sub(1),
            seqn + slen - 1,
            self.rcv.nxt.wrapping_add(self.rcv.wnd as u32),
        ) {
            return Ok(());
        }

        match self.state {
            State::SynRcvd => Ok(()),
            State::Estab => unimplemented!(),
        }
    }
}

fn is_between_wrapping(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            // we have
            // |------------S-------X--------------------|
            // X is between (S < X <= E) in these case
            // |------------S-------X-----E--------------|
            // |-----E------S-------X--------------------|
            // but *not* in these case
            // |------------S------------E----------X----|
            // |------------|-------X--------------------|
            //              ^-S+E
            // |------------S-------|--------------------|
            //                     ^- X+E

            if start <= end && end <= x {
                return false;
            } else {
                return true;
            }
        }
        Ordering::Greater => {
            // we have oppsite abbove
            // |------------X-------S--------------------|
            // X is between is this case (S < X <= E) in these case
            // |-----X------E---------S------------------|
            // but *not* in these case
            // |-----X------S-------E--------------------|
            // |------------S------------E----------X----|
            // |------------|-------S--------------------|
            //              ^-X+E
            // |-----X------|----------------------------|
            //              ^-S+E
            // or in other words, iff S < E < X

            if end < start && x < end {
                return true;
            } else {
                return false;
            }
        }
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
    rcv: ReceiveSequenceSpace,
    send: SendSeuquenceSpace,
    ip: Ipv4Header,
}
