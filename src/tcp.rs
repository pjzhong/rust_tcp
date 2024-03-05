use bitflags::bitflags;
use std::collections::VecDeque;

use etherparse::{ip_number, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

use crate::err::TcpErr;

bitflags! {
    pub struct Available: u32 {
        const Read = 0b00000001;
        const Write = 0b00000010;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    //Closed,
    //Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
}

impl State {
    pub fn is_synchronized(&self) -> bool {
        match self {
            State::Estab | State::FinWait1 | State::Closing | State::FinWait2 | Self::TimeWait => {
                true
            }
            State::SynRcvd => false,
        }
    }
}

impl Connection {
    pub fn accpect(
        ipface: &mut tun_tap::Iface,
        ip_header: &Ipv4HeaderSlice,
        tcp_header: &TcpHeaderSlice,
        _data: &[u8],
    ) -> Result<Option<Self>, TcpErr> {
        // eprintln!(
        //     "Got packet fin:{}, se:{}, ack:{}",
        //     tcp_header.fin(),
        //     tcp_header.sequence_number(),
        //     tcp_header.acknowledgment_number()
        // );
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
            snd: SendSeuquenceSpace {
                iss,
                una: iss,
                nxt: iss,
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

            tcp: TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                iss,
                tcp_header.window_size(),
            ),
            incoming: Default::default(),
            unacked: Default::default(),
        };

        connecton.tcp.acknowledgment_number = connecton.rcv.nxt;
        connecton.tcp.syn = true;
        connecton.tcp.ack = true;

        connecton.write(ipface, &[])?;

        Ok(Some(connecton))
    }

    pub fn on_packet(
        &mut self,
        nic: &mut tun_tap::Iface,
        _ip_header: &Ipv4HeaderSlice,
        tcp_header: &TcpHeaderSlice,
        data: &[u8],
    ) -> Result<Available, TcpErr> {
        // eprintln!(
        //     "Got packet fin:{}, se:{}, ack:{}",
        //     tcp_header.fin(),
        //     tcp_header.sequence_number(),
        //     tcp_header.acknowledgment_number()
        // );
        // A segment is judged to occupy a portion of valid receive sequence
        // space if
        //    RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // or
        //    RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        let seqn = tcp_header.sequence_number();
        let slen = {
            // SEG.LEN = the number of octets occupied by the data in the segment
            // (counting SYN and FIN)

            let mut len = data.len() as u32;
            if tcp_header.syn() {
                len += 1;
            }

            if tcp_header.fin() {
                len += 1;
            }

            len
        };
        let wend = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);
        let okay = if slen == 0 {
            if self.rcv.wnd == 0 {
                seqn == self.rcv.nxt
            } else {
                is_between_wrapping(self.rcv.nxt.wrapping_sub(1), seqn, wend)
            }
        } else if self.rcv.wnd == 0 {
            false
        } else {
            !(!is_between_wrapping(self.rcv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapping(
                    self.rcv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                ))
        };

        if !okay {
            self.write(nic, &[])?;
            return Ok(self.availability());
        }

        //self.rcv.nxt = seqn.wrapping_add(slen);
        if !tcp_header.ack() {
            return Ok(self.availability());
        }

        // // acceptable ack check
        // // SND.UNA < SEG.ACK =< SND.NXT
        // // but wrapping around
        // let ackn = tcp_header.acknowledgment_number();
        // if !is_between_wrapping(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
        //     if !self.state.is_synchronized() {
        //         self.send_rst(ipface)?;
        //     }
        //     return Ok(());
        // }

        // self.snd.una = ackn;
        let ackn = tcp_header.acknowledgment_number();
        if State::SynRcvd == self.state {
            if is_between_wrapping(
                self.snd.una.wrapping_sub(1),
                ackn,
                self.snd.nxt.wrapping_add(1),
            ) {
                self.state = State::Estab;
            } else {
                //TODO  <SEQ=SEG.ACK><CTL=RST>
            }
        }

        if State::Estab == self.state
            || State::FinWait1 == self.state
            || State::FinWait2 == self.state
        {
            // If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
            if is_between_wrapping(self.snd.una, ackn, self.snd.nxt.wrapping_add(1)) {
                self.snd.una = ackn;
            }

            //FIXME: we don't support Write yet, so immediately send EOF
            if State::Estab == self.state {
                //TODO lot of stuffs to do
                self.tcp.fin = true;
                self.state = State::FinWait1;
            }
        }

        if State::FinWait1 == self.state {
            // check the syn and the fin we just send has been acked
            if self.snd.una == self.snd.iss + 2 {
                eprintln!("THEY'VE ACKED OUR FIN");
                self.state = State::FinWait2;
            }
        }

        if State::Estab == self.state
            || State::FinWait1 == self.state
            || State::FinWait2 == self.state
        {
            let mut unread_data_at = (self.rcv.nxt - seqn) as usize;
            if unread_data_at > data.len() {
                // we must have received a re-transmitted FIN that we have already
                // seen nxt points to beyond the fin, but the fin is not in data
                assert_eq!(unread_data_at, data.len() + 1);
                unread_data_at = 0;
            }
            //TODO only read stfuf we haven't read
            //Would index out of range
            self.incoming.extend(&data[unread_data_at..]);

            // Once the TCP takes responsibility for the data it advances
            // RCV.NXT over the data accepted, and adjusts RCV.WND as
            // apporopriate to the current buffer availability.  The total of
            // RCV.NXT and RCV.WND should not be reduced
            self.rcv.nxt = seqn.wrapping_add({
                let mut len = data.len() as u32;
                if tcp_header.fin() {
                    len += 1;
                }

                len
            });

            // Send an acknowledgment of the form:
            //<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            self.write(nic, &[])?;
            //TODO: wake up waiting readers
        }

        if tcp_header.fin() {
            match self.state {
                State::FinWait2 => {
                    eprintln!("THEY'VE FINED");
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(self.availability())
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> Result<u32, TcpErr> {
        let mut buffer = [0u8; 1500];
        self.tcp.sequence_number = self.snd.nxt;
        self.tcp.acknowledgment_number = self.rcv.nxt;
        let size = buffer
            .len()
            .min(self.tcp.header_len() as usize + self.ip.header_len() + payload.len());
        self.ip.set_payload_len(size - self.ip.header_len())?;

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        use std::io::Write;
        let mut slice = &mut buffer[..];
        self.ip.write(&mut slice)?;
        self.tcp.write(&mut slice)?;
        let payload_bytes = slice.write(payload)? as u32;
        let unwritten = slice.len();
        nic.send(&buffer[..buffer.len() - unwritten])?;

        self.snd.nxt = self.snd.nxt.wrapping_add(payload_bytes);
        if self.tcp.syn {
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }

        if self.tcp.fin {
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> Result<(), TcpErr> {
        self.tcp.rst = true;
        // TODO: fix sequence number
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the CLOSED state.

        // TODO: handle synchronized RST
        // 3.  If the connection is in a synchronized state (ESTABLISHED,
        //     FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        //     any unacceptable segment (out of window sequence number or
        //     unacceptible acknowledgment number) must elicit only an empty
        //     acknowledgment segment containing the current send-sequence number
        //     and an acknowledgment indicating the next sequence number expected
        //     to be received, and the connection remains in the same state.

        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }

    pub(crate) fn is_rcv_closed(&self) -> bool {
        self.state == State::TimeWait 
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();

        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::Read
        }

        a
    }
}

// I am not quiet understanding this version, but the streaming use this So I keep with it
fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapping(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

//This version is also right
// fn is_between_wrapping1(start: u32, x: u32, end: u32) -> bool {
//     use std::cmp::Ordering;
//     match start.cmp(&x) {
//         Ordering::Equal => return false,
//         Ordering::Less => {
//             // we have
//             // |------------S-------X--------------------|
//             // X is between (S < X <= E) in these case
//             // |------------S-------X-----E--------------|
//             // |-----E------S-------X--------------------|
//             // but *not* in these case
//             // |------------S------------E----------X----|
//             // |------------|-------X--------------------|
//             //              ^-S+E
//             // |------------S-------|--------------------|
//             //                     ^- X+E

//             if start <= end && end <= x {
//                 return false;
//             } else {
//                 return true;
//             }
//         }
//         Ordering::Greater => {
//             // we have oppsite abbove
//             // |------------X-------S--------------------|
//             // X is between is this case (S < X <= E) in these case
//             // |-----X------E---------S------------------|
//             // but *not* in these case
//             // |-----X------S-------E--------------------|
//             // |------------S------------E----------X----|
//             // |------------|-------S--------------------|
//             //              ^-X+E
//             // |-----X------|----------------------------|
//             //              ^-S+E
//             // or in other words, iff S < E < X

//             if end < start && x < end {
//                 return true;
//             } else {
//                 return false;
//             }
//         }
//     }
// }

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
    snd: SendSeuquenceSpace,
    ip: Ipv4Header,
    tcp: TcpHeader,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
}
