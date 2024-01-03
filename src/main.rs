use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;

    let mut buf = [0u8; 1504];

    loop {
        let nbyte = nic.recv(&mut buf[..])?;

        eprintln!("read {} bytes: {:x?}", nbyte, &buf[..nbyte]);
    }

    Ok(())
}
