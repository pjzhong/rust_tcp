use std::{
    io::{self, Read, Write},
    thread,
};

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;

    let mut l1 = i.bind(6000)?;

    let jh1 = thread::spawn(move || {
        let mut buf = [0; 512];
        if let Ok(mut stream) = l1.accept() {
            println!("l1 accept connection");
            let _ = stream.write("hello".as_bytes());
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    eprintln!("No more data!");
                    break;
                } else {
                    println!(
                        "read {:?}b of data, got\n{}",
                        n,
                        String::from_utf8_lossy(&buf[..n])
                    )
                }
            }
        }
    });

    let _ = jh1.join();

    Ok(())
}
