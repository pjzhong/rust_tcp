use std::{
    io::{self, Read},
    thread,
};

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;

    let mut l1 = i.bind(6000)?;

    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            println!("l1 accept connection");
            let n = stream.read(&mut [0]).unwrap();
            eprintln!("read data");
            assert_eq!(n, 0);
            eprintln!("no more data");
        }
    });

    let _ = jh1.join();

    Ok(())
}
