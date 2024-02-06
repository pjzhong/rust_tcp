use std::{io, thread};

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;

    let mut l1 = i.bind(6000)?;

    let jh1 = thread::spawn(move || {
        while let Ok(_) = l1.accept() {
            println!("l1 accept connection");
        }
    });

    let _ = jh1.join();

    Ok(())
}
