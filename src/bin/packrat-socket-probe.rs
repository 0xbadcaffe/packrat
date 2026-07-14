#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let listener_address = listener.local_addr()?;
    let client = std::thread::spawn(move || -> std::io::Result<()> {
        let mut stream = TcpStream::connect(listener_address)?;
        stream.write_all(b"packrat lifecycle probe")
    });
    let (mut accepted, _) = listener.accept()?;
    let mut payload = [0_u8; 64];
    let _ = accepted.read(&mut payload)?;
    client.join().map_err(|_| "TCP probe thread panicked")??;

    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.send_to(b"packrat lifecycle probe", receiver.local_addr()?)?;
    let _ = receiver.recv_from(&mut payload)?;

    println!("generated loopback TCP accept/connect and UDP send/receive traffic");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("packrat-socket-probe requires Linux");
    std::process::exit(2);
}
