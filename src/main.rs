use std::net::UdpSocket;
use hex;

mod dns;
use dns::Header;

fn debug_print_bytes(buf: &[u8]) -> String {
    buf.chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            // Format the offset
            let offset = format!("{:08x}: ", i * 16);
            
            // Format the hex representation with proper spacing
            let hex_part = chunk
                .iter()
                .map(|byte| format!("{:02x} ", byte))
                .collect::<String>();
                
            // Add padding if chunk is not full
            let padding = "   ".repeat(16 - chunk.len());
            
            // Format the ASCII representation with spacing
            let ascii_part = chunk
                .iter()
                .map(|&byte| {
                    if (32..=126).contains(&byte) {
                        format!("{} ", byte as char)
                    } else {
                        ". ".to_string()
                    }
                })
                .collect::<String>();
                
            format!("{}{}{} {}", offset, hex_part, padding, ascii_part)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:1053").expect("Could not bind to port 1053");
    let mut buf = [0; 512];

    println!("DNS server running at port 1053");


    loop {
        let (len, addr) = socket.recv_from(&mut buf).expect("Could not receive data");
        println!("{:02x?}", &buf);
        debug_print_bytes(&buf);
        let header = Header::from_bytes(&buf[..len]).expect("Could not parse DNS header");
        println!("Received header from {} {:?}", addr, header);
        //print!("{}", debug_print_bytes(&buf));
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_print_bytes_does_not_err() {
        //[14, f, 1, 20, 0, 1, 0, 0, 0, 0, 0, 1, 8, 68, 61, 73, 68, 62, 61, 6e, 67, 2, 6e, 6c, 0, 0, 1, 0, 1, 0, 0, 29, 10,
        let stub = hex::decode("29f701200001000000000001").unwrap();
        let string_output = debug_print_bytes(&stub);
        assert_eq!(string_output, "00000000: 29 f7 01 20 00 01 00 00 00 00 00 01              ) . .   . . . . . . . . ");
    }
}
