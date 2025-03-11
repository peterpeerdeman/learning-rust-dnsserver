use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErrorCondition {
    #[error("Serialization Error: {0}")]
    SerializationErr(String),

    #[error("Deserialization Error: {0}")]
    DeserializationErr(String),
}

/*
 * DNS Header of 12 bytes:
 *
 * 0000 0000 0000 0001 = Id: 1
 * 1... .... .... .... = Response: Message is a response
 * .000 0... .... .... = Opcode: Standard query (0)
 * .... .0.. .... .... = Authoritative: Server is not an authority for domain
 * .... ..0. .... .... = Truncated: Message is not truncated
 * .... ...1 .... .... = Recursion desired: Do query recursively
 * .... .... 1... .... = Recursion available: Server can do recursive queries
 * .... .... .0.. .... = Z: reserved (0)
 * .... .... ..1. .... = Answer authenticated: Answer/authority portion was authenticated by the server
 * .... .... ...0 .... = Non-authenticated data: Unacceptable
 * .... .... .... 0000 = Reply code: No error (0)
 * 0000 0000 0000 0001 = Questions: 1
 * 0000 0000 0000 0001 = Answer RRs: 1
 * 0000 0000 0000 0000 = Authority RRs: 0
 * 0000 0000 0000 0001 = Additional RRs: 1
 */

#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub authorative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub z: bool,
    pub answer_authenticated: bool,
    pub non_authenticated: bool,
    pub rcode: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub nameserver_count: u16,
    pub additional_count: u16
}


impl Header {
    const DNS_HEADER_LEN: usize = 12;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Header::DNS_HEADER_LEN);

        buf.extend_from_slice(&self.id.to_be_bytes()); // this is the first byte
        buf.push(
            (self.response as u8) << 7 //bitshifted to fill big endian b
            | self.opcode << 3
            | (self.authorative as u8) << 2
            | (self.truncated as u8) << 1
            | self.recursion_desired as u8,
         );
        buf.push(
            (self.recursion_available as u8) << 7
            | (self.z as u8) << 6
            | (self.answer_authenticated as u8) << 5
            | (self.non_authenticated as u8) << 4
            | self.rcode
        );
        buf.extend_from_slice(&self.question_count.to_be_bytes());
        buf.extend_from_slice(&self.answer_count.to_be_bytes());
        buf.extend_from_slice(&self.nameserver_count.to_be_bytes());
        buf.extend_from_slice(&self.additional_count.to_be_bytes());
     buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Header, ErrorCondition> {
        if buf.len() < Header::DNS_HEADER_LEN {
            return Err(ErrorCondition::DeserializationErr(
                "Buffer length is less than header length".to_string(),
            ));
        }

        Ok(Header {
            id: u16::from_be_bytes([buf[0],buf[1]]),
            response: (buf[2] & 0b1000_0000) != 0,
            opcode: (buf[2] & 0b0111_1000) >> 3,
            authorative: (buf[2] & 0b0000_0100) != 0,
            truncated: (buf[2] & 0b0000_0010) != 0,
            recursion_desired: (buf[2] & 0b0000_0001) != 0,
            recursion_available: (buf[3] & 0b1000_0000) != 0,
            z: (buf[3] & 0b0100_0000) != 0,
            answer_authenticated: (buf[3] & 0b0010_0000) != 0,
            non_authenticated: (buf[3] & 0b0001_0000) != 0,
            rcode: (buf[3] & 0b0000_1111),
            question_count: u16::from_be_bytes([buf[4], buf[5]]),
            answer_count: u16::from_be_bytes([buf[6], buf[7]]),
            nameserver_count: u16::from_be_bytes([buf[8], buf[9]]),
            additional_count: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_does_not_err() {
        //let buf: [u8; 12] = [0x01, 0x02,0x01, 0x02,0x01, 0x02,0x01, 0x02, 0x01, 0x02,0x01, 0x02];
        let hex_stream = hex::decode("29f701200001000000000001").unwrap();

        let header = Header::from_bytes(&hex_stream).unwrap();
        assert_eq!(header.id, 0x29f7);
        assert_eq!(header.id, 0x29f7);
        println!("{:?}", header);
    }

    #[test]
    fn to_bytes_does_not_err() {
        let test_header = Header { 
            id: 10743, 
            response: false, 
            opcode: 0, 
            authorative: false, 
            truncated: false, 
            recursion_desired: true, 
            recursion_available: false, 
            z: false, 
            answer_authenticated: true, 
            non_authenticated: false, 
            rcode: 0, 
            question_count: 1, 
            answer_count: 0, 
            nameserver_count: 0, 
            additional_count: 1 
        };

        let buf = Header::to_bytes(&test_header);
        assert_eq!(hex::encode(&buf), "29f701200001000000000001");
        println!("{:?}", buf);
    }


}
