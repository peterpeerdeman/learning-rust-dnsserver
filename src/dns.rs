use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErrorCondition {
    #[error("Serialization Error: {0}")]
    SerializationErr(String),

    #[error("Deserialization Error: {0}")]
    DeserializationErr(String),

    #[error("Invalid Label Error: {0}")]
    InvalidLabel(String),
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

#[derive(Debug)]
pub struct Question {
    pub name: Vec<Label>,
    pub qtype: Type,
    pub qclass: Class,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Label(String);

impl Label {
    pub fn new(label: &[u8]) -> Result<Self, ErrorCondition> {
        match std::str::from_utf8(label) {
            Ok(s) => Ok(Label(s.to_string())),
            Err(_) => Err(ErrorCondition::InvalidLabel("this label is not valid".to_string())),
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    // Below are Resource Record Types and QTYPES
    A = 1, // a host address
    NS = 2, // an authoritative name server
    MD = 3, // a mail destination (Obsolete - use MX)
    MF = 4, // a mail forwarder (Obsolete - use MX)
    CNAME = 5, // the canonical name for an alias
    SOA = 6, // marks the start of a zone of authority
    MB = 7, // a mailbox domain name (EXPERIMENTAL)
    MG = 8, // a mail group member (EXPERIMENTAL)
    MR = 9, // a mail rename domain name (EXPERIMENTAL)
    NULL = 10, // a null RR (EXPERIMENTAL)
    WKS = 11, // a well known service description
    PTR = 12, // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX = 15, // mail exchange
    TXT = 16, // text strings
    AAAA = 28, // a ipv6 host address

    // Below are only QTYPES
    AXFR = 252, // A request for a transfer of an entire zone
    MAILB = 253, // A request for mailbox-related records (MB, MG or MR)
    MAILA = 254, // A request for mail agent RRs (Obsolete - see MX)
    _ALL_ = 255, // A request for all records
}

impl Type {
    pub fn from_bytes(bytes: &[u8]) -> Result<Type, ErrorCondition> {
        match u16::from_be_bytes([bytes[0], bytes[1]]) {
            1 => Ok(Type::A),
            2 => Ok(Type::NS),
            3 => Ok(Type::MD),
            4 => Ok(Type::MF),
            5 => Ok(Type::CNAME),
            6 => Ok(Type::SOA),
            7 => Ok(Type::MB),
            8 => Ok(Type::MG),
            9 => Ok(Type::MR),
            10 => Ok(Type::NULL),
            11 => Ok(Type::WKS),
            12 => Ok(Type::PTR),
            13 => Ok(Type::HINFO),
            14 => Ok(Type::MINFO),
            15 => Ok(Type::MX),
            16 => Ok(Type::TXT),
            252 => Ok(Type::AXFR),
            253 => Ok(Type::MAILB),
            254 => Ok(Type::MAILA),
            255 => Ok(Type::_ALL_),
            n => Err(ErrorCondition::DeserializationErr(
                format!("Unknown Question Type {}", n).to_string(),
            )),
        }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let num = match self {
            Type::A => 1,
            Type::NS => 2,
            Type::MD => 3,
            Type::MF => 4,
            Type::CNAME => 5,
            Type::SOA => 6,
            Type::MB => 7,
            Type::MG => 8,
            Type::MR => 9,
            Type::NULL => 10,
            Type::WKS => 11,
            Type::PTR => 12,
            Type::HINFO => 13,
            Type::MINFO => 14,
            Type::MX => 15,
            Type::TXT => 16,
            Type::AAAA => 28,
            Type::AXFR => 252,
            Type::MAILB => 253,
            Type::MAILA => 254,
            Type::_ALL_ => 255,
        };

        u16::to_be_bytes(num)
    }
}

#[derive(Debug, Clone)]
pub enum Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    _ALL_ = 255,
}

impl Class {
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ErrorCondition> {
        let num = u16::from_be_bytes([buf[0], buf[1]]);
        match num {
            1 => Ok(Class::IN),
            2 => Ok(Class::CS),
            3 => Ok(Class::CH),
            4 => Ok(Class::HS),
            _ => Err(ErrorCondition::DeserializationErr(
                format!("Unknown Question Class {}", num).to_string(),
            )),
        }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let num = match self {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
            Class::_ALL_ => 255,
        };

        u16::to_be_bytes(num)
    }
}

impl Question {
    pub fn from_bytes(buf: &[u8]) -> Result<Question, ErrorCondition> {
        let mut index = 0;
        let mut labels: Vec<Label> = Vec::new();

        while buf[index] != 0 {
            let length: usize = buf[index] as usize;
            index += 1;
            labels.push(Label::new(&buf[index..index+length])?);
            index += length;
        }
        println!("{:?}", labels);

        index += 1; //skip over the 0 terminator

        let qtype = Type::from_bytes(&buf[index..index + 2])?;

        index += 2; //skip over the 0 terminator

        let qclass = Class::from_bytes(&buf[index..index + 2])?;
             
        Ok(Question {
            name: labels,
            qtype,
            qclass,
            //id: u16::from_be_bytes([buf[0],buf[1]]),
            //response: (buf[2] & 0b1000_0000) != 0,
            //opcode: (buf[2] & 0b0111_1000) >> 3,
            //authorative: (buf[2] & 0b0000_0100) != 0,
            //truncated: (buf[2] & 0b0000_0010) != 0,
            //recursion_desired: (buf[2] & 0b0000_0001) != 0,
            //recursion_available: (buf[3] & 0b1000_0000) != 0,
            //z: (buf[3] & 0b0100_0000) != 0,
            //answer_authenticated: (buf[3] & 0b0010_0000) != 0,
            //non_authenticated: (buf[3] & 0b0001_0000) != 0,
            //rcode: (buf[3] & 0b0000_1111),
            //question_count: u16::from_be_bytes([buf[4], buf[5]]),
            //answer_count: u16::from_be_bytes([buf[6], buf[7]]),
            //nameserver_count: u16::from_be_bytes([buf[8], buf[9]]),
            //additional_count: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
    //pub fn to_bytes(&self) -> Vec<u8> {
    //    let mut buf = Vec::with_capacity(Header::DNS_HEADER_LEN);
    //
    //    buf.extend_from_slice(&self.id.to_be_bytes()); // this is the first byte
    //    buf.push(
    //        (self.response as u8) << 7 //bitshifted to fill big endian b
    //        | self.opcode << 3
    //        | (self.authorative as u8) << 2
    //        | (self.truncated as u8) << 1
    //        | self.recursion_desired as u8,
    //     );
    //    buf.push(
    //        (self.recursion_available as u8) << 7
    //        | (self.z as u8) << 6
    //        | (self.answer_authenticated as u8) << 5
    //        | (self.non_authenticated as u8) << 4
    //        | self.rcode
    //    );
    //    buf.extend_from_slice(&self.question_count.to_be_bytes());
    //    buf.extend_from_slice(&self.answer_count.to_be_bytes());
    //    buf.extend_from_slice(&self.nameserver_count.to_be_bytes());
    //    buf.extend_from_slice(&self.additional_count.to_be_bytes());
    // buf
    //}

}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_from_bytes_does_not_err() {
        let hex_stream = hex::decode("29f701200001000000000001").unwrap();

        let header = Header::from_bytes(&hex_stream).unwrap();
        assert_eq!(header.id, 0x29f7);
        assert_eq!(header.id, 0x29f7);
        println!("{:?}", header);
    }

    #[test]
    fn header_to_bytes_does_not_err() {
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

    #[test]
    fn question_from_bytes_does_not_err() {
        let dnspacket_stub = vec![0xc7, 0x7f, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x68, 0x61, 0x73, 0x68, 0x62, 0x61, 0x6e, 0x67, 0x02, 0x6e, 0x6c, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10];
        let question_stub = dnspacket_stub.into_iter().skip(12).collect::<Vec<u8>>();
        let question = Question::from_bytes(&question_stub).unwrap();
        println!("{:?}", question);
        assert_eq!(question.qtype, Type::A);
        assert_eq!(question.name[0], Label("hashbang".to_string()));
    }

}
