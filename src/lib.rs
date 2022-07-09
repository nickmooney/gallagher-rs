use std::fmt;

const ENCODE_TABLE: [u8; 256] = *b"\xa3\xb0\x80\xc6\xb2\xf4\\l\x81\xf1\xbb\xebUg<\x05\x1a\x0ea\xf6\"\xce\xaa\x8f\xbd;\x1f^D\x04Q.M\x9a\x84\xea\xf8ft)\x7fp\xd81zm\xa4\x00\x82\xb9_\xb4\x16\xab\xff\xc29\xdc\x19eW| \xfaZI\x13\xd0\xfb\xa8\x91s\xb13\x18\xbe!rH\xb6\xdb\xa0]\xcc\xe6\x17\'\xe5\xd4SB\xf3\xdd{$\xac+X\x1e\xa7\xe7\x86@\xd3\x98\x97q\xcb:\x0f\x01\x9bn\x1b\xfc4\xa6\xda\x07\x0c\xae7\xcaT\xfd&\xfe\nE\xa2*\xc4\x12\r\xf5Oi\xe0\x8aw`?\x99\x95\xd286b\xb72~y\xc0F\x93/\xa5\xba[\xafR\x1d\xc3u\xcf\xd6L\x83\xe8=0N\xbc\x08-\t\x06\xd9%\x9e\x89\xf2\x96\x88\xc1\x8c\x94\x0b(\xf0Gc\xd5\xb3hV\x9c\xf9oAP\x85\x8b\x9dY\xbf\x9f\xe2\x8ej\x11#\xa1\xcd\xb5}\xc7\xa9\xc8\xef\xdf\x02\xb8\x03k5>,v\xc9\xde\x1cK\xd1\xed\x14\xc5\xad\xe9dJ\xec\x8d\xf7\x10Cx\x15\x87\xe4\xd7\x92\xe1\xee\xe3\x90";
const DECODE_TABLE: [u8; 256] = *b"/n\xdd\xdf\x1d\x0f\xb0v\xad\xaf\x7f\xbbw\x85\x11m\xf4\xd2\x84B\xeb\xf74UJ:\x10q\xe7\xa1b\x1a>L\x14\xd3^\xb2}V\xbc\'\x82`\xe3\xae\x1f\x9b\xaa+\x95Is\xe1\x92y\x918l\x19\x0e\xa9\xe2\x8df\xc7Z\xf5\x1c\x80\x99\xbeNA\xf0\xe8\xa6 \xab\x87\xc8\x1e\xa0Y{\x0c\xc3<a\xcc@\x9e\x06R\x1b2\x8c\x12\x93\xbf\xef;%\r\xc2\x88\xd1\xe0\x07-p\xc6)jMG&\xa3\xe4\x8b\xf6\x97,]=\xd7\x96(\x02\x080\xa7\"\xc9e\xf8\xb7\xb4\x8a\xca\xb9\xf2\xd0\x17\xffF\xfb\x9a\xba\x8f\xb6ih\x8e!o\xc4\xcb\xb3\xceQ\xd4\x81\x00.\x9ctcE\xd9\x165_\xedx\x9f\x01H\x04\xc13\xd6O\x94\xde1\x9d\n\xac\x18K\xcd\x98\xb87\xa2\x83\xec\x03\xd8\xda\xe5zkS\xd5\x15\xa4C\xe9\x90gX\xc0\xa5\xfa*\xb1uP9\\\xe6\xdc\x89\xfc\xcf\xfe\xf9WTd\xa8\xee#\x0b\xf1\xea\xfd\xdb\xbd\t\xb5[\x05\x86\x13\xf3$\xc5?Dr|~6";

pub struct Credential {
    pub region: u8,
    pub facility: u16,
    pub card: u32,
    pub issue: u8,
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "RC: {}, FC: {}, CN: {}, IN: {}",
            self.region, self.facility, self.card, self.issue
        )
    }
}

pub fn gallagher_decode(credential_bytes: &[u8]) -> Credential {
    let deobfuscated = gallagher_substitute_decode(credential_bytes);
    Credential {
        region: (deobfuscated[3] >> 1) & 0x0F,
        facility: ((deobfuscated[5] as u16 & 0x0F) << 12)
            + ((deobfuscated[1] as u16) << 4)
            + (((deobfuscated[7] as u16) >> 4) & 0x0F),
        card: ((deobfuscated[0] as u32) << 16)
            + ((deobfuscated[4] as u32 & 0x1F) << 11)
            + ((deobfuscated[2] as u32) << 3)
            + (((deobfuscated[3] as u32) >> 5) & 0x07),
        issue: deobfuscated[7] & 0x0F,
    }
}

pub fn gallagher_encode(credential: &Credential) -> Vec<u8> {
    gallagher_substitute_encode(&[
        ((credential.card >> 16) & 0xFF) as u8,
        ((credential.facility >> 4) & 0xFF) as u8,
        ((credential.card >> 3) & 0xFF) as u8,
        (((credential.card & 0x07) << 5) as u8 + (credential.region << 1)),
        ((credential.card >> 11) as u8) & 0x1F,
        ((credential.facility >> 12) as u8) & 0x0F,
        0, // UC, UD
        ((credential.facility << 4) as u8) + (credential.issue & 0x0F),
    ])
}

fn gallagher_substitute_decode(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    for val in bytes {
        decoded.push(DECODE_TABLE[*val as usize]);
    }
    decoded
}

fn gallagher_substitute_encode(bytes: &[u8; 8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for val in bytes {
        encoded.push(ENCODE_TABLE[*val as usize]);
    }
    encoded
}

pub fn invert_bits(bytes: &[u8]) -> Vec<u8> {
    let mut inverted = Vec::new();
    for val in bytes {
        inverted.push(!val)
    }
    inverted
}
