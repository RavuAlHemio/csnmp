use std::io::Write;

use der_parser::ber::{Class, Tag};

use crate::message::SnmpMessageError;
use crate::oid::ObjectIdentifier;


fn write_raw_asn1_u128<W: Write>(mut write: W, integer: u128) -> Result<usize, SnmpMessageError> {
    let byte_array = integer.to_be_bytes();
    let mut byte_slice = &byte_array[..];

    // always use the shortest encoding
    // this is enforced by specifying that bytes[0] and the topmost bit of bytes[1]
    // must not all be 0, as this means that the first byte may be stripped away
    while byte_slice.len() > 1 && byte_slice[0] == 0x00 && (byte_slice[1] >> 7) == 0 {
        byte_slice = &byte_slice[1..];
    }

    // is the topmost bit set?
    // (this gets interpreted as the sign bit, which doesn't make sense for uint)
    if (byte_slice[0] & (1 << 7)) != 0 {
        // yes; prepend a zero
        write.write_all(&[0x00])
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })?;
        write.write_all(byte_slice)
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })?;
        Ok(1 + byte_slice.len())
    } else {
        // no; take the number verbatim
        write.write_all(byte_slice)
            .map(|_| byte_slice.len())
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })
    }
}

fn write_raw_asn1_i128<W: Write>(mut write: W, integer: i128) -> Result<usize, SnmpMessageError> {
    let byte_array = integer.to_be_bytes();
    let mut byte_slice = &byte_array[..];

    // always use the shortest encoding
    // this is enforced by specifying that bytes[0] and the topmost bit of bytes[1]
    // must neither all be 0 nor all be 1, as this means that the first byte may be
    // stripped away
    let mut stripped = false;
    while byte_slice.len() > 1 && byte_slice[0] == 0x00 && (byte_slice[1] >> 7) == 0b0 {
        byte_slice = &byte_slice[1..];
        stripped = true;
    }
    if !stripped {
        // perhaps we can strip away leading 1s instead
        while byte_slice.len() > 1 && byte_slice[0] == 0xFF && (byte_slice[1] >> 7) == 0b1 {
            byte_slice = &byte_slice[1..];
        }
    }

    if integer >= 0 && (byte_slice[0] & (1 << 7)) != 0 {
        // top bit (sign) is set but we are not a negative number
        // prepend a zero
        write.write_all(&[0x00])
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })?;
        write.write_all(byte_slice)
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })?;
        Ok(1 + byte_slice.len())
    } else {
        write.write_all(byte_slice)
            .map(|_| byte_slice.len())
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })
    }
}

fn write_encoding<W: Write>(mut write: W, class: Class, constructed: bool, tag: Tag) -> Result<usize, SnmpMessageError> {
    let class_bits = class as u8;
    let tag_bits = tag.0;

    if tag_bits > 30 {
        // we need multiple bytes
        let mut header_bytes = Vec::new();

        // shave off 7 bits each time
        let mut remaining_tag_bits = tag_bits;
        while remaining_tag_bits > 0 {
            header_bytes.push((remaining_tag_bits & 0b0111_1111) as u8);
            remaining_tag_bits >>= 7;
        }

        // append the initial header byte
        let header_byte =
            (class_bits << 6)
            | (if constructed { 1 << 5 } else { 0 })
            | (0b0001_1111);
        header_bytes.push(header_byte);

        // reverse the header bytes
        header_bytes.reverse();

        // set the continuation bit (top bit) for all header bytes
        // except the first (interferes with class bits) and last (tag ends there)
        let header_bytes_len = header_bytes.len();
        for b in &mut header_bytes[1..header_bytes_len-1] {
            *b |= 0b1000_0000;
        }

        write.write_all(&header_bytes)
            .map(|_| header_bytes.len())
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })
    } else {
        // we can get away with just one byte

        let header_byte =
            (class_bits << 6)
            | (if constructed { 1 << 5 } else { 0 })
            | (tag_bits as u8);
        write.write_all(&[header_byte])
            .map(|_| 1)
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })
    }
}

fn write_length<W: Write>(mut write: W, length: usize) -> Result<usize, SnmpMessageError> {
    let length_byte_array = length.to_be_bytes();
    let mut length_byte_slice = &length_byte_array[..];

    // strip leading zero bytes
    while length_byte_slice.len() > 1 && length_byte_slice[0] == 0x00 {
        length_byte_slice = &length_byte_slice[1..];
    }

    if length_byte_slice.len() == 1 && length_byte_slice[0] < 128 {
        // single byte
        write.write_all(&[length_byte_slice[0]])
            .map(|_| 1)
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })
    } else {
        // multiple bytes
        assert!(length_byte_slice.len() < 127);
        let first_byte = 0b1000_0000 | u8::try_from(length_byte_slice.len()).unwrap();
        write.write_all(&[first_byte])
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })?;
        write.write_all(length_byte_slice)
            .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })?;
        Ok(1 + length_byte_slice.len())
    }
}

pub(crate) fn write_wrapped<W: Write>(mut write: W, class: Class, constructed: bool, tag: Tag, bytes: &[u8]) -> Result<usize, SnmpMessageError> {
    let mut total_written = 0;
    total_written += write_encoding(&mut write, class, constructed, tag)?;
    total_written += write_length(&mut write, bytes.len())?;
    write.write_all(&bytes)
        .map_err(|error| SnmpMessageError::Asn1EncodingIO { error })?;
    total_written += bytes.len();
    Ok(total_written)
}

pub(crate) fn write_u128<W: Write>(write: W, integer: u128, class: Option<Class>, tag: Option<Tag>) -> Result<usize, SnmpMessageError> {
    let class = class.unwrap_or(Class::Universal);
    let tag = tag.unwrap_or(Tag::Integer);

    let mut integer_bytes = Vec::with_capacity(17);
    write_raw_asn1_u128(&mut integer_bytes, integer).unwrap();

    write_wrapped(write, class, false, tag, &integer_bytes)
}

pub(crate) fn write_i128<W: Write>(write: W, integer: i128, class: Option<Class>, tag: Option<Tag>) -> Result<usize, SnmpMessageError> {
    let class = class.unwrap_or(Class::Universal);
    let tag = tag.unwrap_or(Tag::Integer);

    let mut integer_bytes = Vec::with_capacity(17);
    write_raw_asn1_i128(&mut integer_bytes, integer).unwrap();

    write_wrapped(write, class, false, tag, &integer_bytes)
}

pub(crate) fn write_octet_string<W: Write>(write: W, octets: &[u8], class: Option<Class>, tag: Option<Tag>) -> Result<usize, SnmpMessageError> {
    let class = class.unwrap_or(Class::Universal);
    let tag = tag.unwrap_or(Tag::OctetString);

    write_wrapped(write, class, false, tag, octets)
}

pub(crate) fn write_oid<W: Write>(write: W, oid: &ObjectIdentifier, class: Option<Class>, tag: Option<Tag>) -> Result<usize, SnmpMessageError> {
    let class = class.unwrap_or(Class::Universal);
    let tag = tag.unwrap_or(Tag::Oid);

    let oid_slice = oid.as_slice();
    if oid_slice.len() < 2 {
        return Err(SnmpMessageError::Length { expected: 2, obtained: oid.len() });
    }
    if (oid_slice[0] == 1 || oid_slice[0] == 2) && oid_slice[1] >= 40 {
        return Err(SnmpMessageError::OidInvalidInitialPair { first: oid_slice[0], second: oid_slice[1] });
    }
    let first_integer = oid_slice[0].checked_mul(40).unwrap().checked_add(oid_slice[1]).unwrap();

    let mut buffer = Vec::new();
    let mut slicer = Vec::with_capacity(5);
    for piece in std::iter::once(&first_integer).chain(&oid_slice[2..]) {
        if *piece == 0 {
            buffer.push(0x00);
            continue;
        }

        slicer.clear();
        let mut remaining = *piece;
        while remaining > 0 {
            slicer.push((remaining & 0b0111_1111) as u8);
            remaining >>= 7;
        }

        // we shaved off the least-significant bits first
        slicer.reverse();

        // set top bit on all except last byte
        let slicer_len = slicer.len();
        for byte in &mut slicer[0..slicer_len-1] {
            *byte |= 0b1000_0000;
        }

        buffer.extend(&slicer);
    }

    write_wrapped(write, class, false, tag, &buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! encoding_function {
        ($encode_name:ident, $val_type:ty, $write_name:ident) => {
            fn $encode_name(value: $val_type) -> Vec<u8> {
                let mut vector = Vec::new();
                $write_name(&mut vector, value).unwrap();
                vector
            }
        };
        ($encode_name:ident, $val_type:ty, $write_name:ident, CLASS_TAG) => {
            fn $encode_name(value: $val_type) -> Vec<u8> {
                let mut vector = Vec::new();
                $write_name(&mut vector, value, None, None).unwrap();
                vector
            }
        };
    }
    encoding_function!(raw_encode_asn1_u128, u128, write_raw_asn1_u128);
    encoding_function!(raw_encode_asn1_i128, i128, write_raw_asn1_i128);
    encoding_function!(encode_u128, u128, write_u128, CLASS_TAG);
    encoding_function!(encode_i128, i128, write_i128, CLASS_TAG);
    encoding_function!(encode_octet_string, &[u8], write_octet_string, CLASS_TAG);
    encoding_function!(encode_length, usize, write_length);
    fn encode_encoding(class: Class, constructed: bool, tag: Tag) -> Vec<u8> {
        let mut vector = Vec::new();
        write_encoding(&mut vector, class, constructed, tag).unwrap();
        vector
    }

    fn repeat(byte: u8, count: usize) -> Vec<u8> {
        let mut ret = Vec::with_capacity(count);
        for _ in 0..count {
            ret.push(byte);
        }
        ret
    }

    #[test]
    fn test_length_encoding() {
        assert_eq!(encode_length(0), vec![0x00]);
        assert_eq!(encode_length(1), vec![0x01]);
        assert_eq!(encode_length(2), vec![0x02]);
        assert_eq!(encode_length(127), vec![0x7F]);
        assert_eq!(encode_length(128), vec![0x81, 0x80]);
        assert_eq!(encode_length(129), vec![0x81, 0x81]);
        assert_eq!(encode_length(130), vec![0x81, 0x82]);
        assert_eq!(encode_length(254), vec![0x81, 0xFE]);
        assert_eq!(encode_length(255), vec![0x81, 0xFF]);
        assert_eq!(encode_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(encode_length(257), vec![0x82, 0x01, 0x01]);
        assert_eq!(encode_length(65535), vec![0x82, 0xFF, 0xFF]);
        assert_eq!(encode_length(65536), vec![0x83, 0x01, 0x00, 0x00]);
        assert_eq!(encode_length(65537), vec![0x83, 0x01, 0x00, 0x01]);
        assert_eq!(encode_length(65537), vec![0x83, 0x01, 0x00, 0x01]);
        assert_eq!(encode_length(16777215), vec![0x83, 0xFF, 0xFF, 0xFF]);
        assert_eq!(encode_length(16777216), vec![0x84, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(encode_length(16777217), vec![0x84, 0x01, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_encoding_encoding() {
        // tag 0
        assert_eq!(encode_encoding(Class::Universal, false, Tag::EndOfContent), vec![0b0000_0000]);
        assert_eq!(encode_encoding(Class::Universal, true, Tag::EndOfContent), vec![0b0010_0000]);
        assert_eq!(encode_encoding(Class::Application, false, Tag::EndOfContent), vec![0b0100_0000]);
        assert_eq!(encode_encoding(Class::Application, true, Tag::EndOfContent), vec![0b0110_0000]);
        assert_eq!(encode_encoding(Class::ContextSpecific, false, Tag::EndOfContent), vec![0b1000_0000]);
        assert_eq!(encode_encoding(Class::ContextSpecific, true, Tag::EndOfContent), vec![0b1010_0000]);
        assert_eq!(encode_encoding(Class::Private, false, Tag::EndOfContent), vec![0b1100_0000]);
        assert_eq!(encode_encoding(Class::Private, true, Tag::EndOfContent), vec![0b1110_0000]);

        // tag 30
        assert_eq!(encode_encoding(Class::Universal, false, Tag::BmpString), vec![0b0001_1110]);
        assert_eq!(encode_encoding(Class::Universal, true, Tag::BmpString), vec![0b0011_1110]);
        assert_eq!(encode_encoding(Class::Application, false, Tag::BmpString), vec![0b0101_1110]);
        assert_eq!(encode_encoding(Class::Application, true, Tag::BmpString), vec![0b0111_1110]);
        assert_eq!(encode_encoding(Class::ContextSpecific, false, Tag::BmpString), vec![0b1001_1110]);
        assert_eq!(encode_encoding(Class::ContextSpecific, true, Tag::BmpString), vec![0b1011_1110]);
        assert_eq!(encode_encoding(Class::Private, false, Tag::BmpString), vec![0b1101_1110]);
        assert_eq!(encode_encoding(Class::Private, true, Tag::BmpString), vec![0b1111_1110]);

        // tag 31
        assert_eq!(encode_encoding(Class::Universal, false, Tag(31)), vec![0b0001_1111, 0b0001_1111]);
        assert_eq!(encode_encoding(Class::Universal, true, Tag(31)), vec![0b0011_1111, 0b0001_1111]);
        assert_eq!(encode_encoding(Class::Application, false, Tag(31)), vec![0b0101_1111, 0b0001_1111]);
        assert_eq!(encode_encoding(Class::Application, true, Tag(31)), vec![0b0111_1111, 0b0001_1111]);
        assert_eq!(encode_encoding(Class::ContextSpecific, false, Tag(31)), vec![0b1001_1111, 0b0001_1111]);
        assert_eq!(encode_encoding(Class::ContextSpecific, true, Tag(31)), vec![0b1011_1111, 0b0001_1111]);
        assert_eq!(encode_encoding(Class::Private, false, Tag(31)), vec![0b1101_1111, 0b0001_1111]);
        assert_eq!(encode_encoding(Class::Private, true, Tag(31)), vec![0b1111_1111, 0b0001_1111]);

        // tag 127
        assert_eq!(encode_encoding(Class::Universal, false, Tag(127)), vec![0b0001_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Universal, true, Tag(127)), vec![0b0011_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Application, false, Tag(127)), vec![0b0101_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Application, true, Tag(127)), vec![0b0111_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::ContextSpecific, false, Tag(127)), vec![0b1001_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::ContextSpecific, true, Tag(127)), vec![0b1011_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Private, false, Tag(127)), vec![0b1101_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Private, true, Tag(127)), vec![0b1111_1111, 0b0111_1111]);

        // tag 128
        assert_eq!(encode_encoding(Class::Universal, false, Tag(128)), vec![0b0001_1111, 0b1000_0001, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Universal, true, Tag(128)), vec![0b0011_1111, 0b1000_0001, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Application, false, Tag(128)), vec![0b0101_1111, 0b1000_0001, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Application, true, Tag(128)), vec![0b0111_1111, 0b1000_0001, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::ContextSpecific, false, Tag(128)), vec![0b1001_1111, 0b1000_0001, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::ContextSpecific, true, Tag(128)), vec![0b1011_1111, 0b1000_0001, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Private, false, Tag(128)), vec![0b1101_1111, 0b1000_0001, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Private, true, Tag(128)), vec![0b1111_1111, 0b1000_0001, 0b0000_0000]);

        // tag 16383
        assert_eq!(encode_encoding(Class::Universal, false, Tag(16383)), vec![0b0001_1111, 0b1111_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Universal, true, Tag(16383)), vec![0b0011_1111, 0b1111_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Application, false, Tag(16383)), vec![0b0101_1111, 0b1111_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Application, true, Tag(16383)), vec![0b0111_1111, 0b1111_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::ContextSpecific, false, Tag(16383)), vec![0b1001_1111, 0b1111_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::ContextSpecific, true, Tag(16383)), vec![0b1011_1111, 0b1111_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Private, false, Tag(16383)), vec![0b1101_1111, 0b1111_1111, 0b0111_1111]);
        assert_eq!(encode_encoding(Class::Private, true, Tag(16383)), vec![0b1111_1111, 0b1111_1111, 0b0111_1111]);

        // tag 16384
        assert_eq!(encode_encoding(Class::Universal, false, Tag(16384)), vec![0b0001_1111, 0b1000_0001, 0b1000_0000, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Universal, true, Tag(16384)), vec![0b0011_1111, 0b1000_0001, 0b1000_0000, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Application, false, Tag(16384)), vec![0b0101_1111, 0b1000_0001, 0b1000_0000, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Application, true, Tag(16384)), vec![0b0111_1111, 0b1000_0001, 0b1000_0000, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::ContextSpecific, false, Tag(16384)), vec![0b1001_1111, 0b1000_0001, 0b1000_0000, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::ContextSpecific, true, Tag(16384)), vec![0b1011_1111, 0b1000_0001, 0b1000_0000, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Private, false, Tag(16384)), vec![0b1101_1111, 0b1000_0001, 0b1000_0000, 0b0000_0000]);
        assert_eq!(encode_encoding(Class::Private, true, Tag(16384)), vec![0b1111_1111, 0b1000_0001, 0b1000_0000, 0b0000_0000]);
    }

    #[test]
    fn test_integer_encoding() {
        assert_eq!(raw_encode_asn1_u128(0), vec![0x00]);
        assert_eq!(raw_encode_asn1_u128(1), vec![0x01]);
        assert_eq!(raw_encode_asn1_u128(42), vec![0x2A]);
        assert_eq!(raw_encode_asn1_u128(127), vec![0x7F]);
        assert_eq!(raw_encode_asn1_u128(128), vec![0x00, 0x80]);
        assert_eq!(raw_encode_asn1_u128(129), vec![0x00, 0x81]);
        assert_eq!(raw_encode_asn1_u128(255), vec![0x00, 0xFF]);
        assert_eq!(raw_encode_asn1_u128(256), vec![0x01, 0x00]);
        assert_eq!(raw_encode_asn1_u128(32767), vec![0x7F, 0xFF]);
        assert_eq!(raw_encode_asn1_u128(32768), vec![0x00, 0x80, 0x00]);
        assert_eq!(raw_encode_asn1_u128(32769), vec![0x00, 0x80, 0x01]);
        assert_eq!(raw_encode_asn1_u128(0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF), vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        assert_eq!(raw_encode_asn1_i128(0), vec![0x00]);
        assert_eq!(raw_encode_asn1_i128(1), vec![0x01]);
        assert_eq!(raw_encode_asn1_i128(42), vec![0x2A]);
        assert_eq!(raw_encode_asn1_i128(127), vec![0x7F]);
        assert_eq!(raw_encode_asn1_i128(128), vec![0x00, 0x80]);
        assert_eq!(raw_encode_asn1_i128(129), vec![0x00, 0x81]);
        assert_eq!(raw_encode_asn1_i128(255), vec![0x00, 0xFF]);
        assert_eq!(raw_encode_asn1_i128(256), vec![0x01, 0x00]);
        assert_eq!(raw_encode_asn1_i128(32767), vec![0x7F, 0xFF]);
        assert_eq!(raw_encode_asn1_i128(32768), vec![0x00, 0x80, 0x00]);
        assert_eq!(raw_encode_asn1_i128(32769), vec![0x00, 0x80, 0x01]);
        assert_eq!(raw_encode_asn1_i128(0x7FFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF), vec![0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(raw_encode_asn1_i128(-1), vec![0xFF]);
        assert_eq!(raw_encode_asn1_i128(-2), vec![0xFE]);
        assert_eq!(raw_encode_asn1_i128(-127), vec![0x81]);
        assert_eq!(raw_encode_asn1_i128(-128), vec![0x80]);
        assert_eq!(raw_encode_asn1_i128(-129), vec![0xFF, 0x7F]);
        assert_eq!(raw_encode_asn1_i128(-130), vec![0xFF, 0x7E]);
        assert_eq!(raw_encode_asn1_i128(-32767), vec![0x80, 0x01]);
        assert_eq!(raw_encode_asn1_i128(-32768), vec![0x80, 0x00]);
        assert_eq!(raw_encode_asn1_i128(-32769), vec![0xFF, 0x7F, 0xFF]);
        assert_eq!(raw_encode_asn1_i128(-0x80000000_00000000_00000000_00000000), vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        assert_eq!(encode_u128(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(encode_u128(1), vec![0x02, 0x01, 0x01]);
        assert_eq!(encode_u128(42), vec![0x02, 0x01, 0x2A]);
        assert_eq!(encode_u128(127), vec![0x02, 0x01, 0x7F]);
        assert_eq!(encode_u128(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(encode_u128(129), vec![0x02, 0x02, 0x00, 0x81]);
        assert_eq!(encode_u128(255), vec![0x02, 0x02, 0x00, 0xFF]);
        assert_eq!(encode_u128(256), vec![0x02, 0x02, 0x01, 0x00]);
        assert_eq!(encode_u128(32767), vec![0x02, 0x02, 0x7F, 0xFF]);
        assert_eq!(encode_u128(32768), vec![0x02, 0x03, 0x00, 0x80, 0x00]);
        assert_eq!(encode_u128(32769), vec![0x02, 0x03, 0x00, 0x80, 0x01]);
        assert_eq!(encode_u128(0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF), vec![0x02, 0x11, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        assert_eq!(encode_i128(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(encode_i128(1), vec![0x02, 0x01, 0x01]);
        assert_eq!(encode_i128(42), vec![0x02, 0x01, 0x2A]);
        assert_eq!(encode_i128(127), vec![0x02, 0x01, 0x7F]);
        assert_eq!(encode_i128(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(encode_i128(129), vec![0x02, 0x02, 0x00, 0x81]);
        assert_eq!(encode_i128(255), vec![0x02, 0x02, 0x00, 0xFF]);
        assert_eq!(encode_i128(256), vec![0x02, 0x02, 0x01, 0x00]);
        assert_eq!(encode_i128(32767), vec![0x02, 0x02, 0x7F, 0xFF]);
        assert_eq!(encode_i128(32768), vec![0x02, 0x03, 0x00, 0x80, 0x00]);
        assert_eq!(encode_i128(32769), vec![0x02, 0x03, 0x00, 0x80, 0x01]);
        assert_eq!(encode_i128(0x7FFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF), vec![0x02, 0x10, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(encode_i128(-1), vec![0x02, 0x01, 0xFF]);
        assert_eq!(encode_i128(-2), vec![0x02, 0x01, 0xFE]);
        assert_eq!(encode_i128(-127), vec![0x02, 0x01, 0x81]);
        assert_eq!(encode_i128(-128), vec![0x02, 0x01, 0x80]);
        assert_eq!(encode_i128(-129), vec![0x02, 0x02, 0xFF, 0x7F]);
        assert_eq!(encode_i128(-130), vec![0x02, 0x02, 0xFF, 0x7E]);
        assert_eq!(encode_i128(-32767), vec![0x02, 0x02, 0x80, 0x01]);
        assert_eq!(encode_i128(-32768), vec![0x02, 0x02, 0x80, 0x00]);
        assert_eq!(encode_i128(-32769), vec![0x02, 0x03, 0xFF, 0x7F, 0xFF]);
        assert_eq!(encode_i128(-0x80000000_00000000_00000000_00000000), vec![0x02, 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_octet_string_encoding() {
        fn tose(zero_count: usize, expected_header: &[u8]) {
            let enc = encode_octet_string(&repeat(0x00, zero_count));
            assert_eq!(enc.len(), expected_header.len() + zero_count);
            assert_eq!(&enc[0..expected_header.len()], expected_header);
            assert!(enc[expected_header.len()..].iter().all(|b| *b == 0x00));
        }

        assert_eq!(encode_octet_string(&[]), vec![0x04, 0x00]);

        tose(127, &[0x04, 0x7F]);
        tose(128, &[0x04, 0x81, 0x80]);
        tose(129, &[0x04, 0x81, 0x81]);
        tose(255, &[0x04, 0x81, 0xFF]);
        tose(256, &[0x04, 0x82, 0x01, 0x00]);
    }
}
