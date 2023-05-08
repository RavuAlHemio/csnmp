use std::error::Error;
use std::fmt;
use std::io::Write;
use std::net::Ipv4Addr;

use derivative::Derivative;
use der_parser::ber::{
    Class, MAX_RECURSION, parse_ber_container, parse_ber_null, parse_ber_sequence_defined_g, Tag,
};
use der_parser::error::BerError;
use from_to_repr::FromToRepr;
use nom::branch::alt;
use nom::combinator::complete;
use nom::multi::many0;

use crate::asn1encode::{write_i128, write_octet_string, write_wrapped, write_u128, write_oid};
use crate::oid::{MAX_SUB_IDENTIFIER_COUNT, ObjectIdentifier};


/// Version value stored in every SNMP2c message.
///
/// See RFC1901, section 3.
pub const VERSION_VALUE: i64 = 1;


/// Encodes which type of ASN.1 value was expected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExpectedAsn1Type {
    Integer,
    OctetString,
    Sequence,
    Oid,
    Null,

    /// A virtual type representing any SNMP value (`ObjectSyntax`).
    AnySnmpValueType,
}


/// An error that has occurred while attempting to read or write an SNMP message.
#[derive(Debug)]
#[non_exhaustive]
pub enum SnmpMessageError {
    /// An error has occurred while attempting to parse the ASN.1 message.
    #[non_exhaustive]
    Asn1Decoding { error: BerError },

    /// An I/O error has occurred while attempting to encode the ASN.1 message.
    #[non_exhaustive]
    Asn1EncodingIO { error: std::io::Error },

    /// The message, or a part of it, has an incorrect length. A specific length is expected.
    ///
    /// `expected` and `obtained` are in units of ASN.1 blocks.
    #[non_exhaustive]
    Length { expected: usize, obtained: usize },

    /// The SNMP message has an incorrect version.
    #[non_exhaustive]
    IncorrectVersion { expected: i64, obtained: i64 },

    /// An out-of-range value has been obtained for an enumeration that was decoded as a 32-bit
    /// unsigned integer.
    #[non_exhaustive]
    EnumRangeU32 { enum_name: &'static str, obtained: u32 },

    /// An object identifier has been encountered, one of whose arcs is greater than would fit in a
    /// 32-bit unsigned integer.
    #[non_exhaustive]
    OidDecodeArcNotU32 { index: Option<usize> },

    /// The initial OID pair is `1.n` or `2.n` where `n` is 40 or greater.
    #[non_exhaustive]
    OidInvalidInitialPair { first: u32, second: u32 },
}
impl fmt::Display for SnmpMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1Decoding { error }
                => write!(f, "ASN.1 decoding error: {}", error),
            Self::Asn1EncodingIO { error }
                => write!(f, "ASN.1 encoding I/O error: {}", error),
            Self::Length { expected, obtained }
                => write!(f, "message has wrong length: expected {} ASN.1 blocks, obtained {}", expected, obtained),
            Self::IncorrectVersion { expected, obtained }
                => write!(f, "incorrect SNMP message version: expected {}, obtained {}", expected, obtained),
            Self::EnumRangeU32 { enum_name, obtained }
                => write!(f, "invalid value {:?} obtained for enumeration {:?}", obtained, enum_name),
            Self::OidDecodeArcNotU32 { index } => match index {
                Some(i) => write!(f, "encountered OID whose arc at position {} does not fit into u32", i),
                None => write!(f, "encountered OID one of whose arcs does not fit into u32"),
            },
            Self::OidInvalidInitialPair { first, second }
                => write!(f, "OID starts with {}.{}, but if the first value is {}, the second cannot be >= 40", first, second, first),
        }
    }
}
impl Error for SnmpMessageError {
    fn cause(&self) -> Option<&dyn Error> {
        match self {
            Self::Asn1Decoding { error } => Some(error),
            Self::Asn1EncodingIO { error } => Some(error),
            Self::Length { expected: _, obtained: _ } => None,
            Self::IncorrectVersion { expected: _, obtained: _ } => None,
            Self::EnumRangeU32 { enum_name: _, obtained: _ } => None,
            Self::OidDecodeArcNotU32 { index: _ } => None,
            Self::OidInvalidInitialPair { first: _, second: _ } => None,
        }
    }
}
impl nom::error::ParseError<&[u8]> for SnmpMessageError {
    fn from_error_kind(_input: &[u8], kind: nom::error::ErrorKind) -> Self {
        Self::Asn1Decoding { error: BerError::NomError(kind) }
    }
    fn append(_input: &[u8], kind: nom::error::ErrorKind, _other: Self) -> Self {
        Self::Asn1Decoding { error: BerError::NomError(kind) }
    }
}
impl From<BerError> for SnmpMessageError {
    fn from(value: BerError) -> Self {
        Self::Asn1Decoding { error: value }
    }
}


/// Trait implemented by structs and enums that can be serialized to and deserialized from an
/// encoded form according to ASN.1 BER.
pub trait Asn1BerCodable {
    /// Serializes this enum or struct into a writer.
    fn write_bytes<W: Write>(&self, write: W) -> Result<usize, SnmpMessageError>;

    /// Attempts to deserialize this enum or struct from a slice of bytes.
    ///
    /// As common with `nom`-based parsers, on success, returns `Ok((rest, obj))` where `obj` is
    /// an instance of this enum or struct and `rest` is the remaining byte slice that was not
    /// consumed by the parser. On failure, `Err(e)` is returned where `e` describes the error.
    fn try_parse(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<SnmpMessageError>> where Self: Sized;

    /// Serializes this enum or struct into a vector of bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, SnmpMessageError> {
        let mut buf = Vec::new();
        self.write_bytes(&mut buf)?;
        Ok(buf)
    }
}


/// Attempts to parse the bytes as an octet string.
///
/// On success, returns `Ok((rest, str))` where `rest` are the remaining unparsed bytes and `str` is
/// the octet string as a byte slice.
fn parse_ber_octetstring(bytes: &[u8]) -> Result<(&[u8], &[u8]), nom::Err<SnmpMessageError>> {
    match der_parser::ber::parse_ber_octetstring(bytes) {
        Ok((rest, octet_string_ber)) => match octet_string_ber.as_slice() {
            Ok(os) => Ok((rest, os)),
            Err(error) => Err(nom::Err::Error(SnmpMessageError::Asn1Decoding { error })),
        },
        Err(e) => Err(e.map(|error| SnmpMessageError::Asn1Decoding { error })),
    }
}


/// Attempts to parse the bytes as an octet string, ensuring that the value has the given class and
/// tag.
///
/// On success, returns `Ok((rest, str))` where `rest` are the remaining unparsed bytes and `str` is
/// the octet string as a byte slice.
fn parse_ber_octetstring_class_tag<C: Into<Class>, T: Into<Tag>>(bytes: &[u8], class: C, tag: T) -> Result<(&[u8], &[u8]), nom::Err<SnmpMessageError>> {
    let class = class.into();
    let tag = tag.into();
    let (rest, hdr) = der_parser::ber::ber_read_element_header(bytes)
        .map_err(|err| err.map(|error| SnmpMessageError::Asn1Decoding { error }))?;
    hdr.assert_class(class)
        .map_err(|error| nom::Err::Error(SnmpMessageError::Asn1Decoding { error }))?;
    hdr.assert_tag(tag)
        .map_err(|error| nom::Err::Error(SnmpMessageError::Asn1Decoding { error }))?;
    let (rest, content) = der_parser::ber::ber_read_element_content_as(
        rest,
        Tag::OctetString, // override the tag
        hdr.length(),
        hdr.is_constructed(),
        MAX_RECURSION,
    )
        .map_err(|err| err.map(|error| SnmpMessageError::Asn1Decoding { error }))?;
    let ber_object = der_parser::ber::BerObject::from_header_and_content(hdr, content);
    match ber_object.as_slice() {
        Ok(os) => Ok((rest, os)),
        Err(error) => Err(nom::Err::Error(SnmpMessageError::Asn1Decoding { error })),
    }
}

macro_rules! define_int_parser {
    ($name:ident, $ct_name:ident, $conv_func:ident, $ret_type:ty) => {
        /// Attempts to parse the bytes as an ASN.1 integer and convert them into the given integer
        /// type.
        ///
        /// On success, returns `Ok((rest, i))` where `rest` are the remaining unparsed bytes and
        /// `i` is the integer.
        #[allow(unused)]
        fn $name(bytes: &[u8]) -> Result<(&[u8], $ret_type), nom::Err<SnmpMessageError>> {
            match der_parser::ber::parse_ber_integer(bytes) {
                Ok((rest, integer_ber)) => {
                    match integer_ber.$conv_func() {
                        Ok(integer) => Ok((rest, integer)),
                        Err(error) => Err(nom::Err::Error(SnmpMessageError::Asn1Decoding { error })),
                    }
                },
                Err(e) => Err(e.map(|error| SnmpMessageError::Asn1Decoding { error })),
            }
        }

        /// Attempts to parse the bytes as an ASN.1 integer, ensuring that the value has the given
        /// class and tag, and to convert them into the given integer type.
        ///
        /// On success, returns `Ok((rest, i))` where `rest` are the remaining unparsed bytes and
        /// `i` is the integer.
        #[allow(unused)]
        fn $ct_name<C: Into<Class>, T: Into<Tag>>(bytes: &[u8], class: C, tag: T) -> Result<(&[u8], $ret_type), nom::Err<SnmpMessageError>> {
            let class = class.into();
            let tag = tag.into();

            let (rest, hdr) = der_parser::ber::ber_read_element_header(bytes)
                .map_err(|err| err.map(|error| SnmpMessageError::Asn1Decoding { error }))?;
            hdr.assert_class(class)
                .map_err(|error| nom::Err::Error(SnmpMessageError::Asn1Decoding { error }))?;
            hdr.assert_tag(tag)
                .map_err(|error| nom::Err::Error(SnmpMessageError::Asn1Decoding { error }))?;
            let (rest, content) = der_parser::ber::ber_read_element_content_as(
                rest,
                Tag::Integer, // override the tag
                hdr.length(),
                hdr.is_constructed(),
                MAX_RECURSION,
            )
                .map_err(|err| err.map(|error| SnmpMessageError::Asn1Decoding { error }))?;
            let ber_object = der_parser::ber::BerObject::from_header_and_content(hdr, content);
            match ber_object.$conv_func() {
                Ok(integer) => Ok((rest, integer)),
                Err(error) => Err(nom::Err::Error(SnmpMessageError::Asn1Decoding { error })),
            }
        }
    };
}
define_int_parser!(parse_ber_integer_i64, parse_ber_integer_i64_class_tag, as_i64, i64);
define_int_parser!(parse_ber_integer_u64, parse_ber_integer_u64_class_tag, as_u64, u64);
define_int_parser!(parse_ber_integer_i32, parse_ber_integer_i32_class_tag, as_i32, i32);
define_int_parser!(parse_ber_integer_u32, parse_ber_integer_u32_class_tag, as_u32, u32);

fn parse_ber_oid(bytes: &[u8]) -> Result<(&[u8], ObjectIdentifier), nom::Err<SnmpMessageError>> {
    let (rest, name_ber) = der_parser::ber::parse_ber_oid(bytes)
        .map_err(|err| err.map(|error| error.into()))?;
    let oid_ber = name_ber.as_oid()
        .map_err(|error| nom::Err::Error(error.into()))?;

    let mut oid_array = [0u32; MAX_SUB_IDENTIFIER_COUNT];
    let oid_iter = match oid_ber.iter() {
        Some(oi) => oi,
        None => return Err(nom::Err::Error(SnmpMessageError::OidDecodeArcNotU32 { index: None })),
    };
    let mut arc_count = 0;
    for (index, arc_u64) in oid_iter.enumerate() {
        let arc_u32 = match arc_u64.try_into() {
            Ok(au) => au,
            Err(_) => return Err(nom::Err::Error(SnmpMessageError::OidDecodeArcNotU32 { index: None })),
        };
        oid_array[index] = arc_u32;
        arc_count += 1;
    }

    let oid = ObjectIdentifier::new(arc_count, oid_array);
    Ok((rest, oid))
}

pub fn parse_ber_class_tagged_implicit_g<'a, C, T, Output, F>(
    class: C,
    tag: T,
    f: F,
) -> impl FnMut(&'a [u8]) -> Result<(&[u8], Output), nom::Err<SnmpMessageError>>
where
    F: Fn(&'a [u8], der_parser::ber::Header<'a>, usize) -> Result<(&'a [u8], Output), nom::Err<SnmpMessageError>>,
    T: Into<Tag>,
    C: Into<Class>,
{
    let tag = tag.into();
    let class = class.into();
    parse_ber_container(move |i, hdr| {
        hdr.assert_tag(tag).map_err(|e| nom::Err::Error(e.into()))?;
        hdr.assert_class(class).map_err(|e| nom::Err::Error(e.into()))?;
        // XXX MAX_RECURSION should not be used, it resets the depth counter
        f(i, hdr, MAX_RECURSION)
        // trailing bytes are ignored
    })
}


// RFC1901, section 3.
#[derive(Clone, Derivative, Eq, Hash, PartialEq)]
#[derivative(Debug)]
pub struct Snmp2cMessage {
    pub version: i64,
    #[derivative(Debug="ignore")]
    pub community: Vec<u8>,
    pub pdu: Snmp2cPdu,
}
impl Asn1BerCodable for Snmp2cMessage {
    fn write_bytes<W: Write>(&self, write: W) -> Result<usize, SnmpMessageError> {
        let mut sequence_bytes = Vec::new();
        write_i128(&mut sequence_bytes, self.version.into(), None, None)?;
        write_octet_string(&mut sequence_bytes, &self.community, None, None)?;
        self.pdu.write_bytes(&mut sequence_bytes)?;

        write_wrapped(write, Class::Universal, true, Tag::Sequence, &sequence_bytes)
    }

    fn try_parse(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<SnmpMessageError>> {
        parse_ber_sequence_defined_g(|rest, _hdr| {
            let (rest, version) = parse_ber_integer_i64(rest)?;
            if version != 1 {
                return Err(nom::Err::Failure(SnmpMessageError::IncorrectVersion { expected: 1, obtained: version }));
            }

            let (rest, community) = parse_ber_octetstring(rest)?;
            let (rest, pdu) = Snmp2cPdu::try_parse(rest)?;

            let message = Self {
                version,
                community: Vec::from(community),
                pdu,
            };
            Ok((rest, message))
        })(bytes)
    }
}

// RFC3416, section 3.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Snmp2cPdu {
    GetRequest(InnerPdu),
    GetNextRequest(InnerPdu),
    GetBulkRequest(BulkPdu),
    Response(InnerPdu),
    SetRequest(InnerPdu),
    InformRequest(InnerPdu),
    SnmpV2Trap(InnerPdu),
}
impl Snmp2cPdu {
    /// Returns the request ID from the inner SNMP2c Protocol Data Unit (PDU).
    pub fn request_id(&self) -> i32 {
        match self {
            Self::GetRequest(p) => p.request_id,
            Self::GetNextRequest(p) => p.request_id,
            Self::GetBulkRequest(p) => p.request_id,
            Self::Response(p) => p.request_id,
            Self::SetRequest(p) => p.request_id,
            Self::InformRequest(p) => p.request_id,
            Self::SnmpV2Trap(p) => p.request_id,
        }
    }
}
impl Asn1BerCodable for Snmp2cPdu {
    fn write_bytes<W: Write>(&self, write: W) -> Result<usize, SnmpMessageError> {
        let mut inner_bytes = Vec::new();
        let tag = match self {
            Self::GetRequest(inner_pdu) => {
                inner_pdu.write_bytes(&mut inner_bytes)?;
                Tag(0)
            },
            Self::GetNextRequest(inner_pdu) => {
                inner_pdu.write_bytes(&mut inner_bytes)?;
                Tag(1)
            },
            Self::Response(inner_pdu) => {
                inner_pdu.write_bytes(&mut inner_bytes)?;
                Tag(2)
            },
            Self::SetRequest(inner_pdu) => {
                inner_pdu.write_bytes(&mut inner_bytes)?;
                Tag(3)
            },
            Self::GetBulkRequest(bulk_pdu) => {
                bulk_pdu.write_bytes(&mut inner_bytes)?;
                Tag(5)
            },
            Self::InformRequest(inner_pdu) => {
                inner_pdu.write_bytes(&mut inner_bytes)?;
                Tag(6)
            },
            Self::SnmpV2Trap(inner_pdu) => {
                inner_pdu.write_bytes(&mut inner_bytes)?;
                Tag(7)
            },
        };

        write_wrapped(write, Class::ContextSpecific, true, tag, &inner_bytes)
    }

    fn try_parse(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<SnmpMessageError>> {
        alt((
            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    0,
                    |content, _hdr, _depth| InnerPdu::try_parse(content),
                )(bytes)
                    .map(|(rest, inner_pdu)| (rest, Self::GetRequest(inner_pdu)))
            ),

            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    1,
                    |content, _hdr, _depth| InnerPdu::try_parse(content),
                )(bytes)
                    .map(|(rest, inner_pdu)| (rest, Self::GetNextRequest(inner_pdu)))
            ),

            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    2,
                    |content, _hdr, _depth| InnerPdu::try_parse(content),
                )(bytes)
                    .map(|(rest, inner_pdu)| (rest, Self::Response(inner_pdu)))
            ),

            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    3,
                    |content, _hdr, _depth| InnerPdu::try_parse(content),
                )(bytes)
                    .map(|(rest, inner_pdu)| (rest, Self::SetRequest(inner_pdu)))
            ),

            // tag 4 is obsolete (Trap-PDU from SNMPv1)

            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    5,
                    |content, _hdr: der_parser::der::Header, _depth| BulkPdu::try_parse(content),
                )(bytes)
                    .map(|(rest, bulk_pdu)| (rest, Self::GetBulkRequest(bulk_pdu)))
            ),

            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    6,
                    |content, _hdr, _depth| InnerPdu::try_parse(content),
                )(bytes)
                    .map(|(rest, inner_pdu)| (rest, Self::InformRequest(inner_pdu)))
            ),

            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    7,
                    |content, _hdr, _depth| InnerPdu::try_parse(content),
                )(bytes)
                    .map(|(rest, inner_pdu)| (rest, Self::SnmpV2Trap(inner_pdu)))
            ),
        ))(bytes)
    }
}

#[derive(Clone, Copy, Debug, FromToRepr, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ErrorStatus {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5,
    NoAccess = 6,
    WrongType = 7,
    WrongLength = 8,
    WrongEncoding = 9,
    WrongValue = 10,
    NoCreation = 11,
    InconsistentValue = 12,
    ResourceUnavailable = 13,
    CommitFailed = 14,
    UndoFailed = 15,
    AuthorizationError = 16,
    NotWritable = 17,
    InconsistentName = 18,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InnerPdu {
    pub request_id: i32,
    pub error_status: ErrorStatus,
    pub error_index: u32,
    pub variable_bindings: Vec<VariableBinding>,
}
impl Asn1BerCodable for InnerPdu {
    fn write_bytes<W: Write>(&self, mut write: W) -> Result<usize, SnmpMessageError> {
        let mut total_bytes = 0;
        total_bytes += write_i128(&mut write, self.request_id.into(), None, None)?;
        total_bytes += write_u128(&mut write, u8::from(self.error_status).into(), None, None)?;
        total_bytes += write_u128(&mut write, self.error_index.into(), None, None)?;

        let mut bindings_sequence = Vec::new();
        for binding in &self.variable_bindings {
            binding.write_bytes(&mut bindings_sequence)?;
        }
        total_bytes += write_wrapped(&mut write, Class::Universal, true, Tag::Sequence, &bindings_sequence)?;

        Ok(total_bytes)
    }

    fn try_parse(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<SnmpMessageError>> {
        let (rest, request_id) = parse_ber_integer_i32(bytes)?;
        let (rest, error_status_u32) = parse_ber_integer_u32(rest)?;
        let error_status_u8: u8 = match error_status_u32.try_into() {
            Ok(esu) => esu,
            Err(_) => return Err(nom::Err::Error(SnmpMessageError::EnumRangeU32 {
                enum_name: "ErrorStatus",
                obtained: error_status_u32,
            })),
        };
        let error_status: ErrorStatus = match error_status_u8.try_into() {
            Ok(es) => es,
            Err(_) => return Err(nom::Err::Error(SnmpMessageError::EnumRangeU32 {
                enum_name: "ErrorStatus",
                obtained: error_status_u8.into(),
            })),
        };
        let (rest, error_index) = parse_ber_integer_u32(rest)?;

        let (rest, variable_bindings) = parse_ber_sequence_defined_g(
            |bytes, _header| many0(complete(VariableBinding::try_parse))(bytes)
        )(rest)?;

        let inner_pdu = Self {
            request_id,
            error_status,
            error_index,
            variable_bindings,
        };
        Ok((rest, inner_pdu))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BulkPdu {
    pub request_id: i32,
    pub non_repeaters: u32,
    pub max_repetitions: u32,
    pub variable_bindings: Vec<VariableBinding>,
}
impl Asn1BerCodable for BulkPdu {
    fn write_bytes<W: Write>(&self, mut write: W) -> Result<usize, SnmpMessageError> {
        let mut total_bytes = 0;
        total_bytes += write_i128(&mut write, self.request_id.into(), None, None)?;
        total_bytes += write_u128(&mut write, self.non_repeaters.into(), None, None)?;
        total_bytes += write_u128(&mut write, self.max_repetitions.into(), None, None)?;

        let mut bindings_sequence = Vec::new();
        for binding in &self.variable_bindings {
            binding.write_bytes(&mut bindings_sequence)?;
        }
        total_bytes += write_wrapped(&mut write, Class::Universal, true, Tag::Sequence, &bindings_sequence)?;

        Ok(total_bytes)
    }

    fn try_parse(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<SnmpMessageError>> {
        let (rest, request_id) = parse_ber_integer_i32(bytes)?;
        let (rest, non_repeaters) = parse_ber_integer_u32(rest)?;
        let (rest, max_repetitions) = parse_ber_integer_u32(rest)?;

        let (rest, variable_bindings) = parse_ber_sequence_defined_g(
            |bytes, _header| many0(complete(VariableBinding::try_parse))(bytes)
        )(rest)?;

        let inner_pdu = Self {
            request_id,
            non_repeaters,
            max_repetitions,
            variable_bindings,
        };
        Ok((rest, inner_pdu))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VariableBinding {
    pub name: ObjectIdentifier,
    pub value: BindingValue,
}
impl Asn1BerCodable for VariableBinding {
    fn write_bytes<W: Write>(&self, write: W) -> Result<usize, SnmpMessageError> {
        let mut binding_sequence = Vec::new();

        write_oid(&mut binding_sequence, &self.name, None, None)?;
        self.value.write_bytes(&mut binding_sequence)?;

        write_wrapped(write, Class::Universal, true, Tag::Sequence, &binding_sequence)
    }

    fn try_parse(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<SnmpMessageError>> {
        parse_ber_sequence_defined_g(|rest, _hdr| {
            let (rest, name) = parse_ber_oid(rest)?;
            let (rest, value) = BindingValue::try_parse(rest)?;

            let binding = Self {
                name,
                value,
            };
            Ok((rest, binding))
        })(bytes)
    }
}

// RFC1905: VarBind -> CHOICE
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum BindingValue {
    /// A binding without a value. Used (exclusively) in request packets.
    Unspecified,

    /// A concrete value.
    Value(ObjectValue),

    /// An error signifying that the given object does not exist.
    NoSuchObject,

    /// An error signifying that the given instance (an indexed value below an object) does not
    /// exist.
    NoSuchInstance,

    /// An error signifying that no more values remain.
    EndOfMibView,
}
impl Asn1BerCodable for BindingValue {
    fn write_bytes<W: Write>(&self, write: W) -> Result<usize, SnmpMessageError> {
        match self {
            Self::Unspecified => {
                // regular NULL value
                write_wrapped(write, Class::Universal, false, Tag::Null, &[])
            },
            Self::NoSuchObject => {
                // NULL tagged with context-specific 0
                write_wrapped(write, Class::ContextSpecific, false, Tag(0), &[])
            },
            Self::NoSuchInstance => {
                // NULL tagged with context-specific 1
                write_wrapped(write, Class::ContextSpecific, false, Tag(1), &[])
            },
            Self::EndOfMibView => {
                // NULL tagged with context-specific 2
                write_wrapped(write, Class::ContextSpecific, false, Tag(2), &[])
            },
            Self::Value(value) => {
                // pass on
                value.write_bytes(write)
            },
        }
    }

    fn try_parse(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<SnmpMessageError>> {
        alt((
            // list the more complex options (tagged values) first!

            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    0,
                    |content, _hdr, _depth| parse_ber_null(content)
                        .map_err(|err| err.map(|error| SnmpMessageError::Asn1Decoding { error })),
                )(bytes)
                    .map(|(rest, _null)| (rest, Self::NoSuchObject))
            ),

            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    1,
                    |content, _hdr, _depth| parse_ber_null(content)
                        .map_err(|err| err.map(|error| SnmpMessageError::Asn1Decoding { error })),
                )(bytes)
                    .map(|(rest, _null)| (rest, Self::NoSuchInstance))
            ),

            complete(|bytes|
                parse_ber_class_tagged_implicit_g(
                    Class::ContextSpecific,
                    2,
                    |content, _hdr, _depth| parse_ber_null(content)
                        .map_err(|err| err.map(|error| SnmpMessageError::Asn1Decoding { error })),
                )(bytes)
                    .map(|(rest, _null)| (rest, Self::EndOfMibView))
            ),

            |bytes| parse_ber_null(bytes)
                .map(|(rest, _null)| (rest, Self::Unspecified))
                .map_err(|err| err.map(|error| SnmpMessageError::Asn1Decoding { error })),

            |bytes| ObjectValue::try_parse(bytes)
                .map(|(rest, object_value)| (rest, Self::Value(object_value))),
        ))(bytes)
    }
}

/// A single SNMP value.
///
/// This is a representation of `ObjectSyntax` as defined in RFC2578.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ObjectValue {
    // simple syntax
    Integer(i32),
    String(Vec<u8>),
    ObjectId(ObjectIdentifier),

    // application syntax
    IpAddress(Ipv4Addr),
    Counter32(u32),
    Unsigned32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
}
impl ObjectValue {
    /// Returns [`Some(i32)`] if this `ObjectValue` is an [`Integer`][ObjectValue::Integer];
    /// otherwise, returns [`None`].
    #[allow(dead_code)]
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns [`Some(u32)`] if this `ObjectValue` is a [`Counter32`][ObjectValue::Counter32],
    /// [`Unsigned32`][ObjectValue::Unsigned32], or [`TimeTicks`][ObjectValue::TimeTicks];
    /// otherwise, returns [`None`].
    #[allow(dead_code)]
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Counter32(i) => Some(*i),
            Self::Unsigned32(i) => Some(*i),
            Self::TimeTicks(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns [`Some(u64)`] if this `ObjectValue` is a [`Counter32`][ObjectValue::Counter32],
    /// [`Unsigned32`][ObjectValue::Unsigned32], [`TimeTicks`][ObjectValue::TimeTicks], or
    /// [`Counter64`][ObjectValue::Counter64]; otherwise, returns [`None`].
    #[allow(dead_code)]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Counter32(i) => Some((*i).into()),
            Self::Unsigned32(i) => Some((*i).into()),
            Self::TimeTicks(i) => Some((*i).into()),
            Self::Counter64(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns [`Some(&Vec<u8>)`] if this `ObjectValue` is a [`String`][ObjectValue::String] or
    /// [`Opaque`][ObjectValue::Opaque]; otherwise, returns [`None`].
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> Option<&Vec<u8>> {
        match self {
            Self::String(s) => Some(s),
            Self::Opaque(o) => Some(o),
            _ => None,
        }
    }

    /// Returns [`Some(ObjectIdentifier)`] if this `ObjectValue` is an
    /// [`ObjectId`][ObjectValue::ObjectId]; otherwise, returns [`None`].
    pub fn as_oid(&self) -> Option<ObjectIdentifier> {
        match self {
            Self::ObjectId(o) => Some(*o),
            _ => None,
        }
    }

    /// Returns whether this `ObjectValue` is an [`Integer`][ObjectValue::Integer].
    #[allow(dead_code)]
    pub fn is_integer(&self) -> bool { matches!(self, Self::Integer(_)) }

    /// Returns whether this `ObjectValue` is a [`String`][ObjectValue::String].
    #[allow(dead_code)]
    pub fn is_string(&self) -> bool { matches!(self, Self::String(_)) }

    /// Returns whether this `ObjectValue` is an [`ObjectId`][ObjectValue::ObjectId].
    #[allow(dead_code)]
    pub fn is_object_id(&self) -> bool { matches!(self, Self::ObjectId(_)) }

    /// Returns whether this `ObjectValue` is an [`IpAddress`][ObjectValue::IpAddress].
    #[allow(dead_code)]
    pub fn is_ip_address(&self) -> bool { matches!(self, Self::IpAddress(_)) }

    /// Returns whether this `ObjectValue` is a [`Counter32`][ObjectValue::Counter32].
    #[allow(dead_code)]
    pub fn is_counter32(&self) -> bool { matches!(self, Self::Counter32(_)) }

    /// Returns whether this `ObjectValue` is an [`Unsigned32`][ObjectValue::Unsigned32].
    #[allow(dead_code)]
    pub fn is_unsigned32(&self) -> bool { matches!(self, Self::Unsigned32(_)) }

    /// Returns whether this `ObjectValue` is a [`TimeTicks`][ObjectValue::TimeTicks].
    #[allow(dead_code)]
    pub fn is_time_ticks(&self) -> bool { matches!(self, Self::TimeTicks(_)) }

    /// Returns whether this `ObjectValue` is an [`Opaque`][ObjectValue::Opaque].
    #[allow(dead_code)]
    pub fn is_opaque(&self) -> bool { matches!(self, Self::Opaque(_)) }

    /// Returns whether this `ObjectValue` is a [`Counter64`][ObjectValue::Counter64].
    #[allow(dead_code)]
    pub fn is_counter64(&self) -> bool { matches!(self, Self::Counter64(_)) }

    /// Returns the string representation of this `ObjectValue`'s type.
    #[allow(dead_code)]
    pub fn as_type_str(&self) -> &'static str {
        match self {
            Self::Integer(_) => "Integer",
            Self::String(_) => "String",
            Self::ObjectId(_) => "ObjectId",
            Self::IpAddress(_) => "IpAddress",
            Self::Counter32(_) => "Counter32",
            Self::Unsigned32(_) => "Unsigned32",
            Self::TimeTicks(_) => "TimeTicks",
            Self::Opaque(_) => "Opaque",
            Self::Counter64(_) => "Counter64",
        }
    }
}
impl Asn1BerCodable for ObjectValue {
    fn write_bytes<W: Write>(&self, write: W) -> Result<usize, SnmpMessageError> {
        match self {
            Self::Integer(val) => {
                // regular INTEGER
                write_i128(write, (*val).into(), None, None)
            },
            Self::String(bs) => {
                // regular OCTET STRING
                write_octet_string(write, &bs, None, None)
            },
            Self::ObjectId(oid) => {
                // regular OBJECT IDENTIFIER
                write_oid(write, oid, None, None)
            },
            Self::IpAddress(ip) => {
                // OCTET STRING with APPLICATION tag 0
                write_octet_string(write, &ip.octets(), Some(Class::Application), Some(Tag(0)))
            },
            Self::Counter32(val) => {
                // INTEGER with APPLICATION tag 1
                write_u128(write, (*val).into(), Some(Class::Application), Some(Tag(1)))
            },
            Self::Unsigned32(val) => {
                // INTEGER with APPLICATION tag 2
                write_u128(write, (*val).into(), Some(Class::Application), Some(Tag(2)))
            },
            Self::TimeTicks(val) => {
                // INTEGER with APPLICATION tag 3
                write_u128(write, (*val).into(), Some(Class::Application), Some(Tag(3)))
            },
            Self::Opaque(bs) => {
                // OCTET STRING with APPLICATION tag 4
                write_octet_string(write, bs, Some(Class::Application), Some(Tag(4)))
            },
            Self::Counter64(val) => {
                // INTEGER with APPLICATION tag 6
                write_u128(write, (*val).into(), Some(Class::Application), Some(Tag(6)))
            },
        }
    }

    fn try_parse(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<SnmpMessageError>> {
        alt((
            // application-specific variants first!

            // IpAddress
            complete(|bytes|
                parse_ber_octetstring_class_tag(bytes, Class::Application, 0)
                    .and_then(|(rest, octet_string)| {
                        if octet_string.len() != 4 {
                            Err(nom::Err::Error(SnmpMessageError::Length { expected: 4, obtained: octet_string.len() }))
                        } else {
                            let octets: [u8; 4] = octet_string.try_into().unwrap();
                            Ok((rest, Self::IpAddress(octets.into())))
                        }
                    })
            ),

            // Counter32
            complete(|bytes|
                parse_ber_integer_u32_class_tag(bytes, Class::Application, 1)
                    .map(|(rest, val)| (rest, Self::Counter32(val)))
            ),

            // Unsigned32 (= Gauge32)
            complete(|bytes|
                parse_ber_integer_u32_class_tag(bytes, Class::Application, 2)
                    .map(|(rest, val)| (rest, Self::Unsigned32(val)))
            ),

            // TimeTicks
            complete(|bytes|
                parse_ber_integer_u32_class_tag(bytes, Class::Application, 3)
                    .map(|(rest, val)| (rest, Self::TimeTicks(val)))
            ),

            // Opaque
            complete(|bytes|
                parse_ber_octetstring_class_tag(bytes, Class::Application, 4)
                    .map(|(rest, octet_string)| (rest, Self::Opaque(Vec::from(octet_string)))
            )),

            // [APPLICATION 5] used to be an OSI NSAP address in RFC1442, but was removed in RFC1902

            // Counter64
            complete(|bytes|
                parse_ber_integer_u64_class_tag(bytes, Class::Application, 6)
                    .map(|(rest, val)| (rest, Self::Counter64(val)))
            ),

            // [APPLICATION 7] used to be UInteger32 in RFC1442, but was removed in RFC1902
            // (what's the point if we already have Counter32 and Unsigned32?)

            // global variants next

            // Integer
            complete(|bytes|
                parse_ber_integer_i32(bytes)
                    .map(|(rest, int)| (rest, Self::Integer(int)))
            ),

            // String
            complete(|bytes|
                parse_ber_octetstring(bytes)
                    .map(|(rest, octet_string)| (rest, Self::String(Vec::from(octet_string))))
            ),

            // ObjectId
            complete(|bytes|
                parse_ber_oid(bytes)
                    .map(|(rest, oid)| (rest, Self::ObjectId(oid)))
            ),
        ))(bytes)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn gimme_int(bind: &VariableBinding) -> i32 {
        match &bind.value {
            BindingValue::Value(ObjectValue::Integer(i)) => *i,
            _ => panic!("want int, got {:?}", bind.value),
        }
    }

    fn gimme_octets(bind: &VariableBinding) -> &Vec<u8> {
        match &bind.value {
            BindingValue::Value(ObjectValue::String(bs)) => bs,
            _ => panic!("want octets, got {:?}", bind.value),
        }
    }

    fn gimme_oid(bind: &VariableBinding) -> ObjectIdentifier {
        match &bind.value {
            BindingValue::Value(ObjectValue::ObjectId(oid)) => *oid,
            _ => panic!("want oid, got {:?}", bind.value),
        }
    }

    fn gimme_ip(bind: &VariableBinding) -> Ipv4Addr {
        match &bind.value {
            BindingValue::Value(ObjectValue::IpAddress(addr)) => *addr,
            _ => panic!("want ip addr, got {:?}", bind.value),
        }
    }

    fn gimme_counter(bind: &VariableBinding) -> u32 {
        match &bind.value {
            BindingValue::Value(ObjectValue::Counter32(counter)) => *counter,
            _ => panic!("want counter, got {:?}", bind.value),
        }
    }

    fn gimme_unsigned(bind: &VariableBinding) -> u32 {
        match &bind.value {
            BindingValue::Value(ObjectValue::Unsigned32(u)) => *u,
            _ => panic!("want unsigned, got {:?}", bind.value),
        }
    }

    fn gimme_time(bind: &VariableBinding) -> u32 {
        match &bind.value {
            BindingValue::Value(ObjectValue::TimeTicks(i)) => *i,
            _ => panic!("want time, got {:?}", bind.value),
        }
    }

    fn gimme_counter64(bind: &VariableBinding) -> u64 {
        match &bind.value {
            BindingValue::Value(ObjectValue::Counter64(c64)) => *c64,
            _ => panic!("want counter64, got {:?}", bind.value),
        }
    }

    #[test]
    fn test_decode_integer_object_value() {
        let bytes: Vec<u8> = vec![0x02, 0x01, 0x04];

        let (rest, asn1) = ObjectValue::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        assert_eq!(asn1, ObjectValue::Integer(4));
    }

    #[test]
    fn test_decode_integer_binding_value() {
        let bytes: Vec<u8> = vec![0x02, 0x01, 0x04];

        let (rest, asn1) = BindingValue::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        assert_eq!(asn1, BindingValue::Value(ObjectValue::Integer(4)));
    }

    #[test]
    fn test_decode_variable_binding() {
        let bytes: Vec<u8> = vec![
            0x30, 0x13, 0x06, 0x0E, 0x28, 0xC4, 0x62, 0x01,
            0x01, 0x02, 0x01, 0x04, 0x01, 0x01, 0x04, 0x00,
            0x01, 0x5F, 0x02, 0x01, 0x04,
        ];

        let (rest, asn1) = VariableBinding::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        assert_eq!(asn1.name, "1.0.8802.1.1.2.1.4.1.1.4.0.1.95".parse().unwrap());
        assert_eq!(asn1.value, BindingValue::Value(ObjectValue::Integer(4)));
    }

    #[test]
    fn test_decode_inner_pdu() {
        let bytes: Vec<u8> = vec![
            0x02, 0x04, 0x1c, 0x68, 0x3b, 0x44, 0x02, 0x01,
            0x00, 0x02, 0x01, 0x00, 0x30, 0x16, 0x30, 0x14,
            0x06, 0x0f, 0x28, 0xc4, 0x62, 0x01, 0x01, 0x02,
            0x01, 0x04, 0x01, 0x01, 0x04, 0x00, 0x81, 0x42,
            0x08, 0x02, 0x01, 0x04,
        ];

        let (rest, asn1) = InnerPdu::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        assert_eq!(asn1.request_id, 476592964);
        assert_eq!(asn1.error_status, ErrorStatus::NoError);
        assert_eq!(asn1.error_index, 0);
        assert_eq!(asn1.variable_bindings[0].name, "1.0.8802.1.1.2.1.4.1.1.4.0.194.8".parse().unwrap());
        assert_eq!(asn1.variable_bindings[0].value, BindingValue::Value(ObjectValue::Integer(4)));
    }

    #[test]
    fn test_decode_inner_pdu_10() {
        let bytes: Vec<u8> = vec![
            0x02, 0x01, 0x01, 0x02,
            0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x82, 0x01, 0x87, 0x30, 0x81, 0xca, 0x06,
            0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
            0x00, 0x04, 0x81, 0xbd, 0x43, 0x69, 0x73, 0x63,
            0x6f, 0x20, 0x4e, 0x58, 0x2d, 0x4f, 0x53, 0x28,
            0x74, 0x6d, 0x29, 0x20, 0x6e, 0x35, 0x30, 0x30,
            0x30, 0x2c, 0x20, 0x53, 0x6f, 0x66, 0x74, 0x77,
            0x61, 0x72, 0x65, 0x20, 0x28, 0x6e, 0x35, 0x30,
            0x30, 0x30, 0x2d, 0x75, 0x6b, 0x39, 0x29, 0x2c,
            0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
            0x20, 0x36, 0x2e, 0x30, 0x28, 0x32, 0x29, 0x4e,
            0x32, 0x28, 0x34, 0x29, 0x2c, 0x20, 0x52, 0x45,
            0x4c, 0x45, 0x41, 0x53, 0x45, 0x20, 0x53, 0x4f,
            0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x20, 0x43,
            0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74,
            0x20, 0x28, 0x63, 0x29, 0x20, 0x32, 0x30, 0x30,
            0x32, 0x2d, 0x32, 0x30, 0x31, 0x32, 0x20, 0x62,
            0x79, 0x20, 0x43, 0x69, 0x73, 0x63, 0x6f, 0x20,
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c,
            0x20, 0x49, 0x6e, 0x63, 0x2e, 0x20, 0x44, 0x65,
            0x76, 0x69, 0x63, 0x65, 0x20, 0x4d, 0x61, 0x6e,
            0x61, 0x67, 0x65, 0x72, 0x20, 0x56, 0x65, 0x72,
            0x73, 0x69, 0x6f, 0x6e, 0x20, 0x36, 0x2e, 0x32,
            0x28, 0x31, 0x29, 0x2c, 0x20, 0x20, 0x43, 0x6f,
            0x6d, 0x70, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x32,
            0x2f, 0x32, 0x34, 0x2f, 0x32, 0x30, 0x31, 0x34,
            0x20, 0x31, 0x34, 0x3a, 0x30, 0x30, 0x3a, 0x30,
            0x30, 0x30, 0x18, 0x06, 0x08, 0x2b, 0x06, 0x01,
            0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x0c, 0x2b,
            0x06, 0x01, 0x04, 0x01, 0x09, 0x0c, 0x03, 0x01,
            0x03, 0x87, 0x70, 0x30, 0x11, 0x06, 0x08, 0x2b,
            0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43,
            0x05, 0x00, 0x99, 0xe6, 0x9b, 0xc5, 0x30, 0x0f,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
            0x04, 0x00, 0x04, 0x03, 0x4b, 0x4f, 0x4d, 0x30,
            0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
            0x01, 0x05, 0x00, 0x04, 0x08, 0x73, 0x77, 0x2d,
            0x64, 0x2d, 0x73, 0x6e, 0x31, 0x30, 0x13, 0x06,
            0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06,
            0x00, 0x04, 0x07, 0x44, 0x43, 0x30, 0x32, 0x4d,
            0x30, 0x32, 0x30, 0x0d, 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x02, 0x01, 0x01, 0x07, 0x00, 0x02, 0x01,
            0x46, 0x30, 0x11, 0x06, 0x08, 0x2b, 0x06, 0x01,
            0x02, 0x01, 0x01, 0x08, 0x00, 0x43, 0x05, 0x00,
            0xff, 0xff, 0xff, 0x7e, 0x30, 0x14, 0x06, 0x0a,
            0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01,
            0x02, 0x01, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x06,
            0x03, 0x01, 0x30, 0x17, 0x06, 0x0a, 0x2b, 0x06,
            0x01, 0x02, 0x01, 0x01, 0x09, 0x01, 0x02, 0x02,
            0x06, 0x09, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x10,
            0x02, 0x02, 0x01,
        ];

        let (rest, asn1) = InnerPdu::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        assert_eq!(asn1.request_id, 1);
        assert_eq!(asn1.error_status, ErrorStatus::NoError);
        assert_eq!(asn1.error_index, 0);

        assert_eq!(asn1.variable_bindings[0].name, "1.3.6.1.2.1.1.1.0".parse().unwrap());
        let string0 = gimme_octets(&asn1.variable_bindings[0]);
        assert_eq!(string0, b"Cisco NX-OS(tm) n5000, Software (n5000-uk9), Version 6.0(2)N2(4), RELEASE SOFTWARE Copyright (c) 2002-2012 by Cisco Systems, Inc. Device Manager Version 6.2(1),  Compiled 2/24/2014 14:00:00");

        assert_eq!(asn1.variable_bindings[1].name, "1.3.6.1.2.1.1.2.0".parse().unwrap());
        let oid1 = gimme_oid(&asn1.variable_bindings[1]);
        assert_eq!(oid1, "1.3.6.1.4.1.9.12.3.1.3.1008".parse().unwrap());

        assert_eq!(asn1.variable_bindings[2].name, "1.3.6.1.2.1.1.3.0".parse().unwrap());
        let time2 = gimme_time(&asn1.variable_bindings[2]);
        assert_eq!(time2, 0x99E69BC5);
    }

    #[test]
    fn test_decode_pdu() {
        let bytes: Vec<u8> = vec![
            0xa2, 0x24, 0x02, 0x04, 0x1c, 0x68, 0x3b, 0x44,
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16,
            0x30, 0x14, 0x06, 0x0f, 0x28, 0xc4, 0x62, 0x01,
            0x01, 0x02, 0x01, 0x04, 0x01, 0x01, 0x04, 0x00,
            0x81, 0x42, 0x08, 0x02, 0x01, 0x04,
        ];

        let (rest, asn1) = Snmp2cPdu::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        match asn1 {
            Snmp2cPdu::Response(resp) => {
                assert_eq!(resp.request_id, 476592964);
                assert_eq!(resp.error_status, ErrorStatus::NoError);
                assert_eq!(resp.error_index, 0);
                assert_eq!(resp.variable_bindings[0].name, "1.0.8802.1.1.2.1.4.1.1.4.0.194.8".parse().unwrap());
                assert_eq!(resp.variable_bindings[0].value, BindingValue::Value(ObjectValue::Integer(4)));
            },
            other => panic!("unexpected PDU {:?}", other),
        }
    }

    #[test]
    fn test_decode_message() {
        let bytes: Vec<u8> = vec![
            0x30, 0x30, 0x02, 0x01, 0x01, 0x04, 0x05,
            0x41, 0x69, 0x74, 0x68, 0x39,
            0xa2, 0x24, 0x02, 0x04, 0x1c, 0x68, 0x3b, 0x44,
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x16,
            0x30, 0x14, 0x06, 0x0f, 0x28, 0xc4, 0x62, 0x01,
            0x01, 0x02, 0x01, 0x04, 0x01, 0x01, 0x04, 0x00,
            0x81, 0x42, 0x08, 0x02, 0x01, 0x04,
        ];

        let (rest, asn1) = Snmp2cMessage::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        assert_eq!(asn1.version, 1);
        assert_eq!(asn1.community, b"Aith9");
        match asn1.pdu {
            Snmp2cPdu::Response(resp) => {
                assert_eq!(resp.request_id, 476592964);
                assert_eq!(resp.error_status, ErrorStatus::NoError);
                assert_eq!(resp.error_index, 0);
                assert_eq!(resp.variable_bindings[0].name, "1.0.8802.1.1.2.1.4.1.1.4.0.194.8".parse().unwrap());
                assert_eq!(resp.variable_bindings[0].value, BindingValue::Value(ObjectValue::Integer(4)));
            },
            other => panic!("unexpected PDU {:?}", other),
        }
    }

    #[test]
    fn test_decode1() {
        let bytes: Vec<u8> = vec![
             48, 129, 238,   2,   1,   1,   4,   5,  70, 113,  97, 116, 101, 162, 129, 225,
              2,   4,  38, 176, 163,  99,   2,   1,   0,   2,   1,   0,  48, 129, 210,  48,
             19,   6,  14,  40, 196,  98,   1,   1,   2,   1,   4,   1,   1,   4,   0,   1,
             95,   2,   1,   4,  48,  19,   6,  14,  40, 196,  98,   1,   1,   2,   1,   4,
              1,   1,   4,   0,   2,  94,   2,   1,   4,  48,  19,   6,  14,  40, 196,  98,
              1,   1,   2,   1,   4,   1,   1,   4,   0,   3,  96,   2,   1,   5,  48,  19,
              6,  14,  40, 196,  98,   1,   1,   2,   1,   4,   1,   1,   4,   0,   4,  92,
              2,   1,   4,  48,  19,   6,  14,  40, 196,  98,   1,   1,   2,   1,   4,   1,
              1,   4,   0,   5,  93,   2,   1,   4,  48,  19,   6,  14,  40, 196,  98,   1,
              1,   2,   1,   4,   1,   1,   4,   0,  19,  47,   2,   1,   5,  48,  19,   6,
             14,  40, 196,  98,   1,   1,   2,   1,   4,   1,   1,   4,   0,  22,  54,   2,
              1,   5,  48,  19,   6,  14,  40, 196,  98,   1,   1,   2,   1,   4,   1,   1,
              4,   0,  23,  45,   2,   1,   5,  48,  19,   6,  14,  40, 196,  98,   1,   1,
              2,   1,   4,   1,   1,   4,   0,  24,  52,   2,   1,   5,  48,  19,   6,  14,
             40, 196,  98,   1,   1,   2,   1,   4,   1,   1,   4,   0,  25,  51,   2,   1,
              5,
        ];

        let (rest, asn1) = Snmp2cMessage::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        assert_eq!(asn1.version, 1);
        assert_eq!(asn1.community, b"Fqate");

        let inner_pdu = match asn1.pdu {
            Snmp2cPdu::Response(inner) => inner,
            _ => panic!(),
        };
        assert_eq!(inner_pdu.request_id, 649110371);
        assert_eq!(inner_pdu.error_status, ErrorStatus::NoError);
        assert_eq!(inner_pdu.error_index, 0);
        assert_eq!(inner_pdu.variable_bindings.len(), 10);

        assert_eq!(inner_pdu.variable_bindings[0].name, "1.0.8802.1.1.2.1.4.1.1.4.0.1.95".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[0]), 4);
        assert_eq!(inner_pdu.variable_bindings[1].name, "1.0.8802.1.1.2.1.4.1.1.4.0.2.94".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[1]), 4);
        assert_eq!(inner_pdu.variable_bindings[2].name, "1.0.8802.1.1.2.1.4.1.1.4.0.3.96".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[2]), 5);
        assert_eq!(inner_pdu.variable_bindings[3].name, "1.0.8802.1.1.2.1.4.1.1.4.0.4.92".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[3]), 4);
        assert_eq!(inner_pdu.variable_bindings[4].name, "1.0.8802.1.1.2.1.4.1.1.4.0.5.93".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[4]), 4);
        assert_eq!(inner_pdu.variable_bindings[5].name, "1.0.8802.1.1.2.1.4.1.1.4.0.19.47".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[5]), 5);
        assert_eq!(inner_pdu.variable_bindings[6].name, "1.0.8802.1.1.2.1.4.1.1.4.0.22.54".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[6]), 5);
        assert_eq!(inner_pdu.variable_bindings[7].name, "1.0.8802.1.1.2.1.4.1.1.4.0.23.45".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[7]), 5);
        assert_eq!(inner_pdu.variable_bindings[8].name, "1.0.8802.1.1.2.1.4.1.1.4.0.24.52".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[8]), 5);
        assert_eq!(inner_pdu.variable_bindings[9].name, "1.0.8802.1.1.2.1.4.1.1.4.0.25.51".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[9]), 5);
    }

    #[test]
    fn test_encode1() {
        let message = Snmp2cMessage {
            version: 1,
            community: b"Fqate".to_vec(),
            pdu: Snmp2cPdu::Response(InnerPdu {
                request_id: 649110371,
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings: vec![
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.1.95".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(4)),
                    },
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.2.94".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(4)),
                    },
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.3.96".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(5)),
                    },
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.4.92".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(4)),
                    },
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.5.93".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(4)),
                    },
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.19.47".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(5)),
                    },
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.22.54".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(5)),
                    },
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.23.45".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(5)),
                    },
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.24.52".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(5)),
                    },
                    VariableBinding {
                        name: "1.0.8802.1.1.2.1.4.1.1.4.0.25.51".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(5)),
                    },
                ],
            }),
        };
        let bytes = message.to_bytes().unwrap();

        let expected_bytes: Vec<u8> = vec![
             48, 129, 238,   2,   1,   1,   4,   5,  70, 113,  97, 116, 101, 162, 129, 225,
              2,   4,  38, 176, 163,  99,   2,   1,   0,   2,   1,   0,  48, 129, 210,  48,
             19,   6,  14,  40, 196,  98,   1,   1,   2,   1,   4,   1,   1,   4,   0,   1,
             95,   2,   1,   4,  48,  19,   6,  14,  40, 196,  98,   1,   1,   2,   1,   4,
              1,   1,   4,   0,   2,  94,   2,   1,   4,  48,  19,   6,  14,  40, 196,  98,
              1,   1,   2,   1,   4,   1,   1,   4,   0,   3,  96,   2,   1,   5,  48,  19,
              6,  14,  40, 196,  98,   1,   1,   2,   1,   4,   1,   1,   4,   0,   4,  92,
              2,   1,   4,  48,  19,   6,  14,  40, 196,  98,   1,   1,   2,   1,   4,   1,
              1,   4,   0,   5,  93,   2,   1,   4,  48,  19,   6,  14,  40, 196,  98,   1,
              1,   2,   1,   4,   1,   1,   4,   0,  19,  47,   2,   1,   5,  48,  19,   6,
             14,  40, 196,  98,   1,   1,   2,   1,   4,   1,   1,   4,   0,  22,  54,   2,
              1,   5,  48,  19,   6,  14,  40, 196,  98,   1,   1,   2,   1,   4,   1,   1,
              4,   0,  23,  45,   2,   1,   5,  48,  19,   6,  14,  40, 196,  98,   1,   1,
              2,   1,   4,   1,   1,   4,   0,  24,  52,   2,   1,   5,  48,  19,   6,  14,
             40, 196,  98,   1,   1,   2,   1,   4,   1,   1,   4,   0,  25,  51,   2,   1,
              5,
        ];
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_decode2() {
        let bytes: Vec<u8> = vec![
             48, 130,   1, 162,   2,   1,   1,   4,   5,  57, 118,  55,  57,  73, 162, 130,
              1, 148,   2,   1,   1,   2,   1,   0,   2,   1,   0,  48, 130,   1, 135,  48,
            129, 202,   6,   8,  43,   6,   1,   2,   1,   1,   1,   0,   4, 129, 189,  67,
            105, 115,  99, 111,  32,  78,  88,  45,  79,  83,  40, 116, 109,  41,  32, 110,
             53,  48,  48,  48,  44,  32,  83, 111, 102, 116, 119,  97, 114, 101,  32,  40,
            110,  53,  48,  48,  48,  45, 117, 107,  57,  41,  44,  32,  86, 101, 114, 115,
            105, 111, 110,  32,  54,  46,  48,  40,  50,  41,  78,  50,  40,  52,  41,  44,
             32,  82,  69,  76,  69,  65,  83,  69,  32,  83,  79,  70,  84,  87,  65,  82,
             69,  32,  67, 111, 112, 121, 114, 105, 103, 104, 116,  32,  40,  99,  41,  32,
             50,  48,  48,  50,  45,  50,  48,  49,  50,  32,  98, 121,  32,  67, 105, 115,
             99, 111,  32,  83, 121, 115, 116, 101, 109, 115,  44,  32,  73, 110,  99,  46,
             32,  68, 101, 118, 105,  99, 101,  32,  77,  97, 110,  97, 103, 101, 114,  32,
             86, 101, 114, 115, 105, 111, 110,  32,  54,  46,  50,  40,  49,  41,  44,  32,
             32,  67, 111, 109, 112, 105, 108, 101, 100,  32,  50,  47,  50,  52,  47,  50,
             48,  49,  52,  32,  49,  52,  58,  48,  48,  58,  48,  48,  48,  24,   6,   8,
             43,   6,   1,   2,   1,   1,   2,   0,   6,  12,  43,   6,   1,   4,   1,   9,
             12,   3,   1,   3, 135, 112,  48,  17,   6,   8,  43,   6,   1,   2,   1,   1,
              3,   0,  67,   5,   0, 153, 230, 155, 197,  48,  15,   6,   8,  43,   6,   1,
              2,   1,   1,   4,   0,   4,   3,  75,  79,  77,  48,  20,   6,   8,  43,   6,
              1,   2,   1,   1,   5,   0,   4,   8, 115, 119,  45, 100,  45, 115, 110,  49,
             48,  19,   6,   8,  43,   6,   1,   2,   1,   1,   6,   0,   4,   7,  68,  67,
             48,  50,  77,  48,  50,  48,  13,   6,   8,  43,   6,   1,   2,   1,   1,   7,
              0,   2,   1,  70,  48,  17,   6,   8,  43,   6,   1,   2,   1,   1,   8,   0,
             67,   5,   0, 255, 255, 255, 126,  48,  20,   6,  10,  43,   6,   1,   2,   1,
              1,   9,   1,   2,   1,   6,   6,  43,   6,   1,   6,   3,   1,  48,  23,   6,
             10,  43,   6,   1,   2,   1,   1,   9,   1,   2,   2,   6,   9,  43,   6,   1,
              6,   3,  16,   2,   2,   1,
        ];

        let (rest, asn1) = Snmp2cMessage::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        assert_eq!(asn1.version, 1);
        assert_eq!(asn1.community, b"9v79I");

        let inner_pdu = match asn1.pdu {
            Snmp2cPdu::Response(inner) => inner,
            _ => panic!(),
        };
        assert_eq!(inner_pdu.request_id, 1);
        assert_eq!(inner_pdu.error_status, ErrorStatus::NoError);
        assert_eq!(inner_pdu.error_index, 0);
        assert_eq!(inner_pdu.variable_bindings.len(), 10);

        assert_eq!(inner_pdu.variable_bindings[0].name, "1.3.6.1.2.1.1.1.0".parse().unwrap());
        assert_eq!(gimme_octets(&inner_pdu.variable_bindings[0]), b"Cisco NX-OS(tm) n5000, Software (n5000-uk9), Version 6.0(2)N2(4), RELEASE SOFTWARE Copyright (c) 2002-2012 by Cisco Systems, Inc. Device Manager Version 6.2(1),  Compiled 2/24/2014 14:00:00");
        assert_eq!(inner_pdu.variable_bindings[1].name, "1.3.6.1.2.1.1.2.0".parse().unwrap());
        assert_eq!(gimme_oid(&inner_pdu.variable_bindings[1]), "1.3.6.1.4.1.9.12.3.1.3.1008".parse().unwrap());
        assert_eq!(inner_pdu.variable_bindings[2].name, "1.3.6.1.2.1.1.3.0".parse().unwrap());
        assert_eq!(gimme_time(&inner_pdu.variable_bindings[2]), 2582027205);
        assert_eq!(inner_pdu.variable_bindings[3].name, "1.3.6.1.2.1.1.4.0".parse().unwrap());
        assert_eq!(gimme_octets(&inner_pdu.variable_bindings[3]), b"KOM");
        assert_eq!(inner_pdu.variable_bindings[4].name, "1.3.6.1.2.1.1.5.0".parse().unwrap());
        assert_eq!(gimme_octets(&inner_pdu.variable_bindings[4]), b"sw-d-sn1");
        assert_eq!(inner_pdu.variable_bindings[5].name, "1.3.6.1.2.1.1.6.0".parse().unwrap());
        assert_eq!(gimme_octets(&inner_pdu.variable_bindings[5]), b"DC02M02");
        assert_eq!(inner_pdu.variable_bindings[6].name, "1.3.6.1.2.1.1.7.0".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[6]), 70);
        assert_eq!(inner_pdu.variable_bindings[7].name, "1.3.6.1.2.1.1.8.0".parse().unwrap());
        assert_eq!(gimme_time(&inner_pdu.variable_bindings[7]), 4294967166);
        assert_eq!(inner_pdu.variable_bindings[8].name, "1.3.6.1.2.1.1.9.1.2.1".parse().unwrap());
        assert_eq!(gimme_oid(&inner_pdu.variable_bindings[8]), "1.3.6.1.6.3.1".parse().unwrap());
        assert_eq!(inner_pdu.variable_bindings[9].name, "1.3.6.1.2.1.1.9.1.2.2".parse().unwrap());
        assert_eq!(gimme_oid(&inner_pdu.variable_bindings[9]), "1.3.6.1.6.3.16.2.2.1".parse().unwrap());
    }

    #[test]
    fn test_encode2() {
        let message = Snmp2cMessage {
            version: 1,
            community: b"9v79I".to_vec(),
            pdu: Snmp2cPdu::Response(InnerPdu {
                request_id: 1,
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings: vec![
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.1.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::String(b"Cisco NX-OS(tm) n5000, Software (n5000-uk9), Version 6.0(2)N2(4), RELEASE SOFTWARE Copyright (c) 2002-2012 by Cisco Systems, Inc. Device Manager Version 6.2(1),  Compiled 2/24/2014 14:00:00".to_vec())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.2.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::ObjectId("1.3.6.1.4.1.9.12.3.1.3.1008".parse().unwrap())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.3.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::TimeTicks(2582027205)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.4.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::String(b"KOM".to_vec())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.5.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::String(b"sw-d-sn1".to_vec())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.6.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::String(b"DC02M02".to_vec())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.7.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(70)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.8.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::TimeTicks(4294967166)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.9.1.2.1".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::ObjectId("1.3.6.1.6.3.1".parse().unwrap())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.2.1.1.9.1.2.2".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::ObjectId("1.3.6.1.6.3.16.2.2.1".parse().unwrap())),
                    },
                ],
            }),
        };
        let bytes = message.to_bytes().unwrap();

        let expected_bytes: Vec<u8> = vec![
             48, 130,   1, 162,   2,   1,   1,   4,   5,  57, 118,  55,  57,  73, 162, 130,
              1, 148,   2,   1,   1,   2,   1,   0,   2,   1,   0,  48, 130,   1, 135,  48,
            129, 202,   6,   8,  43,   6,   1,   2,   1,   1,   1,   0,   4, 129, 189,  67,
            105, 115,  99, 111,  32,  78,  88,  45,  79,  83,  40, 116, 109,  41,  32, 110,
             53,  48,  48,  48,  44,  32,  83, 111, 102, 116, 119,  97, 114, 101,  32,  40,
            110,  53,  48,  48,  48,  45, 117, 107,  57,  41,  44,  32,  86, 101, 114, 115,
            105, 111, 110,  32,  54,  46,  48,  40,  50,  41,  78,  50,  40,  52,  41,  44,
             32,  82,  69,  76,  69,  65,  83,  69,  32,  83,  79,  70,  84,  87,  65,  82,
             69,  32,  67, 111, 112, 121, 114, 105, 103, 104, 116,  32,  40,  99,  41,  32,
             50,  48,  48,  50,  45,  50,  48,  49,  50,  32,  98, 121,  32,  67, 105, 115,
             99, 111,  32,  83, 121, 115, 116, 101, 109, 115,  44,  32,  73, 110,  99,  46,
             32,  68, 101, 118, 105,  99, 101,  32,  77,  97, 110,  97, 103, 101, 114,  32,
             86, 101, 114, 115, 105, 111, 110,  32,  54,  46,  50,  40,  49,  41,  44,  32,
             32,  67, 111, 109, 112, 105, 108, 101, 100,  32,  50,  47,  50,  52,  47,  50,
             48,  49,  52,  32,  49,  52,  58,  48,  48,  58,  48,  48,  48,  24,   6,   8,
             43,   6,   1,   2,   1,   1,   2,   0,   6,  12,  43,   6,   1,   4,   1,   9,
             12,   3,   1,   3, 135, 112,  48,  17,   6,   8,  43,   6,   1,   2,   1,   1,
              3,   0,  67,   5,   0, 153, 230, 155, 197,  48,  15,   6,   8,  43,   6,   1,
              2,   1,   1,   4,   0,   4,   3,  75,  79,  77,  48,  20,   6,   8,  43,   6,
              1,   2,   1,   1,   5,   0,   4,   8, 115, 119,  45, 100,  45, 115, 110,  49,
             48,  19,   6,   8,  43,   6,   1,   2,   1,   1,   6,   0,   4,   7,  68,  67,
             48,  50,  77,  48,  50,  48,  13,   6,   8,  43,   6,   1,   2,   1,   1,   7,
              0,   2,   1,  70,  48,  17,   6,   8,  43,   6,   1,   2,   1,   1,   8,   0,
             67,   5,   0, 255, 255, 255, 126,  48,  20,   6,  10,  43,   6,   1,   2,   1,
              1,   9,   1,   2,   1,   6,   6,  43,   6,   1,   6,   3,   1,  48,  23,   6,
             10,  43,   6,   1,   2,   1,   1,   9,   1,   2,   2,   6,   9,  43,   6,   1,
              6,   3,  16,   2,   2,   1,
        ];
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_decode3() {
        let bytes: Vec<u8> = vec![
             48, 130,   1,  53,   2,   1,   1,   4,   8, 114, 101,  97, 100, 111, 110, 108,
            121, 162, 130,   1,  36,   2,   1,   1,   2,   1,   0,   2,   1,   0,  48, 130,
              1,  23,  48,  20,   6,  15,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134,
            141,  31,  69,   1,   0,   2,   1, 214,  48,  43,   6,  15,  43,   6,   1,   4,
              1, 130, 139,  19,   1, 134, 141,  31,  69,   2,   0,   4,  24,  65,  32,  99,
            111,  99, 111, 110, 117, 116,  32, 105, 115,  32, 106, 117, 115, 116,  32,  97,
             32, 110, 117, 116,  46,  48,  22,   6,  15,  43,   6,   1,   4,   1, 130, 139,
             19,   1, 134, 141,  31,  69,   3,   0,   4,   3,  23,  42,  69,  48,  33,   6,
             15,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134, 141,  31,  69,   4,   0,
              6,  14,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134, 141,  31,  69,   9,
             48,  23,   6,  15,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134, 141,  31,
             69,   5,   0,  64,   4, 128, 131,  34,  30,  48,  24,   6,  15,  43,   6,   1,
              4,   1, 130, 139,  19,   1, 134, 141,  31,  69,   6,   0,  65,   5,   0, 254,
            254, 254, 254,  48,  24,   6,  15,  43,   6,   1,   4,   1, 130, 139,  19,   1,
            134, 141,  31,  69,   7,   0,  66,   5,   0, 222, 173, 190, 239,  48,  24,   6,
             15,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134, 141,  31,  69,   8,   0,
             67,   5,   0, 165,  95, 172, 229,  48,  28,   6,  15,  43,   6,   1,   4,   1,
            130, 139,  19,   1, 134, 141,  31,  69,   9,   0,  70,   9,   0, 222, 173, 190,
            239, 165,  95, 172, 229,  48,  18,   6,  10,  43,   6,   1,   6,   3,   1,   1,
              6,   1,   0,   2,   4,  36,  24,   7,  18,
        ];

        let (rest, asn1) = Snmp2cMessage::try_parse(&bytes).unwrap();
        assert_eq!(rest, b"");

        assert_eq!(asn1.version, 1);
        assert_eq!(asn1.community, b"readonly");

        let inner_pdu = match asn1.pdu {
            Snmp2cPdu::Response(inner) => inner,
            _ => panic!(),
        };
        assert_eq!(inner_pdu.request_id, 1);
        assert_eq!(inner_pdu.error_status, ErrorStatus::NoError);
        assert_eq!(inner_pdu.error_index, 0);
        assert_eq!(inner_pdu.variable_bindings.len(), 10);

        assert_eq!(inner_pdu.variable_bindings[0].name, "1.3.6.1.4.1.34195.1.99999.69.1.0".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[0]), -42);
        assert_eq!(inner_pdu.variable_bindings[1].name, "1.3.6.1.4.1.34195.1.99999.69.2.0".parse().unwrap());
        assert_eq!(gimme_octets(&inner_pdu.variable_bindings[1]), b"A coconut is just a nut.");
        assert_eq!(inner_pdu.variable_bindings[2].name, "1.3.6.1.4.1.34195.1.99999.69.3.0".parse().unwrap());
        assert_eq!(gimme_octets(&inner_pdu.variable_bindings[2]), &[23, 42, 69]);
        assert_eq!(inner_pdu.variable_bindings[3].name, "1.3.6.1.4.1.34195.1.99999.69.4.0".parse().unwrap());
        assert_eq!(gimme_oid(&inner_pdu.variable_bindings[3]), "1.3.6.1.4.1.34195.1.99999.69.9".parse().unwrap());
        assert_eq!(inner_pdu.variable_bindings[4].name, "1.3.6.1.4.1.34195.1.99999.69.5.0".parse().unwrap());
        assert_eq!(gimme_ip(&inner_pdu.variable_bindings[4]), "128.131.34.30".parse::<Ipv4Addr>().unwrap());
        assert_eq!(inner_pdu.variable_bindings[5].name, "1.3.6.1.4.1.34195.1.99999.69.6.0".parse().unwrap());
        assert_eq!(gimme_counter(&inner_pdu.variable_bindings[5]), 0xFEFEFEFE);
        assert_eq!(inner_pdu.variable_bindings[6].name, "1.3.6.1.4.1.34195.1.99999.69.7.0".parse().unwrap());
        assert_eq!(gimme_unsigned(&inner_pdu.variable_bindings[6]), 0xDEADBEEF);
        assert_eq!(inner_pdu.variable_bindings[7].name, "1.3.6.1.4.1.34195.1.99999.69.8.0".parse().unwrap());
        assert_eq!(gimme_time(&inner_pdu.variable_bindings[7]), 0xA55FACE5);
        assert_eq!(inner_pdu.variable_bindings[8].name, "1.3.6.1.4.1.34195.1.99999.69.9.0".parse().unwrap());
        assert_eq!(gimme_counter64(&inner_pdu.variable_bindings[8]), 0xDEADBEEFA55FACE5);
        assert_eq!(inner_pdu.variable_bindings[9].name, "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[9]), 605554450);
    }

    #[test]
    fn test_encode3() {
        let message = Snmp2cMessage {
            version: 1,
            community: b"readonly".to_vec(),
            pdu: Snmp2cPdu::Response(InnerPdu {
                request_id: 1,
                error_status: ErrorStatus::NoError,
                error_index: 0,
                variable_bindings: vec![
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.1.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(-42)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.2.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::String(b"A coconut is just a nut.".to_vec())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.3.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::String([23, 42, 69].to_vec())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.4.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::ObjectId("1.3.6.1.4.1.34195.1.99999.69.9".parse().unwrap())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.5.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::IpAddress("128.131.34.30".parse().unwrap())),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.6.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Counter32(0xFEFEFEFE)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.7.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Unsigned32(0xDEADBEEF)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.8.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::TimeTicks(0xA55FACE5)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.9.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Counter64(0xDEADBEEFA55FACE5)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(605554450)),
                    },
                ],
            }),
        };
        let bytes = message.to_bytes().unwrap();

        let expected_bytes: Vec<u8> = vec![
             48, 130,   1,  53,   2,   1,   1,   4,   8, 114, 101,  97, 100, 111, 110, 108,
            121, 162, 130,   1,  36,   2,   1,   1,   2,   1,   0,   2,   1,   0,  48, 130,
              1,  23,  48,  20,   6,  15,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134,
            141,  31,  69,   1,   0,   2,   1, 214,  48,  43,   6,  15,  43,   6,   1,   4,
              1, 130, 139,  19,   1, 134, 141,  31,  69,   2,   0,   4,  24,  65,  32,  99,
            111,  99, 111, 110, 117, 116,  32, 105, 115,  32, 106, 117, 115, 116,  32,  97,
             32, 110, 117, 116,  46,  48,  22,   6,  15,  43,   6,   1,   4,   1, 130, 139,
             19,   1, 134, 141,  31,  69,   3,   0,   4,   3,  23,  42,  69,  48,  33,   6,
             15,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134, 141,  31,  69,   4,   0,
              6,  14,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134, 141,  31,  69,   9,
             48,  23,   6,  15,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134, 141,  31,
             69,   5,   0,  64,   4, 128, 131,  34,  30,  48,  24,   6,  15,  43,   6,   1,
              4,   1, 130, 139,  19,   1, 134, 141,  31,  69,   6,   0,  65,   5,   0, 254,
            254, 254, 254,  48,  24,   6,  15,  43,   6,   1,   4,   1, 130, 139,  19,   1,
            134, 141,  31,  69,   7,   0,  66,   5,   0, 222, 173, 190, 239,  48,  24,   6,
             15,  43,   6,   1,   4,   1, 130, 139,  19,   1, 134, 141,  31,  69,   8,   0,
             67,   5,   0, 165,  95, 172, 229,  48,  28,   6,  15,  43,   6,   1,   4,   1,
            130, 139,  19,   1, 134, 141,  31,  69,   9,   0,  70,   9,   0, 222, 173, 190,
            239, 165,  95, 172, 229,  48,  18,   6,  10,  43,   6,   1,   6,   3,   1,   1,
              6,   1,   0,   2,   4,  36,  24,   7,  18,
        ];
        assert_eq!(bytes, expected_bytes);
    }
}
