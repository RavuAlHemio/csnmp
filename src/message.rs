use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;

use derivative::Derivative;
use from_to_repr::FromToRepr;
use simple_asn1::{
    ASN1Block, ASN1Class, ASN1DecodeErr, ASN1EncodeErr, BigInt, BigUint, FromASN1, from_der, OID,
    ToASN1, to_der,
};

use crate::oid::{ObjectIdentifier, ObjectIdentifierConversionError};


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


/// An error that has occurred while attempting to read an SNMP message.
#[derive(Clone, Debug, PartialEq)]
pub enum SnmpMessageError {
    /// An error has occurred while attempting to parse the ASN.1 message.
    Asn1Decoding(ASN1DecodeErr),

    /// An error has occurred while attempting to encode the ASN.1 message.
    Asn1Encoding(ASN1EncodeErr),

    /// The message, or a part of it, has an incorrect length. A specific length is expected.
    ///
    /// `expected` and `obtained` are in units of ASN.1 blocks.
    Length { expected: usize, obtained: usize },

    /// The message, or a part of it, was too short. A minimum length is expected.
    ///
    /// `expected` and `obtained` are in units of ASN.1 blocks.
    TooShort { expected: usize, obtained: usize },

    /// While decoding the message, a different type was read than expected.
    UnexpectedType { expected: ExpectedAsn1Type, obtained: ASN1Block },

    /// While decoding an integer, it did not fit in the range of a primitive type.
    IntegerPrimitiveRange { primitive_type: &'static str, obtained: ASN1Block },

    /// The SNMP message has an incorrect version.
    IncorrectVersion { expected: i64, obtained: i64 },

    /// A value was tagged by an unexpected tag.
    UnexpectedTag { obtained: BigUint },

    /// A value was tagged by a tag of an unexpected class.
    UnexpectedTagClass { expected: Vec<ASN1Class>, obtained: ASN1Class },

    /// A value was expected to be tagged but wasn't.
    UntaggedValue { obtained: ASN1Block },

    /// An out-of-range value has been obtained for an enumeration.
    EnumRange { enum_name: &'static str, obtained: ASN1Block },

    /// An object identifier has been encountered which is a valid ASN.1 object identifier but not
    /// a valid SNMP object identifier.
    OidDecode { oid: OID, error: ObjectIdentifierConversionError },

    /// An object identifier has been encountered which is a valid SNMP object identifier but not
    /// a valid ASN.1 object identifier.
    OidEncode { oid: ObjectIdentifier, error: ObjectIdentifierConversionError },
}
impl SnmpMessageError {
    /// Checks whether the given slice of [`ASN1Block`s][ASN1Block] has at least the given number of
    /// elements. Returns `Ok(())` if it does and `Err(_)` with an appropriate [`SnmpMessageError`]
    /// variant if it does not.
    pub fn check_min_length(blocks: &[ASN1Block], expected: usize) -> Result<(), SnmpMessageError> {
        if blocks.len() < expected {
            Err(SnmpMessageError::TooShort {
                expected,
                obtained: blocks.len(),
            })
        } else {
            Ok(())
        }
    }

    /// Checks whether the given slice of [`ASN1Block`s][ASN1Block] has exactly the given number of
    /// elements. Returns `Ok(())` if it does and `Err(_)` with an appropriate [`SnmpMessageError`]
    /// variant if it does not.
    pub fn check_length(blocks: &[ASN1Block], expected: usize) -> Result<(), SnmpMessageError> {
        if blocks.len() == expected {
            Ok(())
        } else {
            Err(SnmpMessageError::Length {
                expected,
                obtained: blocks.len(),
            })
        }
    }

    /// Checks whether the given [`ASN1Class`] has the given value. Returns `Ok(())` if it does and
    /// `Err(_)` with an appropriate [`SnmpMessageError`] variant if it does not.
    pub fn check_tag_class(obtained: ASN1Class, expected: ASN1Class) -> Result<(), SnmpMessageError> {
        if obtained == expected {
            Ok(())
        } else {
            Err(SnmpMessageError::UnexpectedTagClass {
                expected: vec![expected],
                obtained,
            })
        }
    }
}
impl fmt::Display for SnmpMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1Decoding(asn1)
                => write!(f, "ASN.1 decoding error: {asn1}"),
            Self::Asn1Encoding(asn1)
                => write!(f, "ASN.1 encoding error: {asn1}"),
            Self::Length { expected, obtained }
                => write!(f, "message has wrong length: expected {expected} ASN.1 blocks, obtained {obtained}"),
            Self::TooShort { expected, obtained }
                => write!(f, "message too short: expected {expected} ASN.1 blocks, obtained {obtained}"),
            Self::UnexpectedType { expected, obtained }
                => write!(f, "expected {expected:?} value, obtained {obtained:?}"),
            Self::IntegerPrimitiveRange { primitive_type, obtained }
                => write!(f, "integer value does not fit into {primitive_type}, obtained {obtained:?}"),
            Self::IncorrectVersion { expected, obtained }
                => write!(f, "incorrect SNMP message version: expected {expected}, obtained {obtained}"),
            Self::UnexpectedTag { obtained }
                => write!(f, "unexpected tag; obtained {obtained:?}"),
            Self::UnexpectedTagClass { expected, obtained }
                => write!(f, "unexpected tag class: expected {expected:?}, obtained {obtained:?}"),
            Self::UntaggedValue { obtained }
                => write!(f, "untagged value; obtained {obtained:?}"),
            Self::EnumRange { enum_name, obtained }
                => write!(f, "invalid value {obtained:?} obtained for enumeration {enum_name:?}"),
            Self::OidDecode { oid, error }
                => write!(f, "object identifier {oid:?} invalid for SNMP: {error}"),
            Self::OidEncode { oid, error }
                => write!(f, "object identifier {oid:?} invalid for ASN.1: {error}"),
        }
    }
}
impl Error for SnmpMessageError {
}
impl From<ASN1DecodeErr> for SnmpMessageError {
    fn from(e: ASN1DecodeErr) -> Self { Self::Asn1Decoding(e) }
}
impl From<ASN1EncodeErr> for SnmpMessageError {
    fn from(e: ASN1EncodeErr) -> Self { Self::Asn1Encoding(e) }
}


/// Implements a conversion from an ASN.1 number block to a primitive integral value.
macro_rules! asn1_number_to_primitive {
    ($name:ident, $type:ty) => {
        fn $name(&self) -> Result<$type, SnmpMessageError> {
            if let Self::Integer(_offset, value) = self {
                value.try_into()
                    .map_err(|_| SnmpMessageError::IntegerPrimitiveRange {
                        primitive_type: stringify!($type),
                        obtained: self.clone(),
                    })
            } else {
                Err(SnmpMessageError::UnexpectedType {
                    expected: ExpectedAsn1Type::Integer,
                    obtained: self.clone(),
                })
            }
        }
    };
}

/// Implements a conversion from a primitive integral value to an ASN.1 number block.
macro_rules! asn1_number_from_primitive {
    ($name:ident, $type:ty) => {
        fn $name(i: $type) -> Self { Self::Integer(0, BigInt::from(i)) }
    };
}



/// Extension functions on [`ASN1Block`].
trait Asn1BlockExtensions: Sized {
    /// Attempts to decode the block as an integer and convert it to an `i32`.
    fn as_i32(&self) -> Result<i32, SnmpMessageError>;

    /// Attempts to decode the block as an integer and convert it to an `i64`.
    fn as_i64(&self) -> Result<i64, SnmpMessageError>;

    /// Attempts to decode the block as an integer and convert it to a `u8`.
    fn as_u8(&self) -> Result<u8, SnmpMessageError>;

    /// Attempts to decode the block as an integer and convert it to a `u32`.
    fn as_u32(&self) -> Result<u32, SnmpMessageError>;

    /// Attempts to decode the block as an integer and convert it to a `u64`.
    fn as_u64(&self) -> Result<u64, SnmpMessageError>;

    /// Attempts to decode the block as an integer and convert it to a [`BigInt`].
    fn as_big_int(&self) -> Result<BigInt, SnmpMessageError>;

    /// Attempts to decode the block as an integer and convert it to a [`BigUint`].
    fn as_big_uint(&self) -> Result<BigUint, SnmpMessageError>;

    /// Attempts to decode the block as an octet string and return it as a reference to a `Vec<u8>`.
    fn as_bytes(&self) -> Result<&Vec<u8>, SnmpMessageError>;

    /// Attempts to decode the block a sequence and return it as a reference to a `Vec<Self>`.
    fn as_sequence(&self) -> Result<&Vec<Self>, SnmpMessageError>;

    /// Attempts to decode the block an object identifier.
    fn as_oid(&self) -> Result<&OID, SnmpMessageError>;

    /// Returns whether this block is a null block.
    fn is_null(&self) -> bool;

    /// Wraps an u8 in an ASN.1 number block.
    fn from_u8(i: u8) -> Self;

    /// Wraps an i32 in an ASN.1 number block.
    fn from_i32(i: i32) -> Self;

    /// Wraps an i64 in an ASN.1 number block.
    fn from_i64(i: i64) -> Self;

    /// Wraps a u32 in an ASN.1 number block.
    fn from_u32(i: u32) -> Self;

    /// Wraps a u64 in an ASN.1 number block.
    fn from_u64(i: u64) -> Self;

    /// Wraps a slice of bytes in an ASN.1 octet-string block.
    fn from_bytes(bs: &[u8]) -> Self;

    /// Attempts to return the tag of this value.
    fn implicit_tag(&self) -> Result<(ASN1Class, BigUint), SnmpMessageError>;

    /// Attempts to return the tag of this value as long as it is the type of tag specified by the
    /// argument.
    fn tag_of_class(&self, of_class: ASN1Class) -> Result<BigUint, SnmpMessageError> {
        let (cls, tag) = self.implicit_tag()?;
        if cls == of_class {
            Ok(tag)
        } else {
            Err(SnmpMessageError::UnexpectedTagClass {
                expected: vec![of_class],
                obtained: cls,
            })
        }
    }

    /// Attempts to return the value without its tag.
    fn untag_implicit(&self) -> Result<Self, SnmpMessageError>;

    /// Packs this value into a tag.
    fn with_tag(self, of_class: ASN1Class, tag: BigUint) -> Self;
}
impl Asn1BlockExtensions for ASN1Block {
    asn1_number_to_primitive!(as_i64, i64);
    asn1_number_to_primitive!(as_i32, i32);
    asn1_number_to_primitive!(as_u8, u8);
    asn1_number_to_primitive!(as_u32, u32);
    asn1_number_to_primitive!(as_u64, u64);

    fn as_big_int(&self) -> Result<BigInt, SnmpMessageError> {
        if let Self::Integer(_offset, value) = self {
            Ok(value.clone())
        } else {
            Err(SnmpMessageError::UnexpectedType {
                expected: ExpectedAsn1Type::Integer,
                obtained: self.clone(),
            })
        }
    }

    fn as_big_uint(&self) -> Result<BigUint, SnmpMessageError> {
        if let Self::Integer(_offset, value) = self {
            value.try_into()
                .map_err(|_| SnmpMessageError::IntegerPrimitiveRange {
                    primitive_type: "BigUint",
                    obtained: self.clone(),
                })
        } else {
            Err(SnmpMessageError::UnexpectedType {
                expected: ExpectedAsn1Type::Integer,
                obtained: self.clone(),
            })
        }
    }

    fn as_bytes(&self) -> Result<&Vec<u8>, SnmpMessageError> {
        if let Self::OctetString(_offset, bytes) = self {
            Ok(bytes)
        } else {
            Err(SnmpMessageError::UnexpectedType {
                expected: ExpectedAsn1Type::OctetString,
                obtained: self.clone(),
            })
        }
    }

    fn as_sequence(&self) -> Result<&Vec<Self>, SnmpMessageError> {
        if let Self::Sequence(_offset, blocks) = self {
            Ok(blocks)
        } else {
            Err(SnmpMessageError::UnexpectedType {
                expected: ExpectedAsn1Type::Sequence,
                obtained: self.clone(),
            })
        }
    }

    fn as_oid(&self) -> Result<&OID, SnmpMessageError> {
        if let Self::ObjectIdentifier(_offset, oid) = self {
            Ok(oid)
        } else {
            Err(SnmpMessageError::UnexpectedType {
                expected: ExpectedAsn1Type::Oid,
                obtained: self.clone(),
            })
        }
    }

    fn is_null(&self) -> bool {
        matches!(self, Self::Null(_offset))
    }

    asn1_number_from_primitive!(from_i32, i32);
    asn1_number_from_primitive!(from_i64, i64);
    asn1_number_from_primitive!(from_u8, u8);
    asn1_number_from_primitive!(from_u32, u32);
    asn1_number_from_primitive!(from_u64, u64);

    fn from_bytes(bs: &[u8]) -> Self {
        Self::OctetString(0, Vec::from(bs))
    }

    fn implicit_tag(&self) -> Result<(ASN1Class, BigUint), SnmpMessageError> {
        if let Self::Unknown(cls, _constructed, _offset, tag, _content) = self {
            Ok((*cls, tag.clone()))
        } else {
            Err(SnmpMessageError::UntaggedValue {
                obtained: self.clone(),
            })
        }
    }

    fn untag_implicit(&self) -> Result<Self, SnmpMessageError> {
        if let Self::Unknown(_cls, _constructed, offset, _tag, content) = self {
            let parsed_blocks = from_der(content)?;
            let sequence = ASN1Block::Sequence(*offset, parsed_blocks);
            Ok(sequence)
        } else {
            Err(SnmpMessageError::UntaggedValue {
                obtained: self.clone(),
            })
        }
    }

    fn with_tag(self, of_class: ASN1Class, tag: BigUint) -> Self {
        Self::Explicit(of_class, self.offset(), tag, Box::new(self))
    }
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
impl Snmp2cMessage {
    /// Serializes this SNMP2c message into a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SnmpMessageError> {
        simple_asn1::der_encode(self)
    }

    /// Attempts to deserialize this SNMP2c message from a slice of bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, SnmpMessageError> {
        simple_asn1::der_decode(bytes)
    }
}
impl FromASN1 for Snmp2cMessage {
    type Error = SnmpMessageError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        SnmpMessageError::check_min_length(v, 1)?;
        let seq = v[0].as_sequence()?;
        SnmpMessageError::check_length(seq, 3)?;

        let version = seq[0].as_i64()?;
        if version != VERSION_VALUE {
            return Err(SnmpMessageError::IncorrectVersion {
                expected: VERSION_VALUE,
                obtained: version,
            });
        }
        let community = seq[1].as_bytes()?.clone();
        let (pdu, _rest) = Snmp2cPdu::from_asn1(&seq[2..3])?;

        let message = Self {
            version,
            community,
            pdu,
        };
        Ok((message, &v[1..]))
    }
}
impl ToASN1 for Snmp2cMessage {
    type Error = SnmpMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let mut pdu_asn1 = self.pdu.to_asn1()?;
        let mut ret = Vec::with_capacity(2 + pdu_asn1.len());

        ret.push(ASN1Block::from_i64(self.version));
        ret.push(ASN1Block::from_bytes(&self.community));
        ret.append(&mut pdu_asn1);

        Ok(vec![ASN1Block::Sequence(0, ret)])
    }
}

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
    #[must_use]
    pub fn request_id(&self) -> i32 {
        match self {
            Self::GetBulkRequest(p) => p.request_id,
            Self::GetRequest(p)
            | Self::GetNextRequest(p)
            | Self::Response(p)
            | Self::SetRequest(p)
            | Self::InformRequest(p)
            | Self::SnmpV2Trap(p) => p.request_id,
        }
    }
}
impl FromASN1 for Snmp2cPdu {
    type Error = SnmpMessageError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        SnmpMessageError::check_min_length(v, 1)?;
        let tag = v[0].tag_of_class(ASN1Class::ContextSpecific)?;
        let untagged = v[0].untag_implicit()?;

        let tag_0 = BigUint::from(0u8);
        let tag_1 = BigUint::from(1u8);
        let tag_2 = BigUint::from(2u8);
        let tag_3 = BigUint::from(3u8);
        let tag_5 = BigUint::from(5u8);
        let tag_6 = BigUint::from(6u8);
        let tag_7 = BigUint::from(7u8);

        let outer_pdu = if (tag >= tag_0 && tag <= tag_3) || (tag >= tag_6 && tag <= tag_7) {
            let (inner_pdu, _rest) = InnerPdu::from_asn1(&[untagged.clone()])?;
            if tag == tag_0 {
                Self::GetRequest(inner_pdu)
            } else if tag == tag_1 {
                Self::GetNextRequest(inner_pdu)
            } else if tag == tag_2 {
                Self::Response(inner_pdu)
            } else if tag == tag_3 {
                Self::SetRequest(inner_pdu)
            } else if tag == tag_6 {
                Self::InformRequest(inner_pdu)
            } else if tag == tag_7 {
                Self::SnmpV2Trap(inner_pdu)
            } else {
                unreachable!()
            }
        } else if tag == tag_5 {
            let (bulk_pdu, _rest) = BulkPdu::from_asn1(&[untagged.clone()])?;
            Self::GetBulkRequest(bulk_pdu)
        } else {
            return Err(SnmpMessageError::UnexpectedTag {
                obtained: tag,
            });
        };

        Ok((outer_pdu, &v[1..]))
    }
}
impl ToASN1 for Snmp2cPdu {
    type Error = SnmpMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let (tag, inner) = match self {
            Self::GetRequest(pdu) => (0u8, pdu.to_asn1()?),
            Self::GetNextRequest(pdu) => (1, pdu.to_asn1()?),
            Self::Response(pdu) => (2, pdu.to_asn1()?),
            Self::SetRequest(pdu) => (3, pdu.to_asn1()?),
            Self::GetBulkRequest(pdu) => (5, pdu.to_asn1()?),
            Self::InformRequest(pdu) => (6, pdu.to_asn1()?),
            Self::SnmpV2Trap(pdu) => (7, pdu.to_asn1()?),
        };

        let mut all_inner = Vec::new();
        for inner_block in &inner {
            let mut inner_bytes = to_der(inner_block)?;
            all_inner.append(&mut inner_bytes);
        }

        let outer_pdu = ASN1Block::Unknown(
            ASN1Class::ContextSpecific,
            true,
            0,
            BigUint::from(tag),
            all_inner,
        );
        Ok(vec![outer_pdu])
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
impl FromASN1 for InnerPdu {
    type Error = SnmpMessageError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        SnmpMessageError::check_min_length(v, 1)?;
        let seq = v[0].as_sequence()?;
        SnmpMessageError::check_length(seq, 4)?;

        let request_id = seq[0].as_i32()?;
        let error_status = ErrorStatus::try_from(seq[1].as_u8()?)
            .map_err(|_| SnmpMessageError::EnumRange { enum_name: "ErrorStatus", obtained: seq[1].clone() })?;
        let error_index = seq[2].as_u32()?;

        let bindings_sequence = seq[3].as_sequence()?;
        let mut variable_bindings = Vec::with_capacity(bindings_sequence.len());
        for block in bindings_sequence {
            let (binding, _rest) = VariableBinding::from_asn1(&[block.clone()])?;
            variable_bindings.push(binding);
        }

        let inner_pdu = Self {
            request_id,
            error_status,
            error_index,
            variable_bindings,
        };
        Ok((inner_pdu, &v[1..]))
    }
}
impl ToASN1 for InnerPdu {
    type Error = SnmpMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let mut ret = Vec::with_capacity(4);
        ret.push(ASN1Block::from_i32(self.request_id));
        ret.push(ASN1Block::from_u8(self.error_status.into()));
        ret.push(ASN1Block::from_u32(self.error_index));

        let mut bindings = Vec::with_capacity(self.variable_bindings.len());
        for binding in &self.variable_bindings {
            let mut binding_asn1 = binding.to_asn1()?;
            bindings.append(&mut binding_asn1);
        }
        ret.push(ASN1Block::Sequence(0, bindings));

        Ok(ret)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BulkPdu {
    pub request_id: i32,
    pub non_repeaters: u32,
    pub max_repetitions: u32,
    pub variable_bindings: Vec<VariableBinding>,
}
impl FromASN1 for BulkPdu {
    type Error = SnmpMessageError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        SnmpMessageError::check_min_length(v, 1)?;
        let seq = v[0].as_sequence()?;
        SnmpMessageError::check_length(seq, 4)?;

        let request_id = seq[0].as_i32()?;
        let non_repeaters = seq[1].as_u32()?;
        let max_repetitions = seq[2].as_u32()?;

        let bindings_sequence = seq[3].as_sequence()?;
        let mut variable_bindings = Vec::with_capacity(bindings_sequence.len());
        for block in bindings_sequence {
            let (binding, _rest) = VariableBinding::from_asn1(&[block.clone()])?;
            variable_bindings.push(binding);
        }

        let bulk_pdu = Self {
            request_id,
            non_repeaters,
            max_repetitions,
            variable_bindings,
        };
        Ok((bulk_pdu, &v[1..]))
    }
}
impl ToASN1 for BulkPdu {
    type Error = SnmpMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let mut ret = Vec::with_capacity(4);
        ret.push(ASN1Block::from_i32(self.request_id));
        ret.push(ASN1Block::from_u32(self.non_repeaters));
        ret.push(ASN1Block::from_u32(self.max_repetitions));

        let mut bindings = Vec::with_capacity(self.variable_bindings.len());
        for binding in &self.variable_bindings {
            let mut binding_asn1 = binding.to_asn1()?;
            bindings.append(&mut binding_asn1);
        }
        ret.push(ASN1Block::Sequence(0, bindings));

        Ok(ret)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VariableBinding {
    pub name: ObjectIdentifier,
    pub value: BindingValue,
}
impl FromASN1 for VariableBinding {
    type Error = SnmpMessageError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        SnmpMessageError::check_min_length(v, 1)?;
        let seq = v[0].as_sequence()?;
        SnmpMessageError::check_length(seq, 2)?;

        let name_asn1 = seq[0].as_oid()?;
        let name = ObjectIdentifier::try_from(name_asn1)
            .map_err(|error| SnmpMessageError::OidDecode {
                oid: name_asn1.clone(),
                error,
            })?;

        let (value, _rest) = BindingValue::from_asn1(&[seq[1].clone()])?;

        let binding = Self {
            name,
            value,
        };
        Ok((binding, &v[1..]))
    }
}
impl ToASN1 for VariableBinding {
    type Error = SnmpMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let mut val_vec = self.value.to_asn1()?;
        let mut ret = Vec::with_capacity(1 + val_vec.len());

        let name_asn1: OID = (&self.name).try_into()
            .map_err(|error| SnmpMessageError::OidEncode {
                oid: self.name,
                error,
            })?;

        ret.push(ASN1Block::ObjectIdentifier(0, name_asn1));
        ret.append(&mut val_vec);

        let inner_pdu = ASN1Block::Sequence(0, ret);
        Ok(vec![inner_pdu])
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
impl FromASN1 for BindingValue {
    type Error = SnmpMessageError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        SnmpMessageError::check_min_length(v, 1)?;
        let binding_value = match &v[0] {
            ASN1Block::Null(_offset) => Self::Unspecified,
            ASN1Block::Unknown(ASN1Class::ContextSpecific, _constructed, _offset, tag, content_bytes) => {
                if !content_bytes.is_empty() {
                    return Err(SnmpMessageError::UnexpectedType {
                        expected: ExpectedAsn1Type::Null,
                        obtained: v[0].clone(),
                    });
                }

                if tag == &BigUint::from(0u8) {
                    Self::NoSuchObject
                } else if tag == &BigUint::from(1u8) {
                    Self::NoSuchInstance
                } else if tag == &BigUint::from(2u8) {
                    Self::EndOfMibView
                } else {
                    return Err(SnmpMessageError::EnumRange {
                        enum_name: "BindingValue",
                        obtained: v[0].clone(),
                    });
                }
            },
            _other => {
                let (val, _rest) = ObjectValue::from_asn1(v)?;
                Self::Value(val)
            },
        };

        Ok((binding_value, &v[1..]))
    }
}
impl ToASN1 for BindingValue {
    type Error = SnmpMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        match self {
            Self::Unspecified => Ok(vec![ASN1Block::Null(0)]),
            Self::Value(val) => val.to_asn1(),
            Self::NoSuchObject|Self::NoSuchInstance|Self::EndOfMibView => {
                let tag: u8 = match self {
                    Self::NoSuchObject => 0,
                    Self::NoSuchInstance => 1,
                    Self::EndOfMibView => 2,
                    _ => unreachable!(),
                };
                Ok(vec![ASN1Block::Unknown(ASN1Class::ContextSpecific, true, 0, BigUint::from(tag), Vec::new())])
            },
        }
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
    #[must_use]
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
    #[must_use]
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::Counter32(i) |
            Self::Unsigned32(i) |
            Self::TimeTicks(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns [`Some(u64)`] if this `ObjectValue` is a [`Counter32`][ObjectValue::Counter32],
    /// [`Unsigned32`][ObjectValue::Unsigned32], [`TimeTicks`][ObjectValue::TimeTicks], or
    /// [`Counter64`][ObjectValue::Counter64]; otherwise, returns [`None`].
    #[allow(dead_code)]
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Counter32(i) |
            Self::Unsigned32(i) |
            Self::TimeTicks(i) => Some((*i).into()),
            Self::Counter64(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns [`Some(&Vec<u8>)`] if this `ObjectValue` is a [`String`][ObjectValue::String] or
    /// [`Opaque`][ObjectValue::Opaque]; otherwise, returns [`None`].
    #[allow(dead_code)]
    #[must_use]
    pub fn as_bytes(&self) -> Option<&Vec<u8>> {
        match self {
            Self::String(s) => Some(s),
            Self::Opaque(o) => Some(o),
            _ => None,
        }
    }

    /// Returns [`Some(ObjectIdentifier)`] if this `ObjectValue` is an
    /// [`ObjectId`][ObjectValue::ObjectId]; otherwise, returns [`None`].
    #[must_use]
    pub fn as_oid(&self) -> Option<ObjectIdentifier> {
        match self {
            Self::ObjectId(o) => Some(*o),
            _ => None,
        }
    }

    /// Returns whether this `ObjectValue` is an [`Integer`][ObjectValue::Integer].
    #[allow(dead_code)]
    #[must_use]
    pub fn is_integer(&self) -> bool { matches!(self, Self::Integer(_)) }

    /// Returns whether this `ObjectValue` is a [`String`][ObjectValue::String].
    #[allow(dead_code)]
    #[must_use]pub fn is_string(&self) -> bool { matches!(self, Self::String(_)) }

    /// Returns whether this `ObjectValue` is an [`ObjectId`][ObjectValue::ObjectId].
    #[allow(dead_code)]
    #[must_use]
    pub fn is_object_id(&self) -> bool { matches!(self, Self::ObjectId(_)) }

    /// Returns whether this `ObjectValue` is an [`IpAddress`][ObjectValue::IpAddress].
    #[allow(dead_code)]
    #[must_use]
    pub fn is_ip_address(&self) -> bool { matches!(self, Self::IpAddress(_)) }

    /// Returns whether this `ObjectValue` is a [`Counter32`][ObjectValue::Counter32].
    #[allow(dead_code)]
    #[must_use]
    pub fn is_counter32(&self) -> bool { matches!(self, Self::Counter32(_)) }

    /// Returns whether this `ObjectValue` is an [`Unsigned32`][ObjectValue::Unsigned32].
    #[allow(dead_code)]
    #[must_use]
    pub fn is_unsigned32(&self) -> bool { matches!(self, Self::Unsigned32(_)) }

    /// Returns whether this `ObjectValue` is a [`TimeTicks`][ObjectValue::TimeTicks].
    #[allow(dead_code)]
    #[must_use]
    pub fn is_time_ticks(&self) -> bool { matches!(self, Self::TimeTicks(_)) }

    /// Returns whether this `ObjectValue` is an [`Opaque`][ObjectValue::Opaque].
    #[allow(dead_code)]
    #[must_use]
    pub fn is_opaque(&self) -> bool { matches!(self, Self::Opaque(_)) }

    /// Returns whether this `ObjectValue` is a [`Counter64`][ObjectValue::Counter64].
    #[allow(dead_code)]
    #[must_use]
    pub fn is_counter64(&self) -> bool { matches!(self, Self::Counter64(_)) }

    /// Returns the string representation of this `ObjectValue`'s type.
    #[allow(dead_code)]
    #[must_use]
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
impl FromASN1 for ObjectValue {
    type Error = SnmpMessageError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        SnmpMessageError::check_min_length(v, 1)?;

        let obj_value = match &v[0] {
            ASN1Block::Integer(_offset, num) => {
                let int_val: i32 = num.try_into()
                    .map_err(|_| SnmpMessageError::IntegerPrimitiveRange {
                        primitive_type: "i32",
                        obtained: v[0].clone(),
                    })?;
                Self::Integer(int_val)
            },
            ASN1Block::OctetString(_offset, bytes) => Self::String(bytes.clone()),
            ASN1Block::ObjectIdentifier(_offset, oid) => {
                let snmp_oid: ObjectIdentifier = oid.try_into()
                    .map_err(|error| SnmpMessageError::OidDecode {
                        oid: oid.clone(),
                        error,
                    })?;
                Self::ObjectId(snmp_oid)
            },

            ASN1Block::Unknown(cls, _constructed, _offset, tag, content_bytes) => {
                SnmpMessageError::check_tag_class(*cls, ASN1Class::Application)?;

                if tag == &BigUint::from(0u8) {
                    // IP address
                    if content_bytes.len() != 4 {
                        return Err(SnmpMessageError::Length {
                            expected: 4,
                            obtained: content_bytes.len(),
                        });
                    }
                    let bs_array: [u8; 4] = content_bytes.clone().try_into().unwrap();
                    let addr = Ipv4Addr::from(bs_array);
                    Self::IpAddress(addr)
                } else if tag >= &BigUint::from(1u8) && tag <= &BigUint::from(3u8) {
                    // 1 = Counter32, 2 = Gauge32/Unsigned32, 3 = TimeTicks
                    let mut val_u32 = 0u32;
                    for b in content_bytes {
                        let b_u32: u32 = (*b).into();
                        val_u32 = (val_u32 << 8) | b_u32;
                    }

                    if tag == &BigUint::from(1u8) {
                        Self::Counter32(val_u32)
                    } else if tag == &BigUint::from(2u8) {
                        Self::Unsigned32(val_u32)
                    } else if tag == &BigUint::from(3u8) {
                        Self::TimeTicks(val_u32)
                    } else {
                        unreachable!();
                    }
                } else if tag == &BigUint::from(4u8) {
                    // Opaque
                    Self::Opaque(content_bytes.clone())
                // 5 is unspecified
                } else if tag == &BigUint::from(6u8) {
                    // Counter64
                    let mut val_u64 = 0u64;
                    for b in content_bytes {
                        let b_u64: u64 = (*b).into();
                        val_u64 = (val_u64 << 8) | b_u64;
                    }
                    Self::Counter64(val_u64)
                } else {
                    return Err(SnmpMessageError::EnumRange {
                        enum_name: "ObjectValue",
                        obtained: v[0].clone(),
                    });
                }
            },

            other => {
                return Err(SnmpMessageError::UnexpectedType {
                    expected: ExpectedAsn1Type::AnySnmpValueType,
                    obtained: other.clone(),
                });
            },
        };

        Ok((obj_value, &v[1..]))
    }
}
impl ToASN1 for ObjectValue {
    type Error = SnmpMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let mut ret = Vec::with_capacity(1);

        match self {
            Self::Integer(i) => ret.push(ASN1Block::from_i32(*i)),
            Self::String(bs) => ret.push(ASN1Block::OctetString(0, bs.clone())),
            Self::ObjectId(oid) => {
                let oid_val: OID = oid.try_into()
                    .map_err(|error| SnmpMessageError::OidEncode {
                        oid: *oid,
                        error,
                    })?;
                ret.push(ASN1Block::ObjectIdentifier(0, oid_val));
            },

            Self::IpAddress(addr) => ret.push(ASN1Block::Unknown(ASN1Class::Application, false, 0,
                BigUint::from(0u8),
                Vec::from(&addr.octets()[..]),
            )),
            Self::Counter32(i) => ret.push(ASN1Block::Unknown(ASN1Class::Application, false, 0,
                BigUint::from(1u8),
                BigInt::from(*i).to_signed_bytes_be(),
            )),
            Self::Unsigned32(i) => ret.push(ASN1Block::Unknown(ASN1Class::Application, false, 0,
                BigUint::from(2u8),
                BigInt::from(BigUint::from(*i)).to_signed_bytes_be(),
            )),
            Self::TimeTicks(i) => ret.push(ASN1Block::Unknown(ASN1Class::Application, false, 0,
                BigUint::from(3u8),
                BigInt::from(BigUint::from(*i)).to_signed_bytes_be(),
            )),
            Self::Opaque(bs) => ret.push(ASN1Block::Unknown(ASN1Class::Application, false, 0,
                BigUint::from(4u8),
                bs.clone(),
            )),
            Self::Counter64(i) => ret.push(ASN1Block::Unknown(ASN1Class::Application, false, 0,
                BigUint::from(6u8),
                BigInt::from(BigUint::from(*i)).to_signed_bytes_be(),
            )),
        }

        Ok(ret)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use simple_asn1::{der_decode, der_encode};

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
    fn test_decode1() {
        #[rustfmt::skip]
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

        let asn1: Snmp2cMessage = der_decode(&bytes).unwrap();
        assert_eq!(asn1.version, 1);
        assert_eq!(asn1.community, b"Fqate");

        let Snmp2cPdu::Response(inner_pdu) = asn1.pdu else {
            panic!();
        };
        assert_eq!(inner_pdu.request_id, 649_110_371);
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
                request_id: 649_110_371,
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
        let bytes = der_encode(&message).unwrap();

        #[rustfmt::skip]
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
        #[rustfmt::skip]
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

        let asn1: Snmp2cMessage = der_decode(&bytes).unwrap();
        assert_eq!(asn1.version, 1);
        assert_eq!(asn1.community, b"9v79I");

        let Snmp2cPdu::Response(inner_pdu) = asn1.pdu  else {
            panic!();
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
        assert_eq!(gimme_time(&inner_pdu.variable_bindings[2]), 2_582_027_205);
        assert_eq!(inner_pdu.variable_bindings[3].name, "1.3.6.1.2.1.1.4.0".parse().unwrap());
        assert_eq!(gimme_octets(&inner_pdu.variable_bindings[3]), b"KOM");
        assert_eq!(inner_pdu.variable_bindings[4].name, "1.3.6.1.2.1.1.5.0".parse().unwrap());
        assert_eq!(gimme_octets(&inner_pdu.variable_bindings[4]), b"sw-d-sn1");
        assert_eq!(inner_pdu.variable_bindings[5].name, "1.3.6.1.2.1.1.6.0".parse().unwrap());
        assert_eq!(gimme_octets(&inner_pdu.variable_bindings[5]), b"DC02M02");
        assert_eq!(inner_pdu.variable_bindings[6].name, "1.3.6.1.2.1.1.7.0".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[6]), 70);
        assert_eq!(inner_pdu.variable_bindings[7].name, "1.3.6.1.2.1.1.8.0".parse().unwrap());
        assert_eq!(gimme_time(&inner_pdu.variable_bindings[7]), 4_294_967_166);
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
                        value: BindingValue::Value(ObjectValue::TimeTicks(2_582_027_205)),
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
                        value: BindingValue::Value(ObjectValue::TimeTicks(4_294_967_166)),
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
        let bytes = der_encode(&message).unwrap();

        #[rustfmt::skip]
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
        #[rustfmt::skip]
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

        let asn1: Snmp2cMessage = der_decode(&bytes).unwrap();
        assert_eq!(asn1.version, 1);
        assert_eq!(asn1.community, b"readonly");

        let Snmp2cPdu::Response(inner_pdu) = asn1.pdu else {
            panic!();
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
        assert_eq!(gimme_counter(&inner_pdu.variable_bindings[5]), 0xFEFE_FEFE);
        assert_eq!(inner_pdu.variable_bindings[6].name, "1.3.6.1.4.1.34195.1.99999.69.7.0".parse().unwrap());
        assert_eq!(gimme_unsigned(&inner_pdu.variable_bindings[6]), 0xDEAD_BEEF);
        assert_eq!(inner_pdu.variable_bindings[7].name, "1.3.6.1.4.1.34195.1.99999.69.8.0".parse().unwrap());
        assert_eq!(gimme_time(&inner_pdu.variable_bindings[7]), 0xA55F_ACE5);
        assert_eq!(inner_pdu.variable_bindings[8].name, "1.3.6.1.4.1.34195.1.99999.69.9.0".parse().unwrap());
        assert_eq!(gimme_counter64(&inner_pdu.variable_bindings[8]), 0xDEAD_BEEF_A55F_ACE5);
        assert_eq!(inner_pdu.variable_bindings[9].name, "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap());
        assert_eq!(gimme_int(&inner_pdu.variable_bindings[9]), 605_554_450);
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
                        value: BindingValue::Value(ObjectValue::Counter32(0xFEFE_FEFE)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.7.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Unsigned32(0xDEAD_BEEF)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.8.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::TimeTicks(0xA55F_ACE5)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.4.1.34195.1.99999.69.9.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Counter64(0xDEAD_BEEF_A55F_ACE5)),
                    },
                    VariableBinding {
                        name: "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap(),
                        value: BindingValue::Value(ObjectValue::Integer(605_554_450)),
                    },
                ],
            }),
        };
        let bytes = der_encode(&message).unwrap();

        #[rustfmt::skip]
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
