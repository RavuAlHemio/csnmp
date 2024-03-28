//! Information collection using SNMP2c.
//!
//! SNMP2c is the Simple Network Management Protocol version 2 with authentication using community
//! strings. This implementation assumes UDP as the transport protocol.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

use simple_asn1::{BigUint, OID};


/// The maximum number of sub-identifiers (numbers) in an object identifier.
///
/// See RFC3416, section 4.1.
pub const MAX_SUB_IDENTIFIER_COUNT: usize = 128;


/// The minimum number of sub-identifiers (numbers) in an absolute object identifier.
///
/// X.680 section 32.11 notes that X.660 requires that an object identifier value contain at least
/// two arcs; this requirement does not appear to be stated explicitly in X.660.
pub const ABS_MIN_SUB_IDENTIFIER_COUNT: usize = 2;


/// An error that can occur when converting from a slice of 32-bit unsigned integers into an
/// [`ObjectIdentifier`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ObjectIdentifierConversionError {
    /// The slice is too long.
    ///
    /// `max` contains the maximum number of sub-identifiers; `obtained` the number of
    /// sub-identifiers in the slice. The maximum number of sub-identifiers in an SNMP object
    /// identifier can be read from [`MAX_SUB_IDENTIFIER_COUNT`].
    TooLong { max: usize, obtained: usize },

    /// The value of one of the entries is out of range.
    ///
    /// `index` contains the index of the out-of-range value. The range of sub-identifiers in an
    /// SNMP object identifier is equal to the range of `u32`.
    ValueRange { index: usize },

    /// The object identifier is used in a context where absolute object identifiers are required
    /// and it has fewer than the required number of sub-identifiers. The minimum number of
    /// sub-identifiers in an absolute object identifier can be read from
    /// [`ABS_MIN_SUB_IDENTIFIER_COUNT`].
    TooShort { length: usize },

    /// The sub-identifier at the given index is invalid.
    InvalidSubIdString { index: usize },
}
impl fmt::Display for ObjectIdentifierConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { obtained, max }
                => write!(f, "slice has length {}, maximum is {}", obtained, max),
            Self::ValueRange { index }
                => write!(f, "value at index {} is out of range", index),
            Self::TooShort { length }
                => write!(f, "need more than {} elements", length),
            Self::InvalidSubIdString { index }
                => write!(f, "invalid sub-identifier at index {}", index),
        }
    }
}
impl Error for ObjectIdentifierConversionError {
}


/// An SNMP object identifier.
///
/// Equivalent to an ASN.1 object identifier, except limited to maximum [`MAX_SUB_IDENTIFIER_COUNT`]
/// sub-identifiers of a value of up to 2**32-1.
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct ObjectIdentifier {
    length: usize,
    sub_identifiers: [u32; MAX_SUB_IDENTIFIER_COUNT],
}
impl ObjectIdentifier {
    /// Makes a new object identifier.
    ///
    /// `sub_identifiers` elements at index >= `length` must all be 0. Panics if this is not the
    /// case.
    ///
    /// You probably want to use the functions of the `TryFrom<&[u32]>` implementation instead.
    pub const fn new(length: usize, sub_identifiers: [u32; MAX_SUB_IDENTIFIER_COUNT]) -> Self {
        let mut i = length;
        while i < MAX_SUB_IDENTIFIER_COUNT {
            if sub_identifiers[i] != 0 {
                panic!("all sub identifiers beyond length must be 0");
            }
            i += 1;
        };

        Self {
            length,
            sub_identifiers,
        }
    }

    /// Returns the length of this object identifier. Guaranteed to be at least 0 and less than
    /// [`MAX_SUB_IDENTIFIER_COUNT`].
    pub fn len(&self) -> usize {
        self.length
    }

    /// Obtains the sub-identifier at the given index, or `None` if the index is out of bounds.
    pub fn get(&self, index: usize) -> Option<u32> {
        if index < self.length {
            Some(self.sub_identifiers[index])
        } else {
            None
        }
    }

    /// Returns this object identifier als a slice of unsigned 32-bit integers.
    pub fn as_slice(&self) -> &[u32] {
        &self.sub_identifiers[0..self.length]
    }

    /// Returns the parent of this object identifier, or `None` if it has no parent.
    pub fn parent(&self) -> Option<Self> {
        if self.length == 0 {
            None
        } else {
            self.sub_identifiers[0..self.length-1]
                .try_into()
                .ok()
        }
    }

    /// Returns a child of this object identifier constructed by appending the given `sub_id`,
    /// or `None` if that would create an object identifier that is too long.
    pub fn child(&self, sub_id: u32) -> Option<Self> {
        if self.length == MAX_SUB_IDENTIFIER_COUNT {
            None
        } else {
            let mut sub_identifiers = self.sub_identifiers.clone();
            sub_identifiers[self.length] = sub_id;
            Some(Self {
                length: self.length + 1,
                sub_identifiers,
            })
        }
    }

    /// If `prefix` is a prefix of or equal to this OID, returns a slice containing the
    /// sub-identifiers following this prefix; otherwise, returns `None`.
    fn tail_slice(&self, prefix: &Self) -> Option<&[u32]> {
        self.as_slice().strip_prefix(prefix.as_slice())
    }

    /// Returns whether this object identifier is a prefix of another object identifier or equal to
    /// it.
    pub fn is_prefix_of_or_equal(&self, other: &Self) -> bool {
        other.as_slice().starts_with(self.as_slice())
    }

    /// Returns whether this object identifier is a prefix of another object identifier. Returns
    /// `false` if the object identifiers are equal.
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        self.len() < other.len() && other.as_slice().starts_with(self.as_slice())
    }

    /// Returns this object identifier relative to the given `base` object identifier. Returns
    /// `None` if `base` is not a prefix of or equal to this object identifier.
    pub fn relative_to(&self, base: &Self) -> Option<Self> {
        self.tail_slice(base)
            .map(|ts| Self::try_from(ts).unwrap())
    }
}
impl Default for ObjectIdentifier {
    fn default() -> Self {
        Self { length: 0, sub_identifiers: [0u32; 128] }
    }
}
impl fmt::Debug for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectIdentifier({})", self)
    }
}
impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in 0..self.length {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", self.sub_identifiers[i])?;
        }
        Ok(())
    }
}
impl PartialOrd for ObjectIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ObjectIdentifier {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sub_identifiers[..self.length].cmp(&other.sub_identifiers[..other.length])
    }
}
impl FromStr for ObjectIdentifier {
    type Err = ObjectIdentifierConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // strip leading and trailing dots
        let stripped_start = s.strip_prefix('.').unwrap_or(s);
        let stripped = stripped_start.strip_suffix('.').unwrap_or(stripped_start);

        // split on dots
        let pieces: Vec<&str> = if stripped.len() > 0 {
            stripped.split(".").collect()
        } else {
            Vec::new()
        };
        if pieces.len() > MAX_SUB_IDENTIFIER_COUNT {
            return Err(ObjectIdentifierConversionError::TooLong {
                max: MAX_SUB_IDENTIFIER_COUNT,
                obtained: pieces.len(),
            });
        }

        let mut sub_identifiers = [0u32; MAX_SUB_IDENTIFIER_COUNT];
        if stripped.len() > 0 {
            for (index, piece) in pieces.iter().enumerate() {
                sub_identifiers[index] = piece.parse()
                    .map_err(|_| ObjectIdentifierConversionError::InvalidSubIdString {
                        index,
                    })?;
            }
        }

        Ok(Self {
            length: pieces.len(),
            sub_identifiers,
        })
    }
}
impl TryFrom<&[u32]> for ObjectIdentifier {
    type Error = ObjectIdentifierConversionError;

    fn try_from(value: &[u32]) -> Result<Self, Self::Error> {
        if value.len() > MAX_SUB_IDENTIFIER_COUNT {
            return Err(ObjectIdentifierConversionError::TooLong {
                max: MAX_SUB_IDENTIFIER_COUNT,
                obtained: value.len(),
            });
        }
        let mut sub_identifiers = [0u32; MAX_SUB_IDENTIFIER_COUNT];
        for i in 0..value.len() {
            sub_identifiers[i] = value[i];
        }
        Ok(Self {
            length: value.len(),
            sub_identifiers,
        })
    }
}
impl TryFrom<&OID> for ObjectIdentifier {
    type Error = ObjectIdentifierConversionError;

    fn try_from(value: &OID) -> Result<Self, Self::Error> {
        let vec: Vec<&BigUint> = value.as_vec().unwrap();
        let mut sub_identifiers = [0u32; MAX_SUB_IDENTIFIER_COUNT];

        for (index, val) in vec.iter().enumerate() {
            let val_u32 = (*val).try_into()
                .map_err(|_| ObjectIdentifierConversionError::ValueRange { index })?;
            sub_identifiers[index] = val_u32;
        }

        Ok(Self {
            length: vec.len(),
            sub_identifiers,
        })
    }
}
impl TryFrom<&ObjectIdentifier> for OID {
    type Error = ObjectIdentifierConversionError;

    fn try_from(value: &ObjectIdentifier) -> Result<Self, Self::Error> {
        if value.len() < ABS_MIN_SUB_IDENTIFIER_COUNT {
            return Err(ObjectIdentifierConversionError::TooShort {
                length: value.len(),
            });
        }
        Ok(OID::new(
            value.as_slice()
                .iter()
                .map(|&i| BigUint::from(i))
                .collect()
        ))
    }
}


/// The zero-zero OID (0.0), indicating the absence of an OID.
pub const ZERO_ZERO_OID: ObjectIdentifier = ObjectIdentifier::new(2, [0; MAX_SUB_IDENTIFIER_COUNT]);


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_from_slice() {
        fn tfs(slice: &[u32]) {
            assert_eq!(slice, ObjectIdentifier::try_from(slice).unwrap().as_slice());
        }
        fn tfs_err(slice: &[u32]) {
            assert!(ObjectIdentifier::try_from(slice).is_err());
        }

        tfs(&[]);
        tfs(&[1, 3, 6, 1, 4, 1]);
        tfs(&[1; 128]);

        tfs_err(&[1; 129]);
    }

    #[test]
    fn test_ops() {
        let base = ObjectIdentifier::try_from(&[1, 3, 6, 1, 4, 1][..]).unwrap();
        assert_eq!(&[1, 3, 6, 1, 4], base.parent().unwrap().as_slice());
        assert_eq!(&[1, 3, 6, 1, 4, 1, 1], base.child(1).unwrap().as_slice());

        let top = ObjectIdentifier::try_from(&[][..]).unwrap();
        assert_eq!(None, top.parent());

        let long = ObjectIdentifier::try_from(&[1; 128][..]).unwrap();
        assert_eq!(None, long.child(2));
    }

    #[test]
    fn test_tail_slice() {
        let empty = ObjectIdentifier::try_from(&[][..]).unwrap();
        let base = ObjectIdentifier::try_from(&[1, 3, 6, 1, 4, 1][..]).unwrap();
        let child = ObjectIdentifier::try_from(&[1, 3, 6, 1, 4, 1, 1][..]).unwrap();
        let descendant = ObjectIdentifier::try_from(&[1, 3, 6, 1, 4, 1, 1, 2, 3, 4, 5][..]).unwrap();
        let different = ObjectIdentifier::try_from(&[3, 2, 1][..]).unwrap();
        let half_different = ObjectIdentifier::try_from(&[1, 3, 4][..]).unwrap();

        // Other is not a prefix. Return None.
        assert_eq!(base.tail_slice(&child), None);
        assert_eq!(base.tail_slice(&descendant), None);
        assert_eq!(base.tail_slice(&different), None);
        assert_eq!(base.tail_slice(&half_different), None);
        assert_eq!(empty.tail_slice(&base), None);
        // Other is empty. Returns self.
        assert_eq!(base.tail_slice(&empty), Some(base.as_slice()));
        assert_eq!(empty.tail_slice(&empty), Some(empty.as_slice()));
        // Other is a prefix. Return tail.
        assert_eq!(child.tail_slice(&base), Some(&[1][..]));
        assert_eq!(descendant.tail_slice(&base), Some(&[1, 2, 3, 4, 5][..]));
    }

    #[test]
    fn test_prefix() {
        let base = ObjectIdentifier::try_from(&[1, 3, 6, 1, 4, 1][..]).unwrap();
        let child = ObjectIdentifier::try_from(&[1, 3, 6, 1, 4, 1, 1][..]).unwrap();
        let descendant = ObjectIdentifier::try_from(&[1, 3, 6, 1, 4, 1, 1, 2, 3, 4, 5][..]).unwrap();
        let different = ObjectIdentifier::try_from(&[3, 2, 1][..]).unwrap();
        let half_different = ObjectIdentifier::try_from(&[1, 3, 4][..]).unwrap();

        assert!(base.is_prefix_of_or_equal(&base));
        assert!(base.is_prefix_of_or_equal(&child));
        assert!(base.is_prefix_of_or_equal(&descendant));
        assert!(!base.is_prefix_of_or_equal(&different));
        assert!(!base.is_prefix_of_or_equal(&half_different));

        assert!(!base.is_prefix_of(&base));
        assert!(base.is_prefix_of(&child));
        assert!(base.is_prefix_of(&descendant));
        assert!(!base.is_prefix_of(&different));
        assert!(!base.is_prefix_of(&half_different));

        assert_eq!(&[] as &[u32], base.relative_to(&base).unwrap().as_slice());
        assert_eq!(&[1], child.relative_to(&base).unwrap().as_slice());
        assert_eq!(&[1, 2, 3, 4, 5], descendant.relative_to(&base).unwrap().as_slice());
        assert_eq!(None, different.relative_to(&base));
        assert_eq!(None, half_different.relative_to(&base));
    }

    #[test]
    fn test_to_string() {
        fn tts(slice: &[u32], string: &str) {
            assert_eq!(ObjectIdentifier::try_from(slice).unwrap().to_string(), string);
        }

        tts(&[], "");
        tts(&[1], "1");
        tts(&[1, 3, 6, 1, 4, 1], "1.3.6.1.4.1");
        tts(&[1, 3, 6, 1, 4, 1, 1], "1.3.6.1.4.1.1");
        tts(&[1, 3, 6, 1, 4, 1, 1, 2, 3, 4, 5], "1.3.6.1.4.1.1.2.3.4.5");
        tts(&[3, 2, 1], "3.2.1");
        tts(&[1, 3, 4], "1.3.4");
        tts(&[1, 3, 4, 4294967295, 1], "1.3.4.4294967295.1");
    }

    #[test]
    fn test_parse() {
        fn tfs(slice: &[u32], string: &str) {
            let parsed: ObjectIdentifier = string.parse().unwrap();
            assert_eq!(parsed.as_slice(), slice, "when parsing \"{string}\"");
        }

        tfs(&[], "");
        tfs(&[], ".");
        tfs(&[], "..");
        tfs(&[1], "1");
        tfs(&[1], ".1.");
        tfs(&[1, 3, 6, 1, 4, 1], "1.3.6.1.4.1");
        tfs(&[1, 3, 4, 4294967295, 1], "1.3.4.4294967295.1");
        let max_length = ".1".repeat(MAX_SUB_IDENTIFIER_COUNT);
        tfs([1u32; MAX_SUB_IDENTIFIER_COUNT].as_slice(), &max_length);

        use ObjectIdentifierConversionError as OICE;
        fn tfs_err(err: OICE, string: &str) {
            let parsed = string.parse::<ObjectIdentifier>();
            assert_eq!(parsed, Err(err), "when parsing \"{string}\"");
        }

        tfs_err(OICE::InvalidSubIdString { index: 0 }, "...");
        tfs_err(OICE::InvalidSubIdString { index: 0 }, "..1.");
        tfs_err(OICE::InvalidSubIdString { index: 1 }, "1..2");
        tfs_err(OICE::InvalidSubIdString { index: 0 }, "4294967296");
        tfs_err(OICE::InvalidSubIdString { index: 0 }, ".4294967296.");
        let one_too_long = ".1".repeat(MAX_SUB_IDENTIFIER_COUNT + 1);
        tfs_err(
            OICE::TooLong {
                max: MAX_SUB_IDENTIFIER_COUNT,
                obtained: MAX_SUB_IDENTIFIER_COUNT + 1,
            },
            &one_too_long,
        );
        let way_too_long = ".1".repeat(MAX_SUB_IDENTIFIER_COUNT * 2);
        tfs_err(
            OICE::TooLong {
                max: MAX_SUB_IDENTIFIER_COUNT,
                obtained: MAX_SUB_IDENTIFIER_COUNT * 2,
            },
            &way_too_long,
        );
    }

    #[test]
    fn test_cmp() {
        let oid_empty = ObjectIdentifier::from_str("").unwrap();
        let oid23 = ObjectIdentifier::from_str("2.3").unwrap();
        let oid310 = ObjectIdentifier::from_str("3.1.0").unwrap();
        let oid32 = ObjectIdentifier::from_str("3.2").unwrap();
        let oid320 = ObjectIdentifier::from_str("3.2.0").unwrap();
        let oid_max_long = ObjectIdentifier::new(
            MAX_SUB_IDENTIFIER_COUNT,
            [u32::MAX; MAX_SUB_IDENTIFIER_COUNT],
        );

        // Different common prefix, different length
        assert_eq!(oid32.cmp(&oid310), Ordering::Greater);
        assert_eq!(oid310.cmp(&oid32), Ordering::Less);
        // Different common prefix, same length
        assert_eq!(oid32.cmp(&oid23), Ordering::Greater);
        assert_eq!(oid23.cmp(&oid32), Ordering::Less);
        // Same common prefix, different length
        assert_eq!(oid320.cmp(&oid32), Ordering::Greater);
        assert_eq!(oid32.cmp(&oid320), Ordering::Less);
        // Same common prefix, same length (a.k.a. equal)
        assert_eq!(oid_empty.cmp(&oid_empty), Ordering::Equal);
        assert_eq!(oid310.cmp(&oid310), Ordering::Equal);
        assert_eq!(oid_max_long.cmp(&oid_max_long), Ordering::Equal);
    }
}
