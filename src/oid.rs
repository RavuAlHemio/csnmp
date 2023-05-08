//! Information collection using SNMP2c.
//!
//! SNMP2c is the Simple Network Management Protocol version 2 with authentication using community
//! strings. This implementation assumes UDP as the transport protocol.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::str::FromStr;


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
        // FIXME: turn all this into a loop once those are supported in const functions
        if MAX_SUB_IDENTIFIER_COUNT != 128 {
            panic!("MAX_SUB_IDENTIFIER_COUNT has changed!");
        }
        if length <= 0 && sub_identifiers[0] != 0 { panic!("item at index 0 is beyond length but not 0"); }
        if length <= 1 && sub_identifiers[1] != 0 { panic!("item at index 1 is beyond length but not 0"); }
        if length <= 2 && sub_identifiers[2] != 0 { panic!("item at index 2 is beyond length but not 0"); }
        if length <= 3 && sub_identifiers[3] != 0 { panic!("item at index 3 is beyond length but not 0"); }
        if length <= 4 && sub_identifiers[4] != 0 { panic!("item at index 4 is beyond length but not 0"); }
        if length <= 5 && sub_identifiers[5] != 0 { panic!("item at index 5 is beyond length but not 0"); }
        if length <= 6 && sub_identifiers[6] != 0 { panic!("item at index 6 is beyond length but not 0"); }
        if length <= 7 && sub_identifiers[7] != 0 { panic!("item at index 7 is beyond length but not 0"); }
        if length <= 8 && sub_identifiers[8] != 0 { panic!("item at index 8 is beyond length but not 0"); }
        if length <= 9 && sub_identifiers[9] != 0 { panic!("item at index 9 is beyond length but not 0"); }
        if length <= 10 && sub_identifiers[10] != 0 { panic!("item at index 10 is beyond length but not 0"); }
        if length <= 11 && sub_identifiers[11] != 0 { panic!("item at index 11 is beyond length but not 0"); }
        if length <= 12 && sub_identifiers[12] != 0 { panic!("item at index 12 is beyond length but not 0"); }
        if length <= 13 && sub_identifiers[13] != 0 { panic!("item at index 13 is beyond length but not 0"); }
        if length <= 14 && sub_identifiers[14] != 0 { panic!("item at index 14 is beyond length but not 0"); }
        if length <= 15 && sub_identifiers[15] != 0 { panic!("item at index 15 is beyond length but not 0"); }
        if length <= 16 && sub_identifiers[16] != 0 { panic!("item at index 16 is beyond length but not 0"); }
        if length <= 17 && sub_identifiers[17] != 0 { panic!("item at index 17 is beyond length but not 0"); }
        if length <= 18 && sub_identifiers[18] != 0 { panic!("item at index 18 is beyond length but not 0"); }
        if length <= 19 && sub_identifiers[19] != 0 { panic!("item at index 19 is beyond length but not 0"); }
        if length <= 20 && sub_identifiers[20] != 0 { panic!("item at index 20 is beyond length but not 0"); }
        if length <= 21 && sub_identifiers[21] != 0 { panic!("item at index 21 is beyond length but not 0"); }
        if length <= 22 && sub_identifiers[22] != 0 { panic!("item at index 22 is beyond length but not 0"); }
        if length <= 23 && sub_identifiers[23] != 0 { panic!("item at index 23 is beyond length but not 0"); }
        if length <= 24 && sub_identifiers[24] != 0 { panic!("item at index 24 is beyond length but not 0"); }
        if length <= 25 && sub_identifiers[25] != 0 { panic!("item at index 25 is beyond length but not 0"); }
        if length <= 26 && sub_identifiers[26] != 0 { panic!("item at index 26 is beyond length but not 0"); }
        if length <= 27 && sub_identifiers[27] != 0 { panic!("item at index 27 is beyond length but not 0"); }
        if length <= 28 && sub_identifiers[28] != 0 { panic!("item at index 28 is beyond length but not 0"); }
        if length <= 29 && sub_identifiers[29] != 0 { panic!("item at index 29 is beyond length but not 0"); }
        if length <= 30 && sub_identifiers[30] != 0 { panic!("item at index 30 is beyond length but not 0"); }
        if length <= 31 && sub_identifiers[31] != 0 { panic!("item at index 31 is beyond length but not 0"); }
        if length <= 32 && sub_identifiers[32] != 0 { panic!("item at index 32 is beyond length but not 0"); }
        if length <= 33 && sub_identifiers[33] != 0 { panic!("item at index 33 is beyond length but not 0"); }
        if length <= 34 && sub_identifiers[34] != 0 { panic!("item at index 34 is beyond length but not 0"); }
        if length <= 35 && sub_identifiers[35] != 0 { panic!("item at index 35 is beyond length but not 0"); }
        if length <= 36 && sub_identifiers[36] != 0 { panic!("item at index 36 is beyond length but not 0"); }
        if length <= 37 && sub_identifiers[37] != 0 { panic!("item at index 37 is beyond length but not 0"); }
        if length <= 38 && sub_identifiers[38] != 0 { panic!("item at index 38 is beyond length but not 0"); }
        if length <= 39 && sub_identifiers[39] != 0 { panic!("item at index 39 is beyond length but not 0"); }
        if length <= 40 && sub_identifiers[40] != 0 { panic!("item at index 40 is beyond length but not 0"); }
        if length <= 41 && sub_identifiers[41] != 0 { panic!("item at index 41 is beyond length but not 0"); }
        if length <= 42 && sub_identifiers[42] != 0 { panic!("item at index 42 is beyond length but not 0"); }
        if length <= 43 && sub_identifiers[43] != 0 { panic!("item at index 43 is beyond length but not 0"); }
        if length <= 44 && sub_identifiers[44] != 0 { panic!("item at index 44 is beyond length but not 0"); }
        if length <= 45 && sub_identifiers[45] != 0 { panic!("item at index 45 is beyond length but not 0"); }
        if length <= 46 && sub_identifiers[46] != 0 { panic!("item at index 46 is beyond length but not 0"); }
        if length <= 47 && sub_identifiers[47] != 0 { panic!("item at index 47 is beyond length but not 0"); }
        if length <= 48 && sub_identifiers[48] != 0 { panic!("item at index 48 is beyond length but not 0"); }
        if length <= 49 && sub_identifiers[49] != 0 { panic!("item at index 49 is beyond length but not 0"); }
        if length <= 50 && sub_identifiers[50] != 0 { panic!("item at index 50 is beyond length but not 0"); }
        if length <= 51 && sub_identifiers[51] != 0 { panic!("item at index 51 is beyond length but not 0"); }
        if length <= 52 && sub_identifiers[52] != 0 { panic!("item at index 52 is beyond length but not 0"); }
        if length <= 53 && sub_identifiers[53] != 0 { panic!("item at index 53 is beyond length but not 0"); }
        if length <= 54 && sub_identifiers[54] != 0 { panic!("item at index 54 is beyond length but not 0"); }
        if length <= 55 && sub_identifiers[55] != 0 { panic!("item at index 55 is beyond length but not 0"); }
        if length <= 56 && sub_identifiers[56] != 0 { panic!("item at index 56 is beyond length but not 0"); }
        if length <= 57 && sub_identifiers[57] != 0 { panic!("item at index 57 is beyond length but not 0"); }
        if length <= 58 && sub_identifiers[58] != 0 { panic!("item at index 58 is beyond length but not 0"); }
        if length <= 59 && sub_identifiers[59] != 0 { panic!("item at index 59 is beyond length but not 0"); }
        if length <= 60 && sub_identifiers[60] != 0 { panic!("item at index 60 is beyond length but not 0"); }
        if length <= 61 && sub_identifiers[61] != 0 { panic!("item at index 61 is beyond length but not 0"); }
        if length <= 62 && sub_identifiers[62] != 0 { panic!("item at index 62 is beyond length but not 0"); }
        if length <= 63 && sub_identifiers[63] != 0 { panic!("item at index 63 is beyond length but not 0"); }
        if length <= 64 && sub_identifiers[64] != 0 { panic!("item at index 64 is beyond length but not 0"); }
        if length <= 65 && sub_identifiers[65] != 0 { panic!("item at index 65 is beyond length but not 0"); }
        if length <= 66 && sub_identifiers[66] != 0 { panic!("item at index 66 is beyond length but not 0"); }
        if length <= 67 && sub_identifiers[67] != 0 { panic!("item at index 67 is beyond length but not 0"); }
        if length <= 68 && sub_identifiers[68] != 0 { panic!("item at index 68 is beyond length but not 0"); }
        if length <= 69 && sub_identifiers[69] != 0 { panic!("item at index 69 is beyond length but not 0"); }
        if length <= 70 && sub_identifiers[70] != 0 { panic!("item at index 70 is beyond length but not 0"); }
        if length <= 71 && sub_identifiers[71] != 0 { panic!("item at index 71 is beyond length but not 0"); }
        if length <= 72 && sub_identifiers[72] != 0 { panic!("item at index 72 is beyond length but not 0"); }
        if length <= 73 && sub_identifiers[73] != 0 { panic!("item at index 73 is beyond length but not 0"); }
        if length <= 74 && sub_identifiers[74] != 0 { panic!("item at index 74 is beyond length but not 0"); }
        if length <= 75 && sub_identifiers[75] != 0 { panic!("item at index 75 is beyond length but not 0"); }
        if length <= 76 && sub_identifiers[76] != 0 { panic!("item at index 76 is beyond length but not 0"); }
        if length <= 77 && sub_identifiers[77] != 0 { panic!("item at index 77 is beyond length but not 0"); }
        if length <= 78 && sub_identifiers[78] != 0 { panic!("item at index 78 is beyond length but not 0"); }
        if length <= 79 && sub_identifiers[79] != 0 { panic!("item at index 79 is beyond length but not 0"); }
        if length <= 80 && sub_identifiers[80] != 0 { panic!("item at index 80 is beyond length but not 0"); }
        if length <= 81 && sub_identifiers[81] != 0 { panic!("item at index 81 is beyond length but not 0"); }
        if length <= 82 && sub_identifiers[82] != 0 { panic!("item at index 82 is beyond length but not 0"); }
        if length <= 83 && sub_identifiers[83] != 0 { panic!("item at index 83 is beyond length but not 0"); }
        if length <= 84 && sub_identifiers[84] != 0 { panic!("item at index 84 is beyond length but not 0"); }
        if length <= 85 && sub_identifiers[85] != 0 { panic!("item at index 85 is beyond length but not 0"); }
        if length <= 86 && sub_identifiers[86] != 0 { panic!("item at index 86 is beyond length but not 0"); }
        if length <= 87 && sub_identifiers[87] != 0 { panic!("item at index 87 is beyond length but not 0"); }
        if length <= 88 && sub_identifiers[88] != 0 { panic!("item at index 88 is beyond length but not 0"); }
        if length <= 89 && sub_identifiers[89] != 0 { panic!("item at index 89 is beyond length but not 0"); }
        if length <= 90 && sub_identifiers[90] != 0 { panic!("item at index 90 is beyond length but not 0"); }
        if length <= 91 && sub_identifiers[91] != 0 { panic!("item at index 91 is beyond length but not 0"); }
        if length <= 92 && sub_identifiers[92] != 0 { panic!("item at index 92 is beyond length but not 0"); }
        if length <= 93 && sub_identifiers[93] != 0 { panic!("item at index 93 is beyond length but not 0"); }
        if length <= 94 && sub_identifiers[94] != 0 { panic!("item at index 94 is beyond length but not 0"); }
        if length <= 95 && sub_identifiers[95] != 0 { panic!("item at index 95 is beyond length but not 0"); }
        if length <= 96 && sub_identifiers[96] != 0 { panic!("item at index 96 is beyond length but not 0"); }
        if length <= 97 && sub_identifiers[97] != 0 { panic!("item at index 97 is beyond length but not 0"); }
        if length <= 98 && sub_identifiers[98] != 0 { panic!("item at index 98 is beyond length but not 0"); }
        if length <= 99 && sub_identifiers[99] != 0 { panic!("item at index 99 is beyond length but not 0"); }
        if length <= 100 && sub_identifiers[100] != 0 { panic!("item at index 100 is beyond length but not 0"); }
        if length <= 101 && sub_identifiers[101] != 0 { panic!("item at index 101 is beyond length but not 0"); }
        if length <= 102 && sub_identifiers[102] != 0 { panic!("item at index 102 is beyond length but not 0"); }
        if length <= 103 && sub_identifiers[103] != 0 { panic!("item at index 103 is beyond length but not 0"); }
        if length <= 104 && sub_identifiers[104] != 0 { panic!("item at index 104 is beyond length but not 0"); }
        if length <= 105 && sub_identifiers[105] != 0 { panic!("item at index 105 is beyond length but not 0"); }
        if length <= 106 && sub_identifiers[106] != 0 { panic!("item at index 106 is beyond length but not 0"); }
        if length <= 107 && sub_identifiers[107] != 0 { panic!("item at index 107 is beyond length but not 0"); }
        if length <= 108 && sub_identifiers[108] != 0 { panic!("item at index 108 is beyond length but not 0"); }
        if length <= 109 && sub_identifiers[109] != 0 { panic!("item at index 109 is beyond length but not 0"); }
        if length <= 110 && sub_identifiers[110] != 0 { panic!("item at index 110 is beyond length but not 0"); }
        if length <= 111 && sub_identifiers[111] != 0 { panic!("item at index 111 is beyond length but not 0"); }
        if length <= 112 && sub_identifiers[112] != 0 { panic!("item at index 112 is beyond length but not 0"); }
        if length <= 113 && sub_identifiers[113] != 0 { panic!("item at index 113 is beyond length but not 0"); }
        if length <= 114 && sub_identifiers[114] != 0 { panic!("item at index 114 is beyond length but not 0"); }
        if length <= 115 && sub_identifiers[115] != 0 { panic!("item at index 115 is beyond length but not 0"); }
        if length <= 116 && sub_identifiers[116] != 0 { panic!("item at index 116 is beyond length but not 0"); }
        if length <= 117 && sub_identifiers[117] != 0 { panic!("item at index 117 is beyond length but not 0"); }
        if length <= 118 && sub_identifiers[118] != 0 { panic!("item at index 118 is beyond length but not 0"); }
        if length <= 119 && sub_identifiers[119] != 0 { panic!("item at index 119 is beyond length but not 0"); }
        if length <= 120 && sub_identifiers[120] != 0 { panic!("item at index 120 is beyond length but not 0"); }
        if length <= 121 && sub_identifiers[121] != 0 { panic!("item at index 121 is beyond length but not 0"); }
        if length <= 122 && sub_identifiers[122] != 0 { panic!("item at index 122 is beyond length but not 0"); }
        if length <= 123 && sub_identifiers[123] != 0 { panic!("item at index 123 is beyond length but not 0"); }
        if length <= 124 && sub_identifiers[124] != 0 { panic!("item at index 124 is beyond length but not 0"); }
        if length <= 125 && sub_identifiers[125] != 0 { panic!("item at index 125 is beyond length but not 0"); }
        if length <= 126 && sub_identifiers[126] != 0 { panic!("item at index 126 is beyond length but not 0"); }
        if length <= 127 && sub_identifiers[127] != 0 { panic!("item at index 127 is beyond length but not 0"); }

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

    /// If `prefix` is a prefix of or equal to this OID, returns a slice containing the items
    /// following this prefix; otherwise, returns `None`.
    fn tail_slice(&self, prefix: &Self) -> Option<&[u32]> {
        if prefix.len() > self.len() {
            return None;
        }

        for i in 0..prefix.len() {
            if self.sub_identifiers[i] != prefix.sub_identifiers[i] {
                return None;
            }
        }

        Some(&self.as_slice()[prefix.len()..])
    }

    /// Returns whether this object identifier is a prefix of another object identifier or equal to
    /// it.
    pub fn is_prefix_of_or_equal(&self, other: &Self) -> bool {
        other.tail_slice(&self).is_some()
    }

    /// Returns whether this object identifier is a prefix of another object identifier. Returns
    /// `false` if the object identifiers are equal.
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        // same length is also unacceptable
        if self.len() >= other.len() {
            return false;
        }

        self.is_prefix_of_or_equal(other)
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
        // compare up to the common length
        let shorter_length = self.length.min(other.length);
        for i in 0..shorter_length {
            let comparison = self.sub_identifiers[i].cmp(&other.sub_identifiers[i]);
            if comparison != Ordering::Equal {
                return Some(comparison);
            }
        }
        // one is a prefix of the other; compare by length
        Some(self.length.cmp(&other.length))
    }
}
impl Ord for ObjectIdentifier {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
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


/// The zero-zero OID (0.0), indicating the absence of an OID.
pub const ZERO_ZERO_OID: ObjectIdentifier = ObjectIdentifier::new(0, [0; MAX_SUB_IDENTIFIER_COUNT]);


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
            assert_eq!(parsed.as_slice(), slice);
        }

        tfs(&[], "");
        tfs(&[1], "1");
        tfs(&[1, 3, 6, 1, 4, 1], "1.3.6.1.4.1");
        tfs(&[1, 3, 6, 1, 4, 1, 1], "1.3.6.1.4.1.1");
        tfs(&[1, 3, 6, 1, 4, 1, 1, 2, 3, 4, 5], "1.3.6.1.4.1.1.2.3.4.5");
        tfs(&[3, 2, 1], "3.2.1");
        tfs(&[1, 3, 4], "1.3.4");
        tfs(&[1, 3, 4, 4294967295, 1], "1.3.4.4294967295.1");
    }
}
