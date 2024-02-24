//! Information collection using SNMP2c.
//!
//! SNMP2c is the Simple Network Management Protocol version 2 with authentication using community
//! strings. This implementation assumes UDP as the transport protocol.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

use simple_asn1::{BigUint, OID};


/// The maximum number of arcs (numbers) in an object identifier.
///
/// See RFC3416, section 4.1.
pub const MAX_ARC_COUNT: usize = 128;


/// The minimum number of arcs (numbers) in an absolute object identifier.
///
/// X.680 section 32.11 notes that X.660 requires that an object identifier value contain at least
/// two arcs; this requirement does not appear to be stated explicitly in X.660.
pub const ABS_MIN_ARC_COUNT: usize = 2;


/// An error that can occur when converting from a slice of 32-bit unsigned integers into an
/// [`ObjectIdentifier`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ObjectIdentifierConversionError {
    /// The slice is too long.
    ///
    /// `max` contains the maximum number of arcs; `obtained` the number of arcs in the slice. The
    /// maximum number of arcs in an SNMP object identifier can be read from [`MAX_ARC_COUNT`].
    TooLong { max: usize, obtained: usize },

    /// The value of one of the entries is out of range.
    ///
    /// `index` contains the index of the out-of-range value. The range of arcs in an SNMP object
    /// identifier is equal to the range of `u32`.
    ValueRange { index: usize },

    /// The object identifier is used in a context where absolute object identifiers are required
    /// and it has fewer than the required number of arcs. The minimum number of arcs in an absolute
    /// object identifier can be read from [`ABS_MIN_ARC_COUNT`].
    TooShort { length: usize },

    /// The arc at the given index is invalid.
    InvalidArcString { index: usize },
}
impl fmt::Display for ObjectIdentifierConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { obtained, max }
                => write!(f, "slice has length {}, maximum is {}", obtained, max),
            Self::ValueRange { index }
                => write!(f, "arc at index {} is out of range", index),
            Self::TooShort { length }
                => write!(f, "need more than {} arcs", length),
            Self::InvalidArcString { index }
                => write!(f, "invalid arc at index {}", index),
        }
    }
}
impl Error for ObjectIdentifierConversionError {
}


/// An SNMP object identifier.
///
/// Equivalent to an ASN.1 object identifier, except limited to maximum [`MAX_ARC_COUNT`] arcs of a
/// value of up to 2**32-1.
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct ObjectIdentifier {
    length: usize,
    arcs: [u32; MAX_ARC_COUNT],
}
impl ObjectIdentifier {
    /// Makes a new object identifier.
    ///
    /// `arcs` elements at index >= `length` must all be 0. Panics if this is not the case.
    ///
    /// You probably want to use the functions of the `TryFrom<&[u32]>` implementation instead.
    pub const fn new(length: usize, arcs: [u32; MAX_ARC_COUNT]) -> Self {
        // FIXME: turn all this into a loop once those are supported in const functions
        if MAX_ARC_COUNT != 128 {
            panic!("MAX_ARC_COUNT has changed!");
        }
        if length <= 0 && arcs[0] != 0 { panic!("arc at index 0 is beyond length but not 0"); }
        if length <= 1 && arcs[1] != 0 { panic!("arc at index 1 is beyond length but not 0"); }
        if length <= 2 && arcs[2] != 0 { panic!("arc at index 2 is beyond length but not 0"); }
        if length <= 3 && arcs[3] != 0 { panic!("arc at index 3 is beyond length but not 0"); }
        if length <= 4 && arcs[4] != 0 { panic!("arc at index 4 is beyond length but not 0"); }
        if length <= 5 && arcs[5] != 0 { panic!("arc at index 5 is beyond length but not 0"); }
        if length <= 6 && arcs[6] != 0 { panic!("arc at index 6 is beyond length but not 0"); }
        if length <= 7 && arcs[7] != 0 { panic!("arc at index 7 is beyond length but not 0"); }
        if length <= 8 && arcs[8] != 0 { panic!("arc at index 8 is beyond length but not 0"); }
        if length <= 9 && arcs[9] != 0 { panic!("arc at index 9 is beyond length but not 0"); }
        if length <= 10 && arcs[10] != 0 { panic!("arc at index 10 is beyond length but not 0"); }
        if length <= 11 && arcs[11] != 0 { panic!("arc at index 11 is beyond length but not 0"); }
        if length <= 12 && arcs[12] != 0 { panic!("arc at index 12 is beyond length but not 0"); }
        if length <= 13 && arcs[13] != 0 { panic!("arc at index 13 is beyond length but not 0"); }
        if length <= 14 && arcs[14] != 0 { panic!("arc at index 14 is beyond length but not 0"); }
        if length <= 15 && arcs[15] != 0 { panic!("arc at index 15 is beyond length but not 0"); }
        if length <= 16 && arcs[16] != 0 { panic!("arc at index 16 is beyond length but not 0"); }
        if length <= 17 && arcs[17] != 0 { panic!("arc at index 17 is beyond length but not 0"); }
        if length <= 18 && arcs[18] != 0 { panic!("arc at index 18 is beyond length but not 0"); }
        if length <= 19 && arcs[19] != 0 { panic!("arc at index 19 is beyond length but not 0"); }
        if length <= 20 && arcs[20] != 0 { panic!("arc at index 20 is beyond length but not 0"); }
        if length <= 21 && arcs[21] != 0 { panic!("arc at index 21 is beyond length but not 0"); }
        if length <= 22 && arcs[22] != 0 { panic!("arc at index 22 is beyond length but not 0"); }
        if length <= 23 && arcs[23] != 0 { panic!("arc at index 23 is beyond length but not 0"); }
        if length <= 24 && arcs[24] != 0 { panic!("arc at index 24 is beyond length but not 0"); }
        if length <= 25 && arcs[25] != 0 { panic!("arc at index 25 is beyond length but not 0"); }
        if length <= 26 && arcs[26] != 0 { panic!("arc at index 26 is beyond length but not 0"); }
        if length <= 27 && arcs[27] != 0 { panic!("arc at index 27 is beyond length but not 0"); }
        if length <= 28 && arcs[28] != 0 { panic!("arc at index 28 is beyond length but not 0"); }
        if length <= 29 && arcs[29] != 0 { panic!("arc at index 29 is beyond length but not 0"); }
        if length <= 30 && arcs[30] != 0 { panic!("arc at index 30 is beyond length but not 0"); }
        if length <= 31 && arcs[31] != 0 { panic!("arc at index 31 is beyond length but not 0"); }
        if length <= 32 && arcs[32] != 0 { panic!("arc at index 32 is beyond length but not 0"); }
        if length <= 33 && arcs[33] != 0 { panic!("arc at index 33 is beyond length but not 0"); }
        if length <= 34 && arcs[34] != 0 { panic!("arc at index 34 is beyond length but not 0"); }
        if length <= 35 && arcs[35] != 0 { panic!("arc at index 35 is beyond length but not 0"); }
        if length <= 36 && arcs[36] != 0 { panic!("arc at index 36 is beyond length but not 0"); }
        if length <= 37 && arcs[37] != 0 { panic!("arc at index 37 is beyond length but not 0"); }
        if length <= 38 && arcs[38] != 0 { panic!("arc at index 38 is beyond length but not 0"); }
        if length <= 39 && arcs[39] != 0 { panic!("arc at index 39 is beyond length but not 0"); }
        if length <= 40 && arcs[40] != 0 { panic!("arc at index 40 is beyond length but not 0"); }
        if length <= 41 && arcs[41] != 0 { panic!("arc at index 41 is beyond length but not 0"); }
        if length <= 42 && arcs[42] != 0 { panic!("arc at index 42 is beyond length but not 0"); }
        if length <= 43 && arcs[43] != 0 { panic!("arc at index 43 is beyond length but not 0"); }
        if length <= 44 && arcs[44] != 0 { panic!("arc at index 44 is beyond length but not 0"); }
        if length <= 45 && arcs[45] != 0 { panic!("arc at index 45 is beyond length but not 0"); }
        if length <= 46 && arcs[46] != 0 { panic!("arc at index 46 is beyond length but not 0"); }
        if length <= 47 && arcs[47] != 0 { panic!("arc at index 47 is beyond length but not 0"); }
        if length <= 48 && arcs[48] != 0 { panic!("arc at index 48 is beyond length but not 0"); }
        if length <= 49 && arcs[49] != 0 { panic!("arc at index 49 is beyond length but not 0"); }
        if length <= 50 && arcs[50] != 0 { panic!("arc at index 50 is beyond length but not 0"); }
        if length <= 51 && arcs[51] != 0 { panic!("arc at index 51 is beyond length but not 0"); }
        if length <= 52 && arcs[52] != 0 { panic!("arc at index 52 is beyond length but not 0"); }
        if length <= 53 && arcs[53] != 0 { panic!("arc at index 53 is beyond length but not 0"); }
        if length <= 54 && arcs[54] != 0 { panic!("arc at index 54 is beyond length but not 0"); }
        if length <= 55 && arcs[55] != 0 { panic!("arc at index 55 is beyond length but not 0"); }
        if length <= 56 && arcs[56] != 0 { panic!("arc at index 56 is beyond length but not 0"); }
        if length <= 57 && arcs[57] != 0 { panic!("arc at index 57 is beyond length but not 0"); }
        if length <= 58 && arcs[58] != 0 { panic!("arc at index 58 is beyond length but not 0"); }
        if length <= 59 && arcs[59] != 0 { panic!("arc at index 59 is beyond length but not 0"); }
        if length <= 60 && arcs[60] != 0 { panic!("arc at index 60 is beyond length but not 0"); }
        if length <= 61 && arcs[61] != 0 { panic!("arc at index 61 is beyond length but not 0"); }
        if length <= 62 && arcs[62] != 0 { panic!("arc at index 62 is beyond length but not 0"); }
        if length <= 63 && arcs[63] != 0 { panic!("arc at index 63 is beyond length but not 0"); }
        if length <= 64 && arcs[64] != 0 { panic!("arc at index 64 is beyond length but not 0"); }
        if length <= 65 && arcs[65] != 0 { panic!("arc at index 65 is beyond length but not 0"); }
        if length <= 66 && arcs[66] != 0 { panic!("arc at index 66 is beyond length but not 0"); }
        if length <= 67 && arcs[67] != 0 { panic!("arc at index 67 is beyond length but not 0"); }
        if length <= 68 && arcs[68] != 0 { panic!("arc at index 68 is beyond length but not 0"); }
        if length <= 69 && arcs[69] != 0 { panic!("arc at index 69 is beyond length but not 0"); }
        if length <= 70 && arcs[70] != 0 { panic!("arc at index 70 is beyond length but not 0"); }
        if length <= 71 && arcs[71] != 0 { panic!("arc at index 71 is beyond length but not 0"); }
        if length <= 72 && arcs[72] != 0 { panic!("arc at index 72 is beyond length but not 0"); }
        if length <= 73 && arcs[73] != 0 { panic!("arc at index 73 is beyond length but not 0"); }
        if length <= 74 && arcs[74] != 0 { panic!("arc at index 74 is beyond length but not 0"); }
        if length <= 75 && arcs[75] != 0 { panic!("arc at index 75 is beyond length but not 0"); }
        if length <= 76 && arcs[76] != 0 { panic!("arc at index 76 is beyond length but not 0"); }
        if length <= 77 && arcs[77] != 0 { panic!("arc at index 77 is beyond length but not 0"); }
        if length <= 78 && arcs[78] != 0 { panic!("arc at index 78 is beyond length but not 0"); }
        if length <= 79 && arcs[79] != 0 { panic!("arc at index 79 is beyond length but not 0"); }
        if length <= 80 && arcs[80] != 0 { panic!("arc at index 80 is beyond length but not 0"); }
        if length <= 81 && arcs[81] != 0 { panic!("arc at index 81 is beyond length but not 0"); }
        if length <= 82 && arcs[82] != 0 { panic!("arc at index 82 is beyond length but not 0"); }
        if length <= 83 && arcs[83] != 0 { panic!("arc at index 83 is beyond length but not 0"); }
        if length <= 84 && arcs[84] != 0 { panic!("arc at index 84 is beyond length but not 0"); }
        if length <= 85 && arcs[85] != 0 { panic!("arc at index 85 is beyond length but not 0"); }
        if length <= 86 && arcs[86] != 0 { panic!("arc at index 86 is beyond length but not 0"); }
        if length <= 87 && arcs[87] != 0 { panic!("arc at index 87 is beyond length but not 0"); }
        if length <= 88 && arcs[88] != 0 { panic!("arc at index 88 is beyond length but not 0"); }
        if length <= 89 && arcs[89] != 0 { panic!("arc at index 89 is beyond length but not 0"); }
        if length <= 90 && arcs[90] != 0 { panic!("arc at index 90 is beyond length but not 0"); }
        if length <= 91 && arcs[91] != 0 { panic!("arc at index 91 is beyond length but not 0"); }
        if length <= 92 && arcs[92] != 0 { panic!("arc at index 92 is beyond length but not 0"); }
        if length <= 93 && arcs[93] != 0 { panic!("arc at index 93 is beyond length but not 0"); }
        if length <= 94 && arcs[94] != 0 { panic!("arc at index 94 is beyond length but not 0"); }
        if length <= 95 && arcs[95] != 0 { panic!("arc at index 95 is beyond length but not 0"); }
        if length <= 96 && arcs[96] != 0 { panic!("arc at index 96 is beyond length but not 0"); }
        if length <= 97 && arcs[97] != 0 { panic!("arc at index 97 is beyond length but not 0"); }
        if length <= 98 && arcs[98] != 0 { panic!("arc at index 98 is beyond length but not 0"); }
        if length <= 99 && arcs[99] != 0 { panic!("arc at index 99 is beyond length but not 0"); }
        if length <= 100 && arcs[100] != 0 { panic!("arc at index 100 is beyond length but not 0"); }
        if length <= 101 && arcs[101] != 0 { panic!("arc at index 101 is beyond length but not 0"); }
        if length <= 102 && arcs[102] != 0 { panic!("arc at index 102 is beyond length but not 0"); }
        if length <= 103 && arcs[103] != 0 { panic!("arc at index 103 is beyond length but not 0"); }
        if length <= 104 && arcs[104] != 0 { panic!("arc at index 104 is beyond length but not 0"); }
        if length <= 105 && arcs[105] != 0 { panic!("arc at index 105 is beyond length but not 0"); }
        if length <= 106 && arcs[106] != 0 { panic!("arc at index 106 is beyond length but not 0"); }
        if length <= 107 && arcs[107] != 0 { panic!("arc at index 107 is beyond length but not 0"); }
        if length <= 108 && arcs[108] != 0 { panic!("arc at index 108 is beyond length but not 0"); }
        if length <= 109 && arcs[109] != 0 { panic!("arc at index 109 is beyond length but not 0"); }
        if length <= 110 && arcs[110] != 0 { panic!("arc at index 110 is beyond length but not 0"); }
        if length <= 111 && arcs[111] != 0 { panic!("arc at index 111 is beyond length but not 0"); }
        if length <= 112 && arcs[112] != 0 { panic!("arc at index 112 is beyond length but not 0"); }
        if length <= 113 && arcs[113] != 0 { panic!("arc at index 113 is beyond length but not 0"); }
        if length <= 114 && arcs[114] != 0 { panic!("arc at index 114 is beyond length but not 0"); }
        if length <= 115 && arcs[115] != 0 { panic!("arc at index 115 is beyond length but not 0"); }
        if length <= 116 && arcs[116] != 0 { panic!("arc at index 116 is beyond length but not 0"); }
        if length <= 117 && arcs[117] != 0 { panic!("arc at index 117 is beyond length but not 0"); }
        if length <= 118 && arcs[118] != 0 { panic!("arc at index 118 is beyond length but not 0"); }
        if length <= 119 && arcs[119] != 0 { panic!("arc at index 119 is beyond length but not 0"); }
        if length <= 120 && arcs[120] != 0 { panic!("arc at index 120 is beyond length but not 0"); }
        if length <= 121 && arcs[121] != 0 { panic!("arc at index 121 is beyond length but not 0"); }
        if length <= 122 && arcs[122] != 0 { panic!("arc at index 122 is beyond length but not 0"); }
        if length <= 123 && arcs[123] != 0 { panic!("arc at index 123 is beyond length but not 0"); }
        if length <= 124 && arcs[124] != 0 { panic!("arc at index 124 is beyond length but not 0"); }
        if length <= 125 && arcs[125] != 0 { panic!("arc at index 125 is beyond length but not 0"); }
        if length <= 126 && arcs[126] != 0 { panic!("arc at index 126 is beyond length but not 0"); }
        if length <= 127 && arcs[127] != 0 { panic!("arc at index 127 is beyond length but not 0"); }

        Self {
            length,
            arcs,
        }
    }

    /// Returns the length of this object identifier. Guaranteed to be at least 0 and less than
    /// [`MAX_ARC_COUNT`].
    pub fn len(&self) -> usize {
        self.length
    }

    /// Obtains the arc at the given index, or `None` if the index is out of bounds.
    pub fn get(&self, index: usize) -> Option<u32> {
        if index < self.length {
            Some(self.arcs[index])
        } else {
            None
        }
    }

    /// Returns this object identifier als a slice of unsigned 32-bit integers.
    pub fn as_slice(&self) -> &[u32] {
        &self.arcs[0..self.length]
    }

    /// Returns the parent of this object identifier, or `None` if it has no parent.
    pub fn parent(&self) -> Option<Self> {
        if self.length == 0 {
            None
        } else {
            self.arcs[0..self.length-1]
                .try_into()
                .ok()
        }
    }

    /// Returns a child of this object identifier constructed by appending the given `arc`, or
    /// `None` if that would create an object identifier that is too long.
    pub fn child(&self, arc: u32) -> Option<Self> {
        if self.length == MAX_ARC_COUNT {
            None
        } else {
            let mut arcs = self.arcs.clone();
            arcs[self.length] = arc;
            Some(Self {
                length: self.length + 1,
                arcs,
            })
        }
    }

    /// If `prefix` is a prefix of or equal to this OID, returns a slice containing the arcs
    /// following this prefix; otherwise, returns `None`.
    fn tail_slice(&self, prefix: &Self) -> Option<&[u32]> {
        if prefix.len() > self.len() {
            return None;
        }

        for i in 0..prefix.len() {
            if self.arcs[i] != prefix.arcs[i] {
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
            .map(|arcs| Self::try_from(arcs).unwrap())
    }
}
impl Default for ObjectIdentifier {
    fn default() -> Self {
        Self { length: 0, arcs: [0u32; 128] }
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
            write!(f, "{}", self.arcs[i])?;
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
        self.arcs[..self.length].cmp(&other.arcs[..other.length])
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
        if pieces.len() > MAX_ARC_COUNT {
            return Err(ObjectIdentifierConversionError::TooLong {
                max: MAX_ARC_COUNT,
                obtained: pieces.len(),
            });
        }

        let mut arcs = [0u32; MAX_ARC_COUNT];
        if stripped.len() > 0 {
            for (index, piece) in pieces.iter().enumerate() {
                arcs[index] = piece.parse()
                    .map_err(|_| ObjectIdentifierConversionError::InvalidArcString {
                        index,
                    })?;
            }
        }

        Ok(Self {
            length: pieces.len(),
            arcs,
        })
    }
}
impl TryFrom<&[u32]> for ObjectIdentifier {
    type Error = ObjectIdentifierConversionError;

    fn try_from(value: &[u32]) -> Result<Self, Self::Error> {
        if value.len() > MAX_ARC_COUNT {
            return Err(ObjectIdentifierConversionError::TooLong {
                max: MAX_ARC_COUNT,
                obtained: value.len(),
            });
        }
        let mut arcs = [0u32; MAX_ARC_COUNT];
        for i in 0..value.len() {
            arcs[i] = value[i];
        }
        Ok(Self {
            length: value.len(),
            arcs,
        })
    }
}
impl TryFrom<&OID> for ObjectIdentifier {
    type Error = ObjectIdentifierConversionError;

    fn try_from(value: &OID) -> Result<Self, Self::Error> {
        let vec: Vec<&BigUint> = value.as_vec().unwrap();
        let mut arcs = [0u32; MAX_ARC_COUNT];

        for (index, val) in vec.iter().enumerate() {
            let arc = (*val).try_into()
                .map_err(|_| ObjectIdentifierConversionError::ValueRange { index })?;
            arcs[index] = arc;
        }

        Ok(Self {
            length: vec.len(),
            arcs,
        })
    }
}
impl TryFrom<&ObjectIdentifier> for OID {
    type Error = ObjectIdentifierConversionError;

    fn try_from(value: &ObjectIdentifier) -> Result<Self, Self::Error> {
        if value.len() < ABS_MIN_ARC_COUNT {
            return Err(ObjectIdentifierConversionError::TooShort {
                length: value.len(),
            });
        }
        Ok(OID::new(
            value.as_slice()
                .iter()
                .map(|&arc| BigUint::from(arc))
                .collect()
        ))
    }
}


/// The zero-zero OID (0.0), indicating the absence of an OID.
pub const ZERO_ZERO_OID: ObjectIdentifier = ObjectIdentifier::new(0, [0; MAX_ARC_COUNT]);


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_from_slice() {
        fn tfs(arcs: &[u32]) {
            assert_eq!(arcs, ObjectIdentifier::try_from(arcs).unwrap().as_slice());
        }
        fn tfs_err(arcs: &[u32]) {
            assert!(ObjectIdentifier::try_from(arcs).is_err());
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
        fn tts(arcs: &[u32], string: &str) {
            assert_eq!(ObjectIdentifier::try_from(arcs).unwrap().to_string(), string);
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
        fn tfs(arcs: &[u32], string: &str) {
            let parsed: ObjectIdentifier = string.parse().unwrap();
            assert_eq!(parsed.as_slice(), arcs);
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

    #[test]
    fn test_cmp() {
        let oid_empty = ObjectIdentifier::from_str("").unwrap();
        let oid23 = ObjectIdentifier::from_str("2.3").unwrap();
        let oid310 = ObjectIdentifier::from_str("3.1.0").unwrap();
        let oid32 = ObjectIdentifier::from_str("3.2").unwrap();
        let oid320 = ObjectIdentifier::from_str("3.2.0").unwrap();
        let oid_max_long = ObjectIdentifier::new(
            MAX_ARC_COUNT,
            [u32::MAX; MAX_ARC_COUNT],
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
