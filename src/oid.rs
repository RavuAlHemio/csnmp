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
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct ObjectIdentifier {
    vector: Vec<u32>,
}
impl ObjectIdentifier {
    /// Makes a new object identifier.
    ///
    /// `sub_identifiers` elements at index >= `length` must all be 0. Panics if this is not the
    /// case.
    ///
    /// You probably want to use the functions of the `TryFrom<&[u32]>` implementation instead.
    pub fn new(vector: Vec<u32>) -> Self {
        if vector.len() > MAX_SUB_IDENTIFIER_COUNT {
            panic!("got {} items which is more than the maximum ({})", vector.len(), MAX_SUB_IDENTIFIER_COUNT);
        }
        Self {
            vector,
        }
    }

    /// Returns the length of this object identifier. Guaranteed to be at least 0 and less than
    /// [`MAX_SUB_IDENTIFIER_COUNT`].
    #[inline]
    pub fn len(&self) -> usize {
        self.vector.len()
    }

    /// Obtains the sub-identifier at the given index, or `None` if the index is out of bounds.
    #[inline]
    pub fn get(&self, index: usize) -> Option<u32> {
        self.vector.get(index).map(|u| *u)
    }

    /// Returns this object identifier als a slice of unsigned 32-bit integers.
    #[inline]
    pub fn as_slice(&self) -> &[u32] {
        self.vector.as_slice()
    }

    /// Returns the parent of this object identifier, or `None` if it has no parent.
    pub fn parent(&self) -> Option<Self> {
        if self.len() == 0 {
            None
        } else {
            self.as_slice()[0..self.len()-1]
                .try_into()
                .ok()
        }
    }

    /// Returns a child of this object identifier constructed by appending the given `sub_id`,
    /// or `None` if that would create an object identifier that is too long.
    pub fn child(&self, sub_id: u32) -> Option<Self> {
        if self.len() == MAX_SUB_IDENTIFIER_COUNT {
            None
        } else {
            let mut new_vector = self.vector.clone();
            new_vector.push(sub_id);
            Some(Self {
                vector: new_vector,
            })
        }
    }

    /// If `prefix` is a prefix of or equal to this OID, returns a slice containing the items
    /// following this prefix; otherwise, returns `None`.
    fn tail_slice(&self, prefix: &Self) -> Option<&[u32]> {
        if prefix.len() > self.len() {
            return None;
        }

        for (s, p) in self.as_slice().into_iter().zip(prefix.as_slice().into_iter()) {
            if s != p {
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
        Self { vector: Vec::new() }
    }
}
impl fmt::Debug for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectIdentifier({})", self)
    }
}
impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, sub_ident) in self.vector.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", sub_ident)?;
        }
        Ok(())
    }
}
impl PartialOrd for ObjectIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // compare up to the common length
        for (s, o) in self.vector.iter().zip(other.vector.iter()) {
            let comparison = s.cmp(o);
            if comparison != Ordering::Equal {
                return Some(comparison);
            }
        }
        // one is a prefix of the other; compare by length
        Some(self.len().cmp(&other.len()))
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

        let vector = if stripped.len() > 0 {
            let mut vector = Vec::with_capacity(pieces.len());
            for (index, piece) in pieces.iter().enumerate() {
                let piece_u32 = piece.parse()
                    .map_err(|_| ObjectIdentifierConversionError::InvalidSubIdString {
                        index,
                    })?;
                vector.push(piece_u32);
            }
            vector
        } else {
            Vec::new()
        };

        Ok(Self {
            vector,
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
        let vector = Vec::from(value);
        Ok(Self {
            vector,
        })
    }
}


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
