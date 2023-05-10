/// Creates an object identifier from a comma-separated sequence.
///
/// Unfortunately, dotted sequences are not supported due to the lexer/parser's interpretation of
/// literals like `1.1` as floating-point numbers instead of dotted integer sequences.
#[macro_export]
macro_rules! make_oid {
    () => {
        $crate::oid::ObjectIdentifier::new(Vec::new())
    };
    ($firstnum:literal $(, $nextnums:literal)*) => {
        $crate::oid::ObjectIdentifier::new(vec![$firstnum $(, $nextnums)*])
    };
}


#[cfg(feature = "tracing")]
#[macro_export]
macro_rules! debug {
    ($first_expr:expr $(, $other_expr:expr)* $(,)?) => {
        ::tracing::debug!($first_expr $(, $other_expr)*);
    };
}

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! debug {
    ($first_expr:expr $(, $other_expr:expr)* $(,)?) => {};
}


#[cfg(test)]
mod tests {
    use crate::{ObjectIdentifier, make_oid};

    #[test]
    fn test_create_empty_oid() {
        let empty_oid = make_oid!();
        assert_eq!(empty_oid, ObjectIdentifier::new(vec![]));
    }

    #[test]
    fn test_two_arc_oid() {
        let short_oid = make_oid!(1,3);
        assert_eq!(short_oid, ObjectIdentifier::new(vec![1, 3]));
    }

    #[test]
    fn test_8_arc_oid() {
        let eight_arc_oid = make_oid!(1,3,6,1,2,1,2,2);
        assert_eq!(eight_arc_oid, ObjectIdentifier::new(vec![1, 3, 6, 1, 2, 1, 2, 2]));
    }
}
