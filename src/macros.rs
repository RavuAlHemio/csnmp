/// Creates an object identifier from a comma-separated sequence.
///
/// Unfortunately, dotted sequences are not supported due to the lexer/parser's interpretation of
/// literals like `1.1` as floating-point numbers instead of dotted integer sequences.
#[macro_export]
macro_rules! make_oid {
    () => {
        $crate::oid::ObjectIdentifier::new(0, [0u32; $crate::oid::MAX_SUB_IDENTIFIER_COUNT])
    };
    ($firstnum:literal $(, $nextnums:literal)*) => {
        {
            let mut arcs = [0u32; $crate::oid::MAX_SUB_IDENTIFIER_COUNT];
            let mut length = 0;
            make_oid!(@store_numbers, arcs, length, $firstnum $(, $nextnums)*);
            $crate::oid::ObjectIdentifier::new(length, arcs)
        }
    };
    (@store_numbers, $arcs:expr, $length:expr, $lastnum:literal) => {
        $arcs[$length] = $lastnum;
        $length += 1;
    };
    (@store_numbers, $arcs:expr, $length:expr, $firstnum:literal $(, $nextnums:literal)*) => {
        $arcs[$length] = $firstnum;
        $length += 1;
        make_oid!(@store_numbers, $arcs, $length $(, $nextnums)*);
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
        const EMPTY_OID: ObjectIdentifier = make_oid!();
        assert_eq!(EMPTY_OID, ObjectIdentifier::new(0, [0u32; 128]));
    }

    #[test]
    fn test_two_arc_oid() {
        const SHORT_OID: ObjectIdentifier = make_oid!(1,3);
        let mut arcs = [0u32; 128];
        arcs[0] = 1;
        arcs[1] = 3;
        assert_eq!(SHORT_OID, ObjectIdentifier::new(2, arcs));
    }

    #[test]
    fn test_8_arc_oid() {
        const EIGHT_ARC_OID: ObjectIdentifier = make_oid!(1,3,6,1,2,1,2,2);
        let mut arcs = [0u32; 128];
        arcs[0] = 1;
        arcs[1] = 3;
        arcs[2] = 6;
        arcs[3] = 1;
        arcs[4] = 2;
        arcs[5] = 1;
        arcs[6] = 2;
        arcs[7] = 2;
        assert_eq!(EIGHT_ARC_OID, ObjectIdentifier::new(8, arcs));
    }
}
