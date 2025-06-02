// Module declarations for the individual stdlib component files
pub mod array;
pub mod control;
pub mod core;
pub mod string;

// Re-export all public items from these modules
pub use array::*;
pub use control::*;
pub use core::*;
pub use string::*;

// Macros moved from the old stdlib.rs
#[macro_export]
macro_rules! function_head {
    ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr) => {

        #[derive(Clone,Hash)]
        pub struct $name(String); // Made field public for potential external construction if needed

        #[allow(dead_code)]
        impl $name {
            pub fn stub() -> $name {$name(stringify!($name).into())} // Made pub
            pub fn make_call($($aname : $crate::script::Value),+) -> $crate::script::Call { // Used crate::script::Value and Call
                $crate::script::Call::new(vec![$name(stringify!($name).into()).into(), $($aname),+ ])
            }
        }
        impl $crate::script::NativeObject for $name { // Used crate::script::NativeObject
            fn as_callable(&self) -> Option<&dyn $crate::script::Callable>{Some(self)} // Used crate::script::Callable
            // Added default implementations for other NativeObject traits
            fn as_evaluatable(&self) -> Option<&dyn $crate::script::Evaluatable> { None }
            fn as_indexable(&self) -> Option<&dyn $crate::script::Indexable> { None }
            fn as_accessible(&self) -> Option<&dyn $crate::script::Accessible> { None }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f,"{}", stringify!($name))
            }
        }
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f,"{}", stringify!($name))
            }
        }
    };
}

#[macro_export]
macro_rules! args {
    ($args:ident, $($aname:ident),+) => {
        let mut iter = $args.into_iter();
        $(let $aname = iter.next().unwrap();)+
    };
    ($args:ident, ctx=$ctx:ident, $($aname:ident),+) => {
        $crate::args!($args, ctx=$ctx, opts=expand, $($aname),+); // Used crate::args
    };
    ($args:ident, ctx=$ctx:ident, opts=expand, $($aname:ident),+) => {
        let mut iter = $args.into_iter();
        $(
            let $aname = iter.next().unwrap().real_value_of($ctx.clone()).await?;
        )+
    };
    ($args:ident, ctx=$ctx:ident, opts=raw, $($aname:ident),+) => {
        let mut iter = $args.into_iter();
        $(
            let $aname = iter.next().unwrap();
        )+
    };
}

#[macro_export]
macro_rules! function {
    ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr, $body:tt) =>{
        $crate::function!($name ($($aname : $atype),+) => $rtype, ctx=ctx, $body); // Used crate::function
    };
    ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr, ctx=$ctx:ident, $body:tt) => {
        $crate::function!($name ($($aname : $atype),+) => $rtype, ctx=$ctx, arg_opts=expand, $body); // Used crate::function
    };
    ($name:ident ($($aname:ident : $atype:expr),+) => $rtype:expr, ctx=$ctx:ident, arg_opts=$arg_opts:ident, $body:tt) => {
        $crate::function_head!($name ($($aname : $atype),+) => $rtype); // Used crate::function_head
        #[async_trait::async_trait] // Used async_trait::async_trait
        impl $crate::script::Callable for $name { // Used crate::script::Callable
            async fn signature(
                &self,
                $ctx: $crate::script::ScriptContextRef, // Used crate::script::ScriptContextRef
                args: &[$crate::script::Value], // Used crate::script::Value
            ) -> Result<$crate::script::Type, easy_error::Error> // Used crate::script::Type, easy_error::Error
            {
                let mut targs : Vec<$crate::script::Type> = Vec::with_capacity(args.len()); // Used crate::script::Type
                for x in args {
                    let t = x.real_type_of($ctx.clone()).await?;
                    targs.push(t);
                }
                $crate::args!(targs, $($aname),+); // Used crate::args
                use $crate::script::Type::*; // Used crate::script::Type
                $(if $aname != $atype {
                    easy_error::bail!("argument {} type mismatch, required: {} provided: {:?}", // Used easy_error::bail
                        stringify!($aname),
                        stringify!($atype),
                        $aname
                    )
                })+
                Ok($rtype)
            }
            #[allow(unused_braces)]
            async fn call(
                &self,
                $ctx: $crate::script::ScriptContextRef, // Used crate::script::ScriptContextRef
                args: &[$crate::script::Value], // Used crate::script::Value
            ) -> Result<$crate::script::Value, easy_error::Error> // Used crate::script::Value, easy_error::Error
            {
                $crate::args!(args, ctx=$ctx, opts=$arg_opts, $($aname),+); // Used crate::args
                $body
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*; // This will now import from array, control, core, string submodules
    use crate::script::{
        Accessible, Arc, Callable, Evaluatable, Indexable, NativeObject, ScriptContextRef, Value,
    }; // Added more specific imports
       // For op_error_test!
    use std::collections::HashMap; // Keep for Test struct in tests
    use std::convert::TryInto; // For op_error_test! and others

    // Helper test functions for callbacks (These might need to be pub if used across test modules, or defined in each)
    // For now, assume they are used only within this test module.
    // If these are general test helpers, they could be in a common test utility module.
    function!(TestHelperAddOne(val: Integer) => Integer, {
        let v: i64 = val.try_into()?;
        Ok(Value::Integer(v + 1))
    });

    function!(TestHelperToString(val: Any) => String, {
        Ok(Value::String(val.to_string()))
    });

    function!(TestHelperSum(acc: Integer, val: Integer) => Integer, {
        let a: i64 = acc.try_into()?;
        let v: i64 = val.try_into()?;
        Ok(Value::Integer(a + v))
    });

    function!(TestHelperIsEven(val: Integer) => Boolean, {
        let v: i64 = val.try_into()?;
        Ok(Value::Boolean(v % 2 == 0))
    });

    function!(TestHelperTrue(_val: Any) => Boolean, { Ok(Value::Boolean(true)) });
    function!(TestHelperFalse(_val: Any) => Boolean, { Ok(Value::Boolean(false)) });

    macro_rules! op_test {
        ($name:ident, $fn:ident, [ $($in:expr),+ ] , $out:expr) => {
            #[tokio::test]
            async fn $name() {
                let ctx : ScriptContextRef = Default::default();
                let func_call_val : Value = $fn::make_call( $($in),+ ).into();
                let expected_output_val : Value = $out;

                let expected_type = expected_output_val.type_of(ctx.clone()).await
                    .unwrap_or_else(|e| panic!("Error getting type of expected output for {}: {:?}", stringify!($name), e));
                let actual_type_result = func_call_val.type_of(ctx.clone()).await;
                assert!(actual_type_result.is_ok(), "Type signature check failed for {}: {:?}", stringify!($name), actual_type_result.err().unwrap());
                assert_eq!(expected_type, actual_type_result.unwrap(), "Type mismatch for {}", stringify!($name));

                let actual_value_result = func_call_val.value_of(ctx).await;
                assert!(actual_value_result.is_ok(), "Value evaluation failed for {}: {:?}", stringify!($name), actual_value_result.err().unwrap());
                assert_eq!(actual_value_result.unwrap(), expected_output_val, "Value mismatch for {}", stringify!($name));
            }
        };
    }

    macro_rules! op_error_test {
        ($name:ident, $fn:ident, [ $($in:expr),+ ] , $expected_error_substring:expr) => {
            #[tokio::test]
            async fn $name() {
                let ctx : ScriptContextRef = Default::default();
                let func_call_val : Value = $fn::make_call( $($in),+ ).into();

                let type_result = func_call_val.type_of(ctx.clone()).await;
                let value_result = func_call_val.value_of(ctx).await;

                let error_message = match (type_result, value_result) {
                    (Err(type_err), _) => type_err.to_string(),
                    (_, Err(val_err)) => val_err.to_string(),
                    (Ok(t), Ok(v)) => {
                        panic!("Expected error for '{}', but got Ok(type: {:?}, value: {:?})", stringify!($name), t, v)
                    }
                };
                assert!(
                    error_message.contains($expected_error_substring),
                    "Error message for '{}' was '{}', expected to contain '{}'",
                    stringify!($name), error_message, $expected_error_substring
                );
            }
        };
    }

    // Test struct for Access/Index tests
    #[derive(Debug)]
    struct Test {
        map: HashMap<String, Value>,
        array: Vec<Value>,
    }

    impl Test {
        fn new() -> Self {
            let mut map: HashMap<String, Value> = Default::default();
            map.insert("test".into(), 1.into());
            let array = vec![1.into(), 2.into(), 3.into()];
            Self { map, array }
        }
    }

    impl std::hash::Hash for Test {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            // Simplified hash for testing; use a proper one if Test needs to be a key in a HashMap itself.
            for k in self.map.keys() {
                std::hash::Hash::hash(k, state);
            }
            std::hash::Hash::hash(&self.array.len(), state);
        }
    }

    impl NativeObject for Test {
        fn as_accessible(&self) -> Option<&dyn Accessible> {
            Some(&self.map)
        }
        fn as_indexable(&self) -> Option<&dyn Indexable> {
            Some(&self.array)
        }
        fn as_callable(&self) -> Option<&dyn Callable> {
            None
        }
        fn as_evaluatable(&self) -> Option<&dyn Evaluatable> {
            None
        }
    }

    // --- Re-add tests from original stdlib.rs, ensuring they use correct paths ---
    op_test!(
        access_tuple,
        Access, // Now from super::control::Access via pub use
        [Value::Tuple(Arc::new(vec![1.into(), 2.into()])), 0.into()],
        1.into()
    );
    op_test!(
        access_hashmap,
        Access,
        [Test::new().into(), Value::Identifier("test".into())],
        1.into()
    );
    op_test!(index, Index, [Test::new().into(), 0.into()], 1.into());
    op_test!(not, Not, [false.into()], true.into());
    op_test!(bit_not, BitNot, [(!1234).into()], 1234.into());
    op_test!(negative, Negative, [1234.into()], (-1234).into());

    macro_rules! int_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, [1234.into(),4.into()], (1234 $op 4).into());
        };
    }

    int_op_test!(plus,Plus,+);
    int_op_test!(minus,Minus,-);
    int_op_test!(mul,Multiply,*);
    int_op_test!(div,Divide,/);
    int_op_test!(imod,Mod,%);
    int_op_test!(band,BitAnd,&);
    int_op_test!(bor,BitOr,|);
    int_op_test!(bxor,BitXor,^);
    int_op_test!(shl,ShiftLeft,<<);
    int_op_test!(shr,ShiftRight,>>);
    op_test!(
        shru,
        ShiftRightUnsigned,
        [1234.into(), 45.into()],
        ((1234u64 >> 45) as i64).into()
    );
    op_error_test!(
        shru_negative_shift,
        ShiftRightUnsigned,
        [10.into(), (-1).into()],
        "Shift amount for ShiftRightUnsigned must be between 0 and 63"
    );
    op_error_test!(
        shru_large_shift,
        ShiftRightUnsigned,
        [10.into(), 64.into()],
        "Shift amount for ShiftRightUnsigned must be between 0 and 63"
    );

    macro_rules! bool_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, [true.into(), false.into()], (true $op false).into());
        };
    }

    bool_op_test!(and,And,&&);
    bool_op_test!(or,Or,||);
    bool_op_test!(xor,Xor,^);

    macro_rules! cmp_op_test {
        ($name:ident, $fn:ident, $op:tt) => {
            op_test!($name, $fn, [1234.into(),4567.into()], (1234 $op 4567).into());
        };
    }

    cmp_op_test!(greater,Greater,>);
    cmp_op_test!(lesser,Lesser,<);
    cmp_op_test!(greater_or_equal,GreaterOrEqual,>=);
    cmp_op_test!(lesser_or_equal,LesserOrEqual,<=);
    cmp_op_test!(equal,Equal,==);
    cmp_op_test!(not_equal,NotEqual,!=);

    op_error_test!(
        greater_int_string,
        Greater,
        [1.into(), "hello".into()],
        "Comparison not implemented for these types"
    );
    op_error_test!(
        greater_string_int,
        Greater,
        ["hello".into(), 1.into()],
        "Comparison not implemented for these types"
    );
    op_error_test!(
        greater_bool_int,
        Greater,
        [true.into(), 1.into()],
        "Comparison not implemented for these types"
    );
    op_error_test!(
        lesser_int_string,
        Lesser,
        [1.into(), "hello".into()],
        "Comparison not implemented for these types"
    );
    op_error_test!(
        goe_int_string,
        GreaterOrEqual,
        [1.into(), "hello".into()],
        "Comparison not implemented for these types"
    );
    op_error_test!(
        loe_int_string,
        LesserOrEqual,
        [1.into(), "hello".into()],
        "Comparison not implemented for these types"
    );

    op_test!(like, Like, ["abc".into(), "a".into()], true.into());
    op_test!(not_like, NotLike, ["abc".into(), "a".into()], false.into());
    op_test!(
        is_member_of,
        IsMemberOf,
        [1.into(), vec![1.into()].into()],
        true.into()
    );
    op_test!(to_string, ToString, [false.into()], "false".into());
    op_test!(to_integer, ToInteger, ["1234".into()], 1234.into());
    op_test!(
        split,
        Split,
        ["1,2".into(), ",".into()],
        vec!["1".into(), "2".into()].into()
    );
    op_test!(
        string_concat,
        StringConcat,
        [vec!["1".into(), "2".into()].into()],
        "12".into()
    );

    op_error_test!(
        index_with_non_integer,
        Index,
        [Value::Array(Arc::new(vec![1.into()])), "a".into()],
        "Index not a integer type"
    );
    op_error_test!(
        index_on_non_indexable_script_value,
        Index,
        ["abc".into(), 0.into()],
        "Object does not implement Indexable"
    );
    op_error_test!(
        access_with_non_string_or_int_key_for_tuple,
        Access,
        [Value::Tuple(Arc::new(vec![1.into()])), true.into()],
        "Can not access a tuple with"
    );
    op_error_test!(
        access_native_with_non_identifier_val,
        Access,
        [Test::new().into(), true.into()],
        "Can not access a NativeObject with"
    );
    op_test!(
        is_member_of_empty_array,
        IsMemberOf,
        [1.into(), Value::Array(Arc::new(vec![]))],
        false.into()
    );
    op_error_test!(
        is_member_of_array_different_type,
        IsMemberOf,
        [1.into(), Value::Array(Arc::new(vec!["a".into()]))],
        "subject must have on same type with array"
    );
    op_error_test!(
        divide_by_zero_stdlib,
        Divide,
        [1.into(), 0.into()],
        "division by zero"
    );
    op_error_test!(
        mod_by_zero_stdlib,
        Mod,
        [1.into(), 0.into()],
        "division by zero"
    );
    op_error_test!(
        like_invalid_regex,
        Like,
        ["abc".into(), "[".into()],
        "failed to compile regex"
    );
    op_error_test!(
        to_integer_non_integer_string,
        ToInteger,
        ["abc".into()],
        "failed to parse integer: abc"
    );
    op_error_test!(
        to_integer_float_string,
        ToInteger,
        ["1.0".into()],
        "failed to parse integer: 1.0"
    );
    op_error_test!(
        to_integer_empty_string,
        ToInteger,
        ["".into()],
        "failed to parse integer: "
    );
    op_test!(
        split_by_empty_delimiter,
        Split,
        ["abc".into(), "".into()],
        Value::Array(Arc::new(vec![
            "".into(),
            "a".into(),
            "b".into(),
            "c".into(),
            "".into()
        ]))
    );
    op_test!(
        split_empty_string,
        Split,
        ["".into(), ",".into()],
        Value::Array(Arc::new(vec!["".into()]))
    );
    op_test!(
        split_by_delimiter_not_present,
        Split,
        ["abc".into(), "d".into()],
        Value::Array(Arc::new(vec!["abc".into()]))
    );
    op_test!(
        strcat_empty_array,
        StringConcat,
        [Value::Array(Arc::new(vec![]))],
        "".into()
    );
    op_test!(
        strcat_array_one_string,
        StringConcat,
        [Value::Array(Arc::new(vec!["a".into()]))],
        "a".into()
    );
    op_test!(
        strcat_array_with_empty_strings,
        StringConcat,
        [Value::Array(Arc::new(vec![
            "a".into(),
            "".into(),
            "b".into()
        ]))],
        "ab".into()
    );
    op_error_test!(
        strcat_array_non_string,
        StringConcat,
        [Value::Array(Arc::new(vec![1.into()]))],
        "type mismatch"
    );
    op_test!(
        and_op_true_true,
        And,
        [true.into(), true.into()],
        true.into()
    );
    op_test!(
        or_op_false_false,
        Or,
        [false.into(), false.into()],
        false.into()
    );
    op_test!(
        equal_different_types,
        Equal,
        [1.into(), "1".into()],
        false.into()
    );
    op_test!(
        not_equal_different_types,
        NotEqual,
        [1.into(), "1".into()],
        true.into()
    );

    op_test!(
        map_empty_array,
        Map,
        [
            Value::Array(Arc::new(vec![])),
            TestHelperAddOne::stub().into()
        ],
        Value::Array(Arc::new(vec![]))
    );
    op_test!(
        map_integers_add_one,
        Map,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into()])),
            TestHelperAddOne::stub().into()
        ],
        Value::Array(Arc::new(vec![2.into(), 3.into(), 4.into()]))
    );
    op_test!(
        map_integers_to_string,
        Map,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into()])),
            TestHelperToString::stub().into()
        ],
        Value::Array(Arc::new(vec![
            Value::String("1".into()),
            Value::String("2".into())
        ]))
    );
    op_test!(
        reduce_empty_array,
        Reduce,
        [
            Value::Array(Arc::new(vec![])),
            Value::Integer(10),
            TestHelperSum::stub().into()
        ],
        Value::Integer(10)
    );
    op_test!(
        reduce_integers_sum,
        Reduce,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into()])),
            Value::Integer(0),
            TestHelperSum::stub().into()
        ],
        Value::Integer(6)
    );
    op_test!(
        reduce_integers_sum_with_initial,
        Reduce,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into()])),
            Value::Integer(10),
            TestHelperSum::stub().into()
        ],
        Value::Integer(16)
    );
    op_test!(
        filter_empty_array,
        Filter,
        [
            Value::Array(Arc::new(vec![])),
            TestHelperIsEven::stub().into()
        ],
        Value::Array(Arc::new(vec![]))
    );
    op_test!(
        filter_integers_is_even,
        Filter,
        [
            Value::Array(Arc::new(vec![
                1.into(),
                2.into(),
                3.into(),
                4.into(),
                5.into()
            ])),
            TestHelperIsEven::stub().into()
        ],
        Value::Array(Arc::new(vec![2.into(), 4.into()]))
    );
    op_test!(
        filter_integers_keep_all,
        Filter,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into()])),
            TestHelperTrue::stub().into()
        ],
        Value::Array(Arc::new(vec![1.into(), 2.into()]))
    );
    op_test!(
        filter_integers_remove_all,
        Filter,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into()])),
            TestHelperFalse::stub().into()
        ],
        Value::Array(Arc::new(vec![]))
    );
    op_test!(
        find_empty_array,
        Find,
        [
            Value::Array(Arc::new(vec![])),
            TestHelperIsEven::stub().into()
        ],
        false.into()
    );
    op_test!(
        find_integer_is_even_found,
        Find,
        [
            Value::Array(Arc::new(vec![1.into(), 3.into(), 4.into(), 6.into()])),
            TestHelperIsEven::stub().into()
        ],
        4.into()
    );
    op_test!(
        find_integer_is_even_not_found,
        Find,
        [
            Value::Array(Arc::new(vec![1.into(), 3.into(), 5.into()])),
            TestHelperIsEven::stub().into()
        ],
        false.into()
    );
    op_test!(
        find_index_empty_array,
        FindIndex,
        [
            Value::Array(Arc::new(vec![])),
            TestHelperIsEven::stub().into()
        ],
        Value::Integer(-1)
    );
    op_test!(
        find_index_integer_is_even_found,
        FindIndex,
        [
            Value::Array(Arc::new(vec![1.into(), 3.into(), 4.into(), 6.into()])),
            TestHelperIsEven::stub().into()
        ],
        Value::Integer(2)
    );
    op_test!(
        find_index_integer_is_even_not_found,
        FindIndex,
        [
            Value::Array(Arc::new(vec![1.into(), 3.into(), 5.into()])),
            TestHelperIsEven::stub().into()
        ],
        Value::Integer(-1)
    );
    op_test!(
        for_each_empty_array,
        ForEach,
        [
            Value::Array(Arc::new(vec![])),
            TestHelperAddOne::stub().into()
        ],
        true.into()
    );
    op_test!(
        for_each_integers,
        ForEach,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into()])),
            TestHelperAddOne::stub().into()
        ],
        true.into()
    );
    op_test!(
        index_of_empty_array,
        IndexOf,
        [Value::Array(Arc::new(vec![])), 1.into(), 0.into()],
        Value::Integer(-1)
    );
    op_test!(
        index_of_found,
        IndexOf,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])),
            20.into(),
            0.into()
        ],
        Value::Integer(1)
    );
    op_test!(
        index_of_not_found,
        IndexOf,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])),
            40.into(),
            0.into()
        ],
        Value::Integer(-1)
    );
    op_test!(
        index_of_from_index_positive_found,
        IndexOf,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into(), 20.into()])),
            20.into(),
            2.into()
        ],
        Value::Integer(3)
    );
    op_test!(
        index_of_from_index_positive_not_found,
        IndexOf,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])),
            20.into(),
            2.into()
        ],
        Value::Integer(-1)
    );
    op_test!(
        index_of_from_index_negative_found,
        IndexOf,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])),
            10.into(),
            (-3).into()
        ],
        Value::Integer(0)
    );
    op_test!(
        index_of_from_index_negative_found_mid,
        IndexOf,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into(), 40.into()])),
            30.into(),
            (-2).into()
        ],
        Value::Integer(2)
    );
    op_test!(
        index_of_from_index_out_of_bounds_positive,
        IndexOf,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into()])),
            10.into(),
            5.into()
        ],
        Value::Integer(-1)
    );
    op_test!(
        index_of_from_index_out_of_bounds_negative,
        IndexOf,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into()])),
            10.into(),
            (-5).into()
        ],
        Value::Integer(0)
    );
    op_test!(
        includes_empty_array,
        Includes,
        [Value::Array(Arc::new(vec![])), 1.into(), 0.into()],
        Value::Boolean(false)
    );
    op_test!(
        includes_found,
        Includes,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])),
            20.into(),
            0.into()
        ],
        Value::Boolean(true)
    );
    op_test!(
        includes_not_found,
        Includes,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])),
            40.into(),
            0.into()
        ],
        Value::Boolean(false)
    );
    op_test!(
        includes_from_index_positive_found,
        Includes,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into(), 20.into()])),
            20.into(),
            2.into()
        ],
        Value::Boolean(true)
    );
    op_test!(
        includes_from_index_positive_not_found,
        Includes,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])),
            20.into(),
            2.into()
        ],
        Value::Boolean(false)
    );
    op_test!(
        includes_from_index_negative_found,
        Includes,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into(), 30.into()])),
            10.into(),
            (-3).into()
        ],
        Value::Boolean(true)
    );
    op_test!(
        includes_from_index_out_of_bounds_positive,
        Includes,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into()])),
            10.into(),
            5.into()
        ],
        Value::Boolean(false)
    );
    op_test!(
        includes_from_index_out_of_bounds_negative,
        Includes,
        [
            Value::Array(Arc::new(vec![10.into(), 20.into()])),
            10.into(),
            (-5).into()
        ],
        Value::Boolean(true)
    );
    op_test!(
        join_empty_array,
        Join,
        [Value::Array(Arc::new(vec![])), ",".into()],
        Value::String("".into())
    );
    op_test!(
        join_single_element,
        Join,
        [Value::Array(Arc::new(vec!["a".into()])), ",".into()],
        Value::String("a".into())
    );
    op_test!(
        join_multiple_elements,
        Join,
        [
            Value::Array(Arc::new(vec!["a".into(), "b".into(), "c".into()])),
            ",".into()
        ],
        Value::String("a,b,c".into())
    );
    op_test!(
        join_with_empty_separator,
        Join,
        [
            Value::Array(Arc::new(vec!["a".into(), "b".into(), "c".into()])),
            "".into()
        ],
        Value::String("abc".into())
    );
    op_test!(
        slice_empty_array,
        Slice,
        [Value::Array(Arc::new(vec![])), 0.into(), 0.into()],
        Value::Array(Arc::new(vec![]))
    );
    op_test!(
        slice_basic,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into(), 4.into()])),
            1.into(),
            3.into()
        ],
        Value::Array(Arc::new(vec![2.into(), 3.into()]))
    );
    op_test!(
        slice_to_end,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into(), 4.into()])),
            2.into(),
            4.into()
        ],
        Value::Array(Arc::new(vec![3.into(), 4.into()]))
    );
    op_test!(
        slice_from_beginning,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into(), 4.into()])),
            0.into(),
            2.into()
        ],
        Value::Array(Arc::new(vec![1.into(), 2.into()]))
    );
    op_test!(
        slice_negative_begin,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into(), 4.into()])),
            (-2).into(),
            4.into()
        ],
        Value::Array(Arc::new(vec![3.into(), 4.into()]))
    );
    op_test!(
        slice_negative_end,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into(), 4.into()])),
            1.into(),
            (-1).into()
        ],
        Value::Array(Arc::new(vec![2.into(), 3.into()]))
    );
    op_test!(
        slice_negative_begin_and_end,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into(), 4.into()])),
            (-3).into(),
            (-1).into()
        ],
        Value::Array(Arc::new(vec![2.into(), 3.into()]))
    );
    op_test!(
        slice_begin_out_of_bounds_positive,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into()])),
            5.into(),
            6.into()
        ],
        Value::Array(Arc::new(vec![]))
    );
    op_test!(
        slice_end_out_of_bounds_positive,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into()])),
            0.into(),
            5.into()
        ],
        Value::Array(Arc::new(vec![1.into(), 2.into()]))
    );
    op_test!(
        slice_begin_greater_than_end,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into()])),
            1.into(),
            0.into()
        ],
        Value::Array(Arc::new(vec![]))
    );
    op_test!(
        slice_full_array_clone,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into()])),
            0.into(),
            2.into()
        ],
        Value::Array(Arc::new(vec![1.into(), 2.into()]))
    );
    op_test!(
        slice_begin_equals_end,
        Slice,
        [
            Value::Array(Arc::new(vec![1.into(), 2.into(), 3.into()])),
            1.into(),
            1.into()
        ],
        Value::Array(Arc::new(vec![]))
    );

    op_test!(
        string_char_at_basic,
        StringCharAt,
        ["hello".into(), 1.into()],
        "e".into()
    );
    op_test!(
        string_char_at_start,
        StringCharAt,
        ["hello".into(), 0.into()],
        "h".into()
    );
    op_test!(
        string_char_at_end,
        StringCharAt,
        ["hello".into(), 4.into()],
        "o".into()
    );
    op_test!(
        string_char_at_out_of_bounds_positive,
        StringCharAt,
        ["hello".into(), 10.into()],
        "".into()
    );
    op_test!(
        string_char_code_at_basic,
        StringCharCodeAt,
        ["hello".into(), 1.into()],
        ('e' as i64).into()
    );
    op_test!(
        string_char_code_at_start,
        StringCharCodeAt,
        ["hello".into(), 0.into()],
        ('h' as i64).into()
    );
    op_test!(
        string_char_code_at_out_of_bounds_positive,
        StringCharCodeAt,
        ["hello".into(), 10.into()],
        Value::Integer(-1)
    );
    op_test!(
        string_ends_with_true,
        StringEndsWith,
        ["hello".into(), "lo".into(), 5.into()],
        true.into()
    );
    op_test!(
        string_ends_with_false,
        StringEndsWith,
        ["hello".into(), "lo".into(), 4.into()],
        false.into()
    );
    op_test!(
        string_ends_with_length_param,
        StringEndsWith,
        ["hello".into(), "o".into(), 4.into()],
        false.into()
    );
    op_test!(
        string_ends_with_full_match_with_len,
        StringEndsWith,
        ["hello".into(), "hell".into(), 4.into()],
        true.into()
    );
    op_test!(
        string_ends_with_empty_search,
        StringEndsWith,
        ["hello".into(), "".into(), 5.into()],
        true.into()
    );
    op_test!(
        string_includes_true,
        StringIncludes,
        ["hello world".into(), "world".into(), 0.into()],
        true.into()
    );
    op_test!(
        string_includes_false,
        StringIncludes,
        ["hello world".into(), "worldz".into(), 0.into()],
        false.into()
    );
    op_test!(
        string_includes_position_true,
        StringIncludes,
        ["hello world".into(), "world".into(), 5.into()],
        true.into()
    );
    op_test!(
        string_includes_position_false,
        StringIncludes,
        ["hello world".into(), "hello".into(), 5.into()],
        false.into()
    );
    op_test!(
        string_starts_with_true,
        StringStartsWith,
        ["hello".into(), "he".into(), 0.into()],
        true.into()
    );
    op_test!(
        string_starts_with_false,
        StringStartsWith,
        ["hello".into(), "hi".into(), 0.into()],
        false.into()
    );
    op_test!(
        string_starts_with_position_true,
        StringStartsWith,
        ["hello".into(), "ll".into(), 2.into()],
        true.into()
    );
    op_test!(
        string_starts_with_position_false,
        StringStartsWith,
        ["hello".into(), "he".into(), 2.into()],
        false.into()
    );
    op_test!(
        string_starts_with_empty_search,
        StringStartsWith,
        ["hello".into(), "".into(), 0.into()],
        true.into()
    );
    op_test!(
        string_index_of_found,
        StringIndexOf,
        ["hello".into(), "ll".into(), 0.into()],
        2.into()
    );
    op_test!(
        string_index_of_not_found,
        StringIndexOf,
        ["hello".into(), "x".into(), 0.into()],
        (-1).into()
    );
    op_test!(
        string_index_of_from_index_found,
        StringIndexOf,
        ["hello hello".into(), "h".into(), 1.into()],
        6.into()
    );
    op_test!(
        string_index_of_empty_search,
        StringIndexOf,
        ["hello".into(), "".into(), 0.into()],
        0.into()
    );
    op_test!(
        string_index_of_empty_search_at_len,
        StringIndexOf,
        ["hello".into(), "".into(), 5.into()],
        5.into()
    );
    op_test!(
        string_match_found,
        StringMatch,
        ["hello".into(), "l+".into()],
        Value::Array(Arc::new(vec!["ll".into()]))
    );
    op_test!(
        string_match_not_found,
        StringMatch,
        ["hello".into(), "x+".into()],
        Value::Array(Arc::new(vec![]))
    );
    op_test!(
        string_match_optional_group_not_matched,
        StringMatch,
        ["hello".into(), "(\\w+)( \\d+)?".into()],
        Value::Array(Arc::new(vec!["hello".into(), "hello".into(), "".into()]))
    );
    op_test!(
        string_match_with_groups,
        StringMatch,
        ["hello 123".into(), "(\\w+) (\\d+)".into()],
        Value::Array(Arc::new(vec![
            "hello 123".into(),
            "hello".into(),
            "123".into()
        ]))
    );
    op_test!(
        string_replace_literal,
        StringReplace,
        ["hello world".into(), "world".into(), "Rust".into()],
        "hello Rust".into()
    );
    op_test!(
        string_replace_literal_no_match,
        StringReplace,
        ["hello".into(), "x".into(), "y".into()],
        "hello".into()
    );
    op_test!(
        string_replace_unicode_pattern,
        StringReplace,
        ["😊😊".into(), "😊".into(), "X".into()],
        "X😊".into()
    );
    op_test!(
        string_replace_unicode_pattern_no_match,
        StringReplace,
        ["ab".into(), "😊".into(), "X".into()],
        "ab".into()
    );
    op_test!(
        string_replace_unicode_text,
        StringReplace,
        ["hello😊world".into(), "😊".into(), "X".into()],
        "helloXworld".into()
    );
    op_test!(
        string_replace_empty_pattern,
        StringReplace,
        ["abc".into(), "".into(), "X".into()],
        "abc".into()
    );
    op_test!(
        string_replace_regex_first,
        StringReplaceRegex,
        ["abab".into(), "b".into(), "c".into()],
        "acac".into()
    );
    op_test!(
        string_replace_regex_all,
        StringReplaceRegex,
        ["abab".into(), "b".into(), "c".into()],
        "acac".into()
    );
    op_test!(
        string_replace_regex_groups_not_supported_yet,
        StringReplaceRegex,
        ["hello 123".into(), "(\\w+) (\\d+)".into(), "$2 $1".into()],
        "123 hello".into()
    );
    op_test!(
        string_slice_basic,
        StringSlice,
        ["hello".into(), 1.into(), 4.into()],
        "ell".into()
    );
    op_test!(
        string_slice_negative_begin,
        StringSlice,
        ["hello".into(), (-3).into(), 4.into()],
        "ll".into()
    );
    op_test!(
        string_slice_negative_end,
        StringSlice,
        ["hello".into(), 1.into(), (-1).into()],
        "ell".into()
    );
    op_test!(
        string_slice_begin_greater_than_end,
        StringSlice,
        ["hello".into(), 3.into(), 1.into()],
        "".into()
    );
    op_test!(
        string_slice_full,
        StringSlice,
        ["hello".into(), 0.into(), 5.into()],
        "hello".into()
    );
    op_test!(
        string_substring_basic,
        StringSubstring,
        ["hello".into(), 1.into(), 4.into()],
        "ell".into()
    );
    op_test!(
        string_substring_start_greater_than_end,
        StringSubstring,
        ["hello".into(), 4.into(), 1.into()],
        "ell".into()
    );
    op_test!(
        string_substring_negative_treated_as_zero,
        StringSubstring,
        ["hello".into(), (-2).into(), 3.into()],
        "hel".into()
    );
    op_test!(
        string_substring_index_out_of_bounds,
        StringSubstring,
        ["hello".into(), 0.into(), 10.into()],
        "hello".into()
    );
    op_test!(
        string_lower_case,
        StringLowerCase,
        ["HeLlO".into()],
        "hello".into()
    );
    op_test!(
        string_upper_case,
        StringUpperCase,
        ["HeLlO".into()],
        "HELLO".into()
    );
    op_test!(
        string_trim_basic,
        StringTrim,
        ["  hello  ".into()],
        "hello".into()
    );
    op_test!(
        string_trim_no_whitespace,
        StringTrim,
        ["hello".into()],
        "hello".into()
    );
    op_test!(
        string_trim_only_whitespace,
        StringTrim,
        ["   ".into()],
        "".into()
    );

    op_error_test!(
        map_non_array_arg,
        Map,
        [1.into(), TestHelperAddOne::stub().into()],
        "argument array type mismatch"
    );
    op_error_test!(
        map_non_function_callback,
        Map,
        [Value::Array(Arc::new(vec![])), 1.into()],
        "Second argument to map must be a function"
    );
    op_error_test!(
        reduce_non_array_arg,
        Reduce,
        [1.into(), 0.into(), TestHelperSum::stub().into()],
        "argument array type mismatch"
    );
    op_error_test!(
        reduce_non_function_callback,
        Reduce,
        [Value::Array(Arc::new(vec![])), 0.into(), 1.into()],
        "Third argument to reduce must be a function"
    );
    op_error_test!(
        filter_non_array_arg,
        Filter,
        [1.into(), TestHelperIsEven::stub().into()],
        "argument array type mismatch"
    );
    op_error_test!(
        filter_non_function_callback,
        Filter,
        [Value::Array(Arc::new(vec![])), 1.into()],
        "Second argument to filter must be a function"
    );
    op_error_test!(
        filter_callback_returns_non_boolean,
        Filter,
        [
            Value::Array(Arc::new(vec![1.into()])),
            TestHelperAddOne::stub().into()
        ],
        "Filter function must return a Boolean"
    );
    op_error_test!(
        find_non_array_arg,
        Find,
        [1.into(), TestHelperIsEven::stub().into()],
        "argument array type mismatch"
    );
    op_error_test!(
        find_non_function_callback,
        Find,
        [Value::Array(Arc::new(vec![])), 1.into()],
        "Second argument to find must be a function"
    );
    op_error_test!(
        find_callback_returns_non_boolean,
        Find,
        [
            Value::Array(Arc::new(vec![1.into()])),
            TestHelperAddOne::stub().into()
        ],
        "Find function must return a Boolean"
    );
    op_error_test!(
        find_index_non_array_arg,
        FindIndex,
        [1.into(), TestHelperIsEven::stub().into()],
        "argument array type mismatch"
    );
    op_error_test!(
        find_index_non_function_callback,
        FindIndex,
        [Value::Array(Arc::new(vec![])), 1.into()],
        "Second argument to findIndex must be a function"
    );
    op_error_test!(
        find_index_callback_returns_non_boolean,
        FindIndex,
        [
            Value::Array(Arc::new(vec![1.into()])),
            TestHelperAddOne::stub().into()
        ],
        "FindIndex function must return a Boolean"
    );
    op_error_test!(
        for_each_non_array_arg,
        ForEach,
        [1.into(), TestHelperAddOne::stub().into()],
        "argument array type mismatch"
    );
    op_error_test!(
        for_each_non_function_callback,
        ForEach,
        [Value::Array(Arc::new(vec![])), 1.into()],
        "Second argument to forEach must be a function"
    );
    op_error_test!(
        index_of_non_array_arg,
        IndexOf,
        [1.into(), 1.into(), 0.into()],
        "argument array type mismatch"
    );
    op_error_test!(
        index_of_non_integer_from_index,
        IndexOf,
        [Value::Array(Arc::new(vec![])), 1.into(), "a".into()],
        "argument from_index type mismatch"
    );
    op_error_test!(
        includes_non_array_arg,
        Includes,
        [1.into(), 1.into(), 0.into()],
        "argument array type mismatch"
    );
    op_error_test!(
        includes_non_integer_from_index,
        Includes,
        [Value::Array(Arc::new(vec![])), 1.into(), "a".into()],
        "argument from_index type mismatch"
    );
    op_error_test!(
        join_non_array_arg,
        Join,
        [1.into(), ",".into()],
        "argument array type mismatch"
    );
    op_error_test!(
        join_non_string_separator,
        Join,
        [Value::Array(Arc::new(vec![])), 1.into()],
        "argument separator type mismatch"
    );
    op_error_test!(
        slice_non_array_arg,
        Slice,
        [1.into(), 0.into(), 1.into()],
        "argument array type mismatch"
    );
    op_error_test!(
        slice_non_integer_begin,
        Slice,
        [Value::Array(Arc::new(vec![])), "a".into(), 1.into()],
        "argument begin_index type mismatch"
    );
    op_error_test!(
        slice_non_integer_end,
        Slice,
        [Value::Array(Arc::new(vec![])), 0.into(), "a".into()],
        "argument end_index type mismatch"
    );
    op_error_test!(
        string_char_at_non_string,
        StringCharAt,
        [1.into(), 0.into()],
        "argument text type mismatch"
    );
    op_error_test!(
        string_char_at_non_integer_index,
        StringCharAt,
        ["hi".into(), "a".into()],
        "argument index type mismatch"
    );
    op_error_test!(
        string_char_at_negative_index,
        StringCharAt,
        ["hello".into(), (-1).into()],
        "Index out of bounds: index cannot be negative"
    );
    op_error_test!(
        string_char_code_at_non_string,
        StringCharCodeAt,
        [1.into(), 0.into()],
        "argument text type mismatch"
    );
    op_error_test!(
        string_char_code_at_non_integer_index,
        StringCharCodeAt,
        ["hi".into(), "a".into()],
        "argument index type mismatch"
    );
    op_error_test!(
        string_char_code_at_negative_index,
        StringCharCodeAt,
        ["hello".into(), (-1).into()],
        "Index out of bounds: index cannot be negative"
    );
    op_error_test!(
        string_match_invalid_regex,
        StringMatch,
        ["hello".into(), "[".into()],
        "Invalid regex pattern"
    );
    op_error_test!(
        string_replace_regex_invalid_regex,
        StringReplaceRegex,
        ["h".into(), "[".into(), "a".into()],
        "Invalid regex pattern"
    );
}
