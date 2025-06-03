// Adjust use statements to new module structure
// super::super::parser::parse will be crate::parser::parse
// super::* will try to import from crate::script::* (due to re-exports in script/mod.rs)
use crate::parser::parse;
use crate::script::*; // This should bring in Value, Type, ScriptContext, etc.
use easy_error::{bail, Error}; // Error is used by the NativeObject impls in test_utils
use super::test_utils::*; // Import the NativeObject impls

use std::collections::HashSet; // Keep for unresovled_ids test
use std::sync::Arc; // Keep for Arc usage in tests

// NativeObject impls and related structs have been moved to test_utils.rs

macro_rules! eval_test {
    ($input: expr, $output: expr) => {{
        let ctx = ScriptContext::default_ref(); // Use helper for ScriptContextRef
        let parsed_value =
            parse($input).unwrap_or_else(|e| panic!("Parse error for '{}': {:?}", $input, e));
        let value = parsed_value
            .value_of(ctx)
            .await
            .unwrap_or_else(|e| panic!("Eval error for '{}': {:?}", $input, e));
        assert_eq!(value, $output);
    }};
}

macro_rules! eval_error_test {
    ($input: expr, $expected_error_substring: expr) => {{
        let ctx = ScriptContext::default_ref(); // Use helper for ScriptContextRef
        let parsed_value =
            parse($input).unwrap_or_else(|e| panic!("Parse error for '{}': {:?}", $input, e));
        let result = parsed_value.value_of(ctx).await;
        assert!(
            result.is_err(),
            "Expected error for '{}', but got Ok({:?})",
            $input,
            result.as_ref().ok()
        );
        let error_message = result.err().unwrap().to_string();
        assert!(
            error_message.contains($expected_error_substring),
            "Error message for '{}' was '{}', expected to contain '{}'",
            $input,
            error_message,
            $expected_error_substring
        );
    }};
}

macro_rules! assert_eval_and_type {
    ($input:expr, $expected_value:expr, $expected_type:expr) => {
        {
            async {
                let ctx = ScriptContext::default_ref();
                let parsed_script = match parse($input) {
                    Ok(script) => script,
                    Err(e) => panic!("Parse error for '{}': {:?}", $input, e),
                };

                // Check value
                match parsed_script.value_of(ctx.clone()).await {
                    Ok(value) => assert_eq!(value, $expected_value, "Evaluation failed for '{}'", $input),
                    Err(e) => panic!("Eval error for '{}': {:?}", $input, e),
                };

                // Check type
                match parsed_script.type_of(ctx).await {
                    Ok(value_type) => assert_eq!(value_type, $expected_type, "Type check failed for '{}'", $input),
                    Err(e) => panic!("Type check error for '{}': {:?}", $input, e),
                };
            }
        }
    };
}

async fn type_test(input: &str, output: Type) {
    let ctx = ScriptContext::default_ref(); // Use helper for ScriptContextRef
    let parsed_value =
        parse(input).unwrap_or_else(|e| panic!("Parse error for '{}': {:?}", input, e));
    let value_type = parsed_value.type_of(ctx).await.unwrap();
    assert_eq!(value_type, output);
}

// Helper for creating default ScriptContextRef, as Default::default() gives ScriptContext
// This might need to be part of ScriptContext impl if not already.
// For now, local helper for tests.
impl ScriptContext {
    fn default_ref() -> ScriptContextRef {
        Arc::new(Default::default())
    }
}

// Helper function to create a script context and register a native object.
fn create_context_with_native_object<T: NativeObject + 'static>(
    name: &str,
    object: T,
) -> ScriptContextRef {
    let mut ctx_instance = ScriptContext::new(Some(ScriptContext::default_ref()));
    ctx_instance.set(name.into(), object.into());
    Arc::new(ctx_instance)
}

// Helper function to create a script context and register a variable.
fn create_context_with_variable(name: &str, value: Value) -> ScriptContextRef {
    let mut ctx_instance = ScriptContext::new(Some(ScriptContext::default_ref()));
    ctx_instance.set(name.into(), value);
    Arc::new(ctx_instance)
}

#[tokio::test]
async fn one_plus_one() {
    assert_eval_and_type!("1+1", Value::Integer(2), Type::Integer).await;
}

#[tokio::test]
async fn to_string() {
    assert_eval_and_type!("to_string(100*2)", Value::String("200".to_string()), Type::String).await;
}

#[test]
fn unresovled_ids() {
    let value = parse("let a=1;b=2 in a+b").unwrap();
    let mut unresovled_ids = HashSet::new();
    value.unresovled_ids(&mut unresovled_ids);
    assert!(
        unresovled_ids.is_empty(),
        "Test 1 failed: expected empty, got {:?}",
        unresovled_ids
    );

    let value = parse("let a=1;b=a+1 in a+b+c").unwrap();
    let mut unresovled_ids = HashSet::new();
    value.unresovled_ids(&mut unresovled_ids);
    assert_eq!(
        unresovled_ids.len(),
        2,
        "Test 2 failed: Expected 2 unresolved IDs, got {:?} with count {}",
        unresovled_ids,
        unresovled_ids.len()
    );
    assert!(
        unresovled_ids.contains(&Value::Identifier("a".into())),
        "Test 2 failed: expected 'a' to be unresolved"
    );
    assert!(
        unresovled_ids.contains(&Value::Identifier("c".into())),
        "Test 2 failed: expected 'c' to be unresolved"
    );
}

#[tokio::test]
async fn arrays() {
    type_test("[1,2,3]", Type::array_of(Type::Integer)).await;
    eval_test!(
        "[if 1>2||1==1 then 1*1 else 99,2*2,3*3,to_integer(\"4\")][0]",
        1.into()
    )
}

#[tokio::test]
async fn array_type() {
    let input = "[1,\"true\",false]";
    let ctx = ScriptContext::default_ref();
    let parsed_value = parse(input).unwrap();
    let value_type_result = parsed_value.type_of(ctx).await;
    assert!(value_type_result.is_err());
}

#[tokio::test]
async fn ctx_chain() {
    let ctx_arc = create_context_with_variable("a", 1.into());
    let value = parse("a+1").unwrap().value_of(ctx_arc).await.unwrap();
    assert_eq!(value, 2.into());
}

#[tokio::test]
async fn scope() {
    assert_eval_and_type!("let a=1;b=2 in a+b", Value::Integer(3), Type::Integer).await;
}

#[tokio::test]
async fn access_tuple() {
    assert_eval_and_type!("(1,\"2\",false).1", Value::String("2".to_string()), Type::String).await;
}

#[tokio::test]
async fn strcat() {
    assert_eval_and_type!(
        r#" strcat(["1","2",to_string(3)]) "#,
        Value::String("123".to_string()),
        Type::String
    )
    .await;
}

#[tokio::test]
async fn template() {
    assert_eval_and_type!(
        r#" `x=
${to_string(1+2)}` "#,
        Value::String("x=\n3".to_string()),
        Type::String
    )
    .await;
}

#[tokio::test]
async fn native_objects() {
    let ctx_arc = create_context_with_native_object("a", ("xx".to_owned(), 1));
    let value = parse("a.length+1+a.x")
        .unwrap()
        .value_of(ctx_arc.clone())
        .await
        .unwrap();
    assert_eq!(value, 4.into());
    let value = parse("a[a.x] > 200 ? a : \"yy\"")
        .unwrap()
        .value_of(ctx_arc)
        .await
        .unwrap();
    assert_eq!(value, "yy".into());
}

#[tokio::test]
async fn eval_simple_function_call() {
    assert_eval_and_type!("let f(a) = a + 1 in f(5)", Value::Integer(6), Type::Integer).await;
}

#[tokio::test]
async fn eval_function_multiple_args() {
    assert_eval_and_type!("let add(x, y) = x + y in add(3, 4)", Value::Integer(7), Type::Integer).await;
}

#[tokio::test]
async fn eval_function_no_args() {
    assert_eval_and_type!("let get_num() = 42 in get_num()", Value::Integer(42), Type::Integer).await;
}

#[tokio::test]
async fn eval_closure_lexical_scoping() {
    assert_eval_and_type!("let x = 10; f(a) = a + x in f(5)", Value::Integer(15), Type::Integer).await;
    assert_eval_and_type!("let x = 10; f() = x * 2 in f()", Value::Integer(20), Type::Integer).await;
}

#[tokio::test]
async fn eval_closure_arg_shadows_outer_scope() {
    assert_eval_and_type!("let x = 10; f(x) = x + 1 in f(5)", Value::Integer(6), Type::Integer).await;
}

#[tokio::test]
async fn eval_closure_inner_let_shadows_outer_scope() {
    assert_eval_and_type!(
        "let x = 10; f() = (let x = 5 in x + 1) in f()",
        Value::Integer(6),
        Type::Integer
    )
    .await;
    assert_eval_and_type!(
        "let x = 10; f() = (let y = 5 in x + y) in f()",
        Value::Integer(15),
        Type::Integer
    )
    .await;
}

#[tokio::test]
async fn eval_recursive_function_factorial() {
    assert_eval_and_type!(
        "let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(3)",
        Value::Integer(6),
        Type::Integer
    )
    .await;
    assert_eval_and_type!(
        "let fac(n) = if n == 0 then 1 else n * fac(n - 1) in fac(0)",
        Value::Integer(1),
        Type::Integer
    )
    .await;
}

#[tokio::test]
async fn eval_mutually_recursive_functions() {
    // Type of the `in` expression for `is_even(4)` is Boolean.
    // The type_test was Type::Integer, which seems incorrect for the expression result.
    // Assuming Type::Boolean is the correct expected type for the `in` expression's result.
    let script_even = "let is_even(n) = if n == 0 then true else is_odd(n - 1); is_odd(n) = if n == 0 then false else is_even(n - 1) in is_even(4)";
    assert_eval_and_type!(script_even, Value::Boolean(true), Type::Boolean).await;

    // Similarly for `is_odd(3)`
    let script_odd = "let is_even(n) = if n == 0 then true else is_odd(n - 1); is_odd(n) = if n == 0 then false else is_even(n - 1) in is_odd(3)";
    assert_eval_and_type!(script_odd, Value::Boolean(true), Type::Boolean).await;
}

#[tokio::test]
async fn eval_function_uses_another_in_same_block() {
    assert_eval_and_type!("let g() = 10; f(a) = a + g() in f(5)", Value::Integer(15), Type::Integer).await;
}

#[tokio::test]
async fn test_call_non_existent_function() {
    eval_error_test!("non_existent_func()", "\"non_existent_func\" is undefined");
}

#[tokio::test]
async fn test_call_non_callable_value() {
    eval_error_test!("let x = 10 in x()", "is not a callable function type");
}

#[tokio::test]
async fn test_incorrect_arg_count_udf() {
    eval_error_test!("let f(a) = a in f(1,2)", "expected 1 arguments, got 2");
}

#[tokio::test]
async fn test_type_mismatch_binary_op() {
    eval_error_test!("1 + \"hello\"", "type mismatch");
}

#[tokio::test]
async fn test_index_out_of_bounds_array() {
    eval_error_test!("[1,2][2]", "index out of bounds: 2");
    eval_error_test!("[1,2][-3]", "index out of bounds");
}

#[tokio::test]
async fn test_index_out_of_bounds_tuple() {
    eval_error_test!("(1,2).2", "index out of bounds: 2");
    eval_error_test!("(1,2).-3", "index out of bounds");
}

#[tokio::test]
async fn test_access_non_existent_property_native() {
    let ctx_arc = create_context_with_native_object("no_simple", TestNativeSimple);
    let parsed = parse("no_simple.invalid_prop").unwrap();
    let res = parsed.value_of(ctx_arc).await;
    assert!(res.is_err());
    assert!(res
        .err()
        .unwrap()
        .to_string()
        .contains("no such property: invalid_prop"));
}

#[tokio::test]
async fn test_division_by_zero() {
    eval_error_test!("1 / 0", "division by zero");
}

#[tokio::test]
async fn test_modulo_by_zero() {
    eval_error_test!("1 % 0", "division by zero");
}

#[tokio::test]
async fn test_variable_shadowing_and_unshadowing() {
    eval_test!("let x = 1 in (let x = 2 in x) + x", Value::Integer(3));
    eval_test!(
        "let x = 1 in let y = (let x = 2 in x) + x in y",
        Value::Integer(3)
    );
}

#[tokio::test]
async fn test_variable_redefinition_in_let_block() {
    eval_test!("let a = 1; a = 2 in a", Value::Integer(2));
}

#[tokio::test]
async fn test_native_object_failing_get() {
    let ctx_arc = create_context_with_native_object("native_fail_get", TestNativeFailingAccess);
    let parsed = parse("native_fail_get.prop_that_fails").unwrap();
    let res = parsed.value_of(ctx_arc).await;
    assert!(res.is_err());
    assert!(res
        .err()
        .unwrap()
        .to_string()
        .contains("native error on get for prop_that_fails"));
}

#[tokio::test]
async fn test_native_object_failing_call() {
    let ctx_arc = create_context_with_native_object("native_fail_call", TestNativeFailingCall);
    let parsed = parse("native_fail_call()").unwrap();
    let res = parsed.value_of(ctx_arc).await;
    assert!(res.is_err());
    assert!(res
        .err()
        .unwrap()
        .to_string()
        .contains("native error on call"));
}

#[tokio::test]
async fn test_to_string_empty_array() {
    eval_test!("to_string([])", Value::String("[]".to_string()));
}

#[tokio::test]
async fn test_to_string_mixed_array() {
    eval_test!("to_string([1, 2])", Value::String("[1,2]".to_string()));
    eval_test!(
        "to_string([\"a\", \"b\"])",
        Value::String("[\"a\",\"b\"]".to_string())
    );
}

#[tokio::test]
async fn test_to_string_empty_tuple() {
    eval_test!("to_string(())", Value::String("()".to_string()));
}

#[tokio::test]
async fn test_to_string_mixed_tuple() {
    eval_test!(
        "to_string((1, \"a\"))",
        Value::String("(1,\"a\")".to_string())
    );
}

#[tokio::test]
async fn test_to_string_complex_expression_result() {
    eval_test!("to_string(let x=1 in x+1)", Value::String("2".to_string()));
    eval_test!(
        "to_string(if true then \"hello\" else \"world\")",
        Value::String("\"hello\"".to_string())
    );
}
