#[cfg(test)]
mod tests {
    use crate::parser::parse;
    // For Not, Plus, etc. types used by macros
    use crate::script::{ParsedFunction, Value};
    use std::sync::Arc;

    // Import ALL necessary macros from crate root (exported from test_utils)
    use crate::{
        access,
        and,
        array,
        band,
        bit_not,
        bool,
        bor,
        branch,
        bxor,
        call,
        div,
        equal, // Unary & Binary op macros
        id,
        index,
        int,
        member_of,
        minus,
        mul,
        neg,
        not,
        or,
        plus,
        scope,
        str,
        strcat, // Other specific operation macros
        tuple,  // Basic value macros
    };

    #[inline]
    fn assert_ast(input: &str, value: Value) {
        let output = parse(input);
        println!("input={}\noutput={:?}", input, output);
        assert_eq!(output.unwrap(), value);
    }

    #[test]
    fn simple_op() {
        let input = "x+1";
        let value = plus!(id!("x"), int!(1));
        assert_ast(input, value);
    }

    #[test]
    fn root_is_value() {
        let input = "x";
        let value = id!("x");
        assert_ast(input, value);
        let input = "\r\n\t x \r\n\t ";
        let value = id!("x");
        assert_ast(input, value);
        let input = " ( ( ( ( x ) ) ) ) ";
        let value = id!("x");
        assert_ast(input, value);
    }

    #[test]
    fn opreator_priority() {
        let input = "1 && ( 2 ) || 3 == 4";
        let value = or!(and!(int!(1), int!(2)), equal!(int!(3), int!(4)));
        assert_ast(input, value);
        let input = "1 ^ 4 & ( 2 | 3 )";
        let value = { bxor!(int!(1), band!(int!(4), bor!(int!(2), int!(3)))) };
        assert_ast(input, value);
    }

    #[test]
    fn op_8() {
        let input = "a(b).c[d]";
        let value = index!(access!(call!(id!("a"), id!("b")), id!("c")), id!("d"));
        assert_ast(input, value);
    }

    #[test]
    fn op_7() {
        let input = " ! ! ( ~ true ) ";
        let value = not!(not!(bit_not!(bool!(true))));
        assert_ast(input, value);
    }

    #[test]
    fn op_6() {
        let input = "1 * 1 / -2";
        let value = div!(mul!(int!(1), int!(1)), neg!(int!(2)));
        assert_ast(input, value);
    }

    #[test]
    fn op_5() {
        let input = "1+1-2";
        let value = minus!(plus!(int!(1), int!(1)), int!(2));
        assert_ast(input, value);
    }

    #[test]
    fn template_string() {
        let input = "`a=${1+1}`";
        let value = strcat!(array!(str!("a="), plus!(int!(1), int!(1))));
        assert_ast(input, value);
        let input = r#"`a=\${a}`"#;
        let value = strcat!(array!(str!("a="), str!("$"), str!("{a}")));
        assert_ast(input, value);
        let input = "`a=${`x=${x}`}`";
        let value = strcat!(array!(str!("a="), strcat!(array!(str!("x="), id!("x")))));
        assert_ast(input, value);
    }

    #[test]
    fn tuple_array() {
        let input = "[ ( ) , ( ( 1 ) , ) , ( 1 , 2 ) , ( 1 , 2 , ) ]";
        let value = array!(
            tuple!(),
            tuple!(int!(1)),
            tuple!(int!(1), int!(2)),
            tuple!(int!(1), int!(2))
        );
        assert_ast(input, value);
    }

    #[test]
    fn test_branch_rules() {
        // Renamed from fn branch()
        let input = "if a then b else if c then d else e";
        let value = branch!(id!("a"), id!("b"), branch!(id!("c"), id!("d"), id!("e")));
        assert_ast(input, value);
        let input = "if if a then b else c then d else e";
        let value = branch!(branch!(id!("a"), id!("b"), id!("c")), id!("d"), id!("e"));
        assert_ast(input, value);
        let input = "(a ? b : c) ? d : e";
        let value = branch!(branch!(id!("a"), id!("b"), id!("c")), id!("d"), id!("e"));
        assert_ast(input, value);
    }

    #[test]
    fn test_scope_rules() {
        // Renamed from fn scope()
        let value: Value = scope!(
            array!(tuple!(id!("a"), int!(1)), tuple!(id!("b"), int!(2))),
            plus!(id!("a"), id!("b"))
        );
        let input = "let a=1;b=2 in a+b";
        assert_ast(input, value.clone());
        let input = "let a=1;b=2; in a+b";
        assert_ast(input, value);
    }

    #[test]
    fn comments() {
        let input = "if #comments\r\n a /* \r\n /* */then/**/b else c";
        let value = branch!(id!("a"), id!("b"), id!("c"));
        assert_ast(input, value);
        let input = r#" [
            " #not a comment ",
            " /* also not a comment " , " */"
        ]"#;
        let value = array!(
            str!(" #not a comment "),
            str!(" /* also not a comment "),
            str!(" */")
        );
        assert_ast(input, value);
    }

    #[test]
    fn complex() {
        let input = " 1 _: [ \"test\" , 0x1 , 0b10 , 0o3 , false , if xyz == 1 then 2 else 3] ";
        let value = {
            member_of!(
                int!(1),
                array!(
                    str!("test"),
                    int!(1),
                    int!(2),
                    int!(3),
                    bool!(false),
                    branch!(equal!(id!("xyz"), int!(1)), int!(2), int!(3))
                )
            )
        };
        assert_ast(input, value);
    }

    #[test]
    fn parse_simple_function_definition() {
        let input = "let f(a) = a + 1 in f(5)";
        let expected_vars = array!(Value::ParsedFunction(Arc::new(ParsedFunction {
            name_ident: id!("f"),
            arg_idents: vec![id!("a")],
            body: plus!(id!("a"), int!(1)),
        })));
        let expected_expr_in_scope = call!(id!("f"), int!(5));
        let expected_value = scope!(expected_vars, expected_expr_in_scope);
        assert_ast(input, expected_value);
    }

    #[test]
    fn parse_function_definition_multiple_args() {
        let input = "let add(x, y) = x + y in add(3, 4)";
        let expected_vars = array!(Value::ParsedFunction(Arc::new(ParsedFunction {
            name_ident: id!("add"),
            arg_idents: vec![id!("x"), id!("y")],
            body: plus!(id!("x"), id!("y")),
        })));
        let expected_expr_in_scope = call!(id!("add"), int!(3), int!(4));
        let expected_value = scope!(expected_vars, expected_expr_in_scope);
        assert_ast(input, expected_value);
    }

    #[test]
    fn parse_function_definition_no_args() {
        let input = "let get_num() = 42 in get_num()";
        let expected_vars = array!(Value::ParsedFunction(Arc::new(ParsedFunction {
            name_ident: id!("get_num"),
            arg_idents: vec![],
            body: int!(42),
        })));
        let expected_expr_in_scope = call!(vec![id!("get_num")]); // Corrected: pass a Vec<Value>
        let expected_value = scope!(expected_vars, expected_expr_in_scope);
        assert_ast(input, expected_value);
    }

    #[test]
    fn parse_function_definition_mixed_with_vars() {
        let input = "let a = 1; f(b) = b + a; c = 2 in f(c)";
        let expected_vars = array!(
            tuple!(id!("a"), int!(1)),
            Value::ParsedFunction(Arc::new(ParsedFunction {
                name_ident: id!("f"),
                arg_idents: vec![id!("b")],
                body: plus!(id!("b"), id!("a")),
            })),
            tuple!(id!("c"), int!(2))
        );
        let expected_expr_in_scope = call!(id!("f"), id!("c"));
        let expected_value = scope!(expected_vars, expected_expr_in_scope);
        assert_ast(input, expected_value);
    }

    #[test]
    fn parse_standalone_function_assignment() {
        let input = "f(a) = a + 1";
        let expected_value = Value::ParsedFunction(Arc::new(ParsedFunction {
            name_ident: id!("f"),
            arg_idents: vec![id!("a")],
            body: plus!(id!("a"), int!(1)),
        }));
        assert_ast(input, expected_value);
    }

    #[test]
    fn test_unmatched_parentheses() {
        assert!(parse("(1 + 2").is_err());
        assert!(parse("1 + 2)").is_err());
        assert!(parse("((1 + 2").is_err());
    }

    #[test]
    fn test_incomplete_expressions() {
        assert!(parse("let a = ;").is_err());
        assert!(parse("1 +").is_err());
        assert!(parse("a ==").is_err());
    }

    #[test]
    fn test_invalid_operator_usage() {
        assert!(parse("1 + * 2").is_err());
        assert!(parse("1 ** 2").is_err());
        assert!(parse("/ 2").is_err());
    }

    #[test]
    fn test_malformed_integer_literals() {
        assert!(parse("0xZ").is_err());
        assert!(parse("0b3").is_err());
        assert!(parse("0o9").is_err());
        assert!(parse("1_").is_err());
    }

    #[test]
    fn test_errors_in_let_bindings() {
        assert!(parse("let a in expr").is_err());
        assert!(parse("let = 1 in expr").is_err());
        assert!(parse("let a = 1 expr").is_err());
        assert!(parse("leta = 1 in expr").is_err());
    }

    #[test]
    fn test_errors_in_function_definitions() {
        assert!(parse("let f() = ; in f()").is_err());
        assert!(parse("let f(a b) = a+b in f(1,2)").is_err());
        assert!(parse("let f(a,) = a in f(1)").is_err());
        assert!(parse("f(a) = ").is_err());
    }

    #[test]
    fn test_integer_formats() {
        assert_ast("0b1010", int!(10));
        assert_ast("0o12", int!(10));
        assert_ast("0xCafe", int!(51966));
        assert_ast("0b1_010", int!(10));
        assert_ast("0o1_2", int!(10));
        assert_ast("0xCa_fe", int!(51966));
        assert_ast("1_000_000", int!(1000000));
    }

    #[test]
    fn test_empty_array() {
        assert_ast("[]", array!());
    }

    #[test]
    fn test_array_with_trailing_comma() {
        assert_ast("[1,]", array!(int!(1)));
        assert_ast("[1,2,]", array!(int!(1), int!(2)));
    }

    #[test]
    fn test_tuple_with_trailing_comma() {
        assert_ast("(1,2,)", tuple!(int!(1), int!(2)));
    }

    #[test]
    fn test_comment_at_end_of_input() {
        assert_ast("1 + 1 # This is a comment", plus!(int!(1), int!(1)));
        assert_ast("1 + 1 /* block comment */", plus!(int!(1), int!(1)));
    }

    #[test]
    fn test_comment_eof_after_spaces() {
        assert_ast("1 + 1   # comment", plus!(int!(1), int!(1)));
        assert_ast("1 /* comment */ ", int!(1));
    }

    #[test]
    fn test_comments_interspersed() {
        assert_ast(
            "1 # comment\n + # another comment\n 2",
            plus!(int!(1), int!(2)),
        );
        assert_ast("1 /* block1 */ + /* block2 */ 2", plus!(int!(1), int!(2)));
        assert_ast(
            "let a = 1; # comment for a\n /* block comment */ b = 2; # comment for b\n in a + b",
            scope!(
                array!(tuple!(id!("a"), int!(1)), tuple!(id!("b"), int!(2))),
                plus!(id!("a"), id!("b"))
            ),
        );
        assert_ast(
            "1 + /* comment before op */ - /* comment after op */ 2",
            plus!(int!(1), neg!(int!(2))),
        );
    }

    #[test]
    fn test_empty_input_with_comment() {
        assert!(parse("# just a comment").is_err());
        assert!(parse("/* block comment */").is_err());
        assert!(parse("   # comment   ").is_err());
    }

    #[test]
    fn test_semicolon_termination() {
        assert_ast("1+2;;", plus!(int!(1), int!(2)));
        assert_ast("1+2 ;;", plus!(int!(1), int!(2)));
        assert_ast(
            "let a=1 in a;;",
            scope!(array!(tuple!(id!("a"), int!(1))), id!("a")),
        );
    }
}
