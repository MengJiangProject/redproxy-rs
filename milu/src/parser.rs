use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, tag_no_case, take_until},
    character::complete::{
        alpha1, alphanumeric1, char, digit1, hex_digit1, multispace0, multispace1, oct_digit1,
        one_of,
    },
    combinator::{all_consuming, cut, map, map_opt, map_res, opt, recognize},
    error::{context, convert_error, ContextError, FromExternalError, ParseError, VerboseError},
    multi::{many0, many1, separated_list0}, 
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple as nom_tuple},
    IResult, Parser,
};
use nom_locate::LocatedSpan;
use std::{fmt, num::ParseIntError, sync::Arc};

mod string;
mod template;
use super::script::stdlib::*;
use super::script::{Call, Value};

pub type Span<'s> = LocatedSpan<&'s str>;

fn parse_many(op: Span, mut args: Vec<Value>) -> Value {
    let op = op.to_ascii_lowercase();
    match op.as_str() {
        "call" => Call::new(args).into(),
        "index" => {
            let p1 = args.remove(0);
            let p2 = args.remove(0);
            Index::make_call(p1, p2).into()
        }
        "access" => {
            let p1 = args.remove(0);
            let p2 = args.remove(0);
            Access::make_call(p1, p2).into()
        }
        _ => panic!("not implemented operator in parse_many: {}", op),
    }
}
fn parse1(op: Span, p1: Value) -> Value {
    let op = op.to_ascii_lowercase();
    match op.as_str() {
        "!" => Not::make_call(p1).into(),
        "~" => BitNot::make_call(p1).into(),
        "-" => Negative::make_call(p1).into(),
        _ => panic!("not implemented unary operator in parse1: {}", op),
    }
}
fn parse2(op: Span, p1: Value, p2: Value) -> Value {
    let op = op.to_ascii_lowercase();
    match op.as_str() {
        "*" => Multiply::make_call(p1, p2).into(),
        "/" => Divide::make_call(p1, p2).into(),
        "%" => Mod::make_call(p1, p2).into(),
        "+" => Plus::make_call(p1, p2).into(),
        "-" => Minus::make_call(p1, p2).into(),
        "<<" => ShiftLeft::make_call(p1, p2).into(),
        ">>" => ShiftRight::make_call(p1, p2).into(),
        ">>>" => ShiftRightUnsigned::make_call(p1, p2).into(),
        ">" => Greater::make_call(p1, p2).into(),
        ">=" => GreaterOrEqual::make_call(p1, p2).into(),
        "<" => Lesser::make_call(p1, p2).into(),
        "<=" => LesserOrEqual::make_call(p1, p2).into(),
        "==" => Equal::make_call(p1, p2).into(),
        "!=" => NotEqual::make_call(p1, p2).into(),
        "=~" => Like::make_call(p1, p2).into(),
        "!~" => NotLike::make_call(p1, p2).into(),
        "_:" => IsMemberOf::make_call(p1, p2).into(),
        "&&" => BitAnd::make_call(p1, p2).into(),
        "^" => BitXor::make_call(p1, p2).into(),
        "bitor" => BitOr::make_call(p1, p2).into(),
        "and" => And::make_call(p1, p2).into(),
        "^^" | "xor" => Xor::make_call(p1, p2).into(),
        "||" | "or" => Or::make_call(p1, p2).into(),
        "|" => ArrayConcatOp::make_call(p1, p2).into(),
        _ => panic!("not implemented binary operator in parse2: {}", op),
    }
}

macro_rules! rule {
    ($vis:vis $name:ident ( $input:ident ) -> $rt:ty, $context:ident, $body:block) => {
        #[allow(dead_code)]
        $vis fn $name<'a, E>($input: Span<'a>) -> IResult<Span<'a>, $rt, E>
        where
            E: ParseError<Span<'a>>
                + ContextError<Span<'a>>
                + FromExternalError<Span<'a>, ParseIntError>
                + fmt::Debug,
        {
            $context!($name, $body, $input)
        }
    };
}

#[allow(unused_macros)]
macro_rules! no_ctx { ($name:ident, $body:block, $input:ident) => { ($body) }; }
#[allow(unused_macros)]
macro_rules! ctx { ($name:ident, $body:block, $input:ident) => { context(stringify!($name), ws($body))($input) }; }

rule!(eol_comment(i) -> Span<'a>, no_ctx, { recognize(pair(char('#'), is_not("\n\r")))(i) });
rule!(inline_comment(i) -> Span<'a>, no_ctx, { delimited(tag("/*"), take_until("*/"), tag("*/"))(i) });
rule!(blank(i) -> Span<'a>, no_ctx, { recognize(many0(alt((multispace1, eol_comment, inline_comment))))(i) });

fn ws<'a, O, E, F>(f: F) -> impl FnMut(Span<'a>) -> IResult<Span<'a>, O, E>
where E: ParseError<Span<'a>> + ContextError<Span<'a>> + FromExternalError<Span<'a>, ParseIntError> + fmt::Debug, F: Parser<Span<'a>, O, E> {
    preceded(blank, f)
}

rule!(string(i) -> Value, ctx, { map(string::parse_string,Into::into)(i) });
rule!(template(i) -> Value, ctx, { map(template::parse_template, |v| StringConcat::make_call(v.into()).into() )(i) });
rule!(boolean(i) -> Value, ctx, { map(alt((nom::combinator::value(true, tag("true")), nom::combinator::value(false, tag("false")))),Into::into)(i) });
rule!(hexadecimal(i) -> Span<'a>, ctx, { preceded(tag_no_case("0x"), recognize(many1(terminated(hex_digit1, many0(char('_'))))))(i) });
rule!(octal(i) -> Span<'a>, ctx, { preceded(tag_no_case("0o"), recognize(many1(terminated(oct_digit1, many0(char('_'))))))(i) });
rule!(binary(i) -> Span<'a>, ctx, { preceded(tag_no_case("0b"), recognize(many1(terminated(one_of("01"), many0(char('_'))))))(i) });
rule!(decimal(i) -> Span<'a>, ctx, { recognize(many1(terminated(digit1, many0(char('_')))))(i) });

rule!(integer(i) -> Value, ctx, {
    fn atoi<'a>(n: u32) -> impl Fn(Span<'a>) -> Result<Value, ParseIntError> {
        move |x| i64::from_str_radix(&x, n).map(Into::into)
    }
    alt((map_res(binary, atoi(2)), map_res(octal, atoi(8)), map_res(hexadecimal, atoi(16)), map_res(decimal, atoi(10))))(i)
});

rule!(identifier(i) -> Value, ctx, { map(recognize(pair(alt((alpha1, tag("_"))), many0(alt((alphanumeric1, tag("_")))))), |x:Span|Value::Identifier(String::from(*x)))(i) });

rule!(array(i) -> Value, ctx, { map(delimited(ws(char('[')), cut(terminated(separated_list0(ws(char(',')), op_0), opt(ws(char(','))))), ws(char(']'))), Into::into)(i) });
rule!(tuple(i) -> Value, ctx, { map(map(delimited(ws(char('(')), cut(map_opt(pair(many0(terminated(op_0, ws(char(',')))), opt(op_0)), |(mut ary,last)|{ if ary.is_empty() && last.is_some() { return None } if let Some(v)=last { ary.push(v); } Some(ary) })), ws(char(')'))), Arc::new), Value::Tuple)(i) });

// ArrayPattern: [a, b | rest] or [a,b] or [] or [|rest]
rule!(array_pattern(i) -> Value, ctx, {
    map(
        delimited(
            ws(char('[')),
            pair(
                terminated(separated_list0(ws(char(',')), ws(identifier)), opt(ws(char(',')))), // elements
                opt(preceded(ws(char('|')), ws(identifier))) // optional rest identifier
            ),
            ws(char(']'))
        ),
        |(elements, rest)| Value::ArrayPattern { elements, rest: rest.map(Arc::new) }
    )(i)
});

// Pattern for let/binding LHS: an identifier or an array pattern
rule!(let_lhs_pattern(i) -> Value, ctx, { alt((array_pattern, identifier))(i) });

rule!(value(i) -> Value, ctx, { alt((string, template, boolean, integer, array, tuple, fun_definition, identifier ))(i) });

rule!(fun_definition(i) -> Value, ctx, { map(nom_tuple((ws(tag("fun")), ws(many1(identifier)), ws(tag("=")), cut(op_0) )), |(_, params, _, body)| Value::FunctionDef { name: None, params, body: Arc::new(body) })(i) });
rule!(op_value(i) -> Value, ctx, { alt((delimited(ws(char('(')), ws(op_0), ws(char(')'))), value))(i) });
rule!(op_index(i) -> (Span<'a>,Vec<Value>), ctx, { map(delimited(ws(tag("[")), op_0, ws(char(']'))), |idx| (Span::new("index"), vec![idx]))(i) });
rule!(op_access(i) -> (Span<'a>,Vec<Value>), ctx, { map(preceded(ws(tag(".")), alt((identifier,integer))), |id| (Span::new("access"), vec![id]))(i) });
rule!(op_call(i) -> (Span<'a>,Vec<Value>), ctx, { map(delimited(ws(char('(')), separated_list0(ws(char(',')), op_0), ws(char(')'))), |args|(Span::new("call"),args))(i) });

rule!(op_8(i) -> Value, ctx, { map(nom_tuple((op_value, many0(alt((op_index, op_access, op_call))) )) , |(p1, expr)| { expr.into_iter().fold(p1, |p1_fold, val_op| { let (op_span, mut args_vec) : (Span,Vec<Value>) = val_op; args_vec.insert(0,p1_fold); parse_many(op_span, args_vec) }) })(i) });
rule!(op_7(i) -> Value, ctx, { alt((map(nom_tuple((ws(alt((tag("!"), tag("~"), tag("-")))), op_7)), |(op,p1)|parse1(op, p1)), op_8))(i) });

macro_rules! op_rule { ($name:ident, $next:ident, $tags:expr ) => { rule!($name(i) -> Value, ctx, { map(nom_tuple(($next, many0(nom_tuple((ws($tags), $next))) )), |(p1, expr)| expr.into_iter().fold(p1, |p1_fold, val_op| { let (op_span, p2_val) = val_op; parse2(op_span, p1_fold, p2_val).into() }))(i) }); }; }

op_rule!(op_6, op_7, alt((tag("*"), tag("/"), tag("%"),)));
op_rule!(op_5, op_6, alt((tag("+"), tag("-"))));
op_rule!(op_4_5, op_5, tag("|"));
op_rule!(op_4_1, op_4_5, alt((tag("<<"), tag(">>"), tag(">>>"))));
op_rule!(op_4, op_4_1, alt((tag(">"), tag(">="), tag("<"), tag("<="))));
op_rule!(op_3, op_4, alt((tag("=="), tag("!="), tag("=~"), tag("!~"), tag("_:"))));
op_rule!(op_2_5, op_3, tag("&&")); 
op_rule!(op_2_4, op_2_5, tag("^"));
op_rule!(op_2_3, op_2_4, tag_no_case("bitor")); 
op_rule!(op_2, op_2_3, tag_no_case("and")); 
op_rule!(op_1, op_2, alt((tag("||"), tag_no_case("or"))));

rule!(op_if(i) -> Value, ctx, { map(alt((nom_tuple((preceded(ws(tag("if")),op_0), preceded(ws(tag("then")),op_0), preceded(ws(tag("else")),op_0))) , nom_tuple((terminated(op_1,ws(tag("?"))), terminated(op_0,ws(tag(":"))), op_0)) )), |(cond, yes, no)| If::make_call(cond, yes, no).into())(i) });

// A single binding definition: pattern = expression
rule!(binding_def(i) -> Value, ctx, {
    map(
        separated_pair(ws(let_lhs_pattern), ws(tag("=")), op_0),
        |(pattern, expr)| Value::Binding {
            pattern: Arc::new(pattern),
            expr: Arc::new(expr),
        }
    )(i)
});

rule!(op_let(i) -> Value, ctx, {
    map(
        nom_tuple((
            preceded(ws(tag("let")),
                terminated(
                    separated_list0(ws(char(';')), binding_def), 
                    opt(ws(char(';'))) 
                )
            ),
            preceded(ws(tag("in")),op_0),
        )),
        |(bindings_vec,expr)| { 
            Scope::make_call(Value::Array(Arc::new(bindings_vec)), expr).into()
        }
    )(i)
});

rule!(do_block(i) -> Value, ctx, {
    map(
        preceded(
            ws(tag("do")),
            cut(pair( 
                many0(terminated(
                    preceded(ws(tag("let")), binding_def), 
                    ws(char(';'))
                )),
                ws(op_0) 
            ))
        ),
        |(bindings, final_expr)| Value::DoBlock {
            bindings, 
            final_expr: Arc::new(final_expr),
        }
    )(i)
});

rule!(op_0(i) -> Value, ctx, { alt((op_if, op_let, do_block, op_1))(i) });
rule!(root(i)->Value, ctx, { all_consuming(terminated(op_0,delimited(multispace0,opt(tag(";;")),multispace0)))(i) });

pub fn parse(input: &str) -> Result<Value, SyntaxError> {
    root::<VerboseError<Span>>(Span::new(input)).map(|x| x.1).map_err(|err| SyntaxError::new(err, input))
}

pub struct SyntaxError { msg: String }
impl SyntaxError {
    fn new(e: nom::Err<VerboseError<Span>>, input: &str) -> Self {
        let msg = match e {
            nom::Err::Error(er) | nom::Err::Failure(er) => convert_error(input, VerboseError { errors: er.errors.into_iter().map(|(span, e)| (*span, e)).collect::<Vec<_>>() }),
            _ => e.to_string(),
        };
        SyntaxError { msg }
    }
}
impl std::error::Error for SyntaxError {}
impl fmt::Display for SyntaxError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result { write!(f, "SyntaxError: {}", self.msg) } }
impl fmt::Debug for SyntaxError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result { write!(f, "SyntaxError: {}", self.msg) } }

#[cfg(test)]
mod tests {
    use super::super::script::ScriptContext; 
    use std::sync::Arc; 
    use super::*;

    macro_rules! expr { ($id:ident,$name:ident) => { expr!($id, $name, make_call); }; ($id:ident,$name:ident,$make_call:ident) => { #[allow(unused_macros)] macro_rules! $id { ($p1:expr) => { $name::$make_call($p1).into() }; ($p1:expr,$p2:expr) => { $name::$make_call($p1, $p2).into() }; ($p1:expr,$p2:expr,$p3:expr) => { $name::$make_call($p1, $p2, $p3).into() }; } }; }
    expr!(not, Not); expr!(bit_not, BitNot); expr!(neg, Negative); expr!(and, And); expr!(or, Or); expr!(band, BitAnd); expr!(bor, BitOr); expr!(bxor, BitXor); expr!(plus, Plus); expr!(minus, Minus); expr!(mul, Multiply); expr!(div, Divide); expr!(equal, Equal); expr!(member_of, IsMemberOf); expr!(call, Call, new); expr!(scope, Scope); expr!(index, Index); expr!(access, Access); expr!(branch, If); expr!(strcat, StringConcat); expr!(array_concat_op, ArrayConcatOp); 

    macro_rules! id { ($st:expr) => { Value::Identifier($st.to_string()) }; }
    macro_rules! str { ($st:expr) => { Value::String($st.to_string()) }; }
    macro_rules! int { ($st:expr) => { Value::Integer($st) }; }
    macro_rules! bool { ($st:expr) => { Value::Boolean($st) }; }
    macro_rules! array { ($($st:expr),*) => { Value::Array(Arc::new(vec![ $($st),* ])) }; }
    macro_rules! tuple { ($($st:expr),*) => { Value::Tuple(Arc::new(vec![ $($st),* ])) }; }
    
    macro_rules! array_pattern_val {
        (elements: [$($el:expr),* $(,)*], rest: None) => { Value::ArrayPattern { elements: vec![$($el),*], rest: None, } };
        (elements: [$($el:expr),* $(,)*], rest: Some($r:expr)) => { Value::ArrayPattern { elements: vec![$($el),*], rest: Some(Arc::new($r)), } };
        (elements: [], rest: Some($r:expr)) => { Value::ArrayPattern { elements: vec![], rest: Some(Arc::new($r)), } };
    }
    macro_rules! binding_val { ($pattern:expr, $expr:expr) => { Value::Binding { pattern: Arc::new($pattern), expr: Arc::new($expr), } }; }

    #[inline] fn assert_ast(input: &str, value: Value) { let output = parse(input); println!("input={}\noutput={:?}", input, output); assert_eq!(output.unwrap(), value); }
    #[inline] fn assert_eval(input: &str, expected_value: Value) { let parsed_ast = parse(input).unwrap_or_else(|e| { panic!("Parsing failed for input '{}': {:?}", input, e); }); let ctx: super::super::script::ScriptContextRef = Default::default(); let eval_result = parsed_ast.value_of(ctx); println!( "input={}\nast={:?}\neval_result={:?}", input, parsed_ast, eval_result ); assert_eq!(eval_result.unwrap(), expected_value); }
    #[inline] fn assert_eval_error(input: &str, error_substring: &str) { let parsed_ast = parse(input).unwrap_or_else(|e| { panic!("Parsing failed for input '{}': {:?}", input, e); }); let ctx: super::super::script::ScriptContextRef = Default::default(); let eval_result = parsed_ast.value_of(ctx); println!( "input={}\nast={:?}\neval_result={:?}", input, parsed_ast, eval_result ); match eval_result { Ok(val) => panic!( "Expected error containing '{}' for input '{}', but got Ok({:?})", error_substring, input, val ), Err(e) => { let error_string = e.to_string(); assert!( error_string.contains(error_substring), "Error message '{}' does not contain expected substring '{}'", error_string, error_substring ); } } }

    #[test] fn simple_op() { assert_ast("x+1", plus!(id!("x"), int!(1))); }
    #[test] fn root_is_value() { assert_ast("x", id!("x")); assert_ast("\r\n\t x \r\n\t ", id!("x")); assert_ast(" ( ( ( ( x ) ) ) ) ", id!("x")); }
    #[test] fn opreator_priority() { assert_ast("1 and ( 2 ) or 3 == 4", or!(and!(int!(1), int!(2)), equal!(int!(3), int!(4)))); assert_ast("1 ^ 4 && ( 2 bitor 3 )", bxor!(int!(1), band!(int!(4), bor!(int!(2), int!(3))))); }
    #[test] fn bitwise_and_op() { assert_ast("1 && 2", band!(int!(1), int!(2))); }
    #[test] fn logical_and_op() { assert_ast("true and false", and!(bool!(true), bool!(false))); }
    #[test] fn bitwise_or_op() { assert_ast("1 bitor 2", bor!(int!(1), int!(2))); }
    #[test] fn array_concat_op_parser() { assert_ast("[1,2] | [3,4]", array_concat_op!(array![int!(1), int!(2)], array![int!(3), int!(4)])); }
    #[test] fn operator_precedence_combined() { assert_ast("id_a && id_b | id_c and id_d", and!(array_concat_op!(band!(id!("id_a"),id!("id_b")),id!("id_c")),id!("id_d"))); }
    #[test] fn op_8() { assert_ast("a(b).c[d]", index!(access!(call!(vec![id!("a"), id!("b")]), id!("c")), id!("d"))); }
    #[test] fn op_7() { assert_ast(" ! ! ( ~ true ) ", not!(not!(bit_not!(bool!(true))))); }
    #[test] fn op_6() { assert_ast("1 * 1 / -2", div!(mul!(int!(1), int!(1)), neg!(int!(2)))); }
    #[test] fn op_5() { assert_ast("1+1-2", minus!(plus!(int!(1), int!(1)), int!(2))); }
    #[test] fn template_string() { assert_ast("`a=${1+1}`", strcat!(array!(str!("a="), plus!(int!(1), int!(1))))); assert_ast(r#"`a=\${a}`"#, strcat!(array!(str!("a="), str!("$"), str!("{a}")))); assert_ast("`a=${`x=${x}`}`", strcat!(array!(str!("a="), strcat!(array!(str!("x="), id!("x")))))); }
    #[test] fn tuple_array() { assert_ast("[ ( ) , ( ( 1 ) , ) , ( 1 , 2 ) , ( 1 , 2 , ) ]", array!(tuple!(), tuple!(int!(1)), tuple!(int!(1), int!(2)), tuple!(int!(1), int!(2)))); }
    #[test] fn branch() { assert_ast("if a then b else if c then d else e", branch!(id!("a"),id!("b"),branch!(id!("c"),id!("d"),id!("e")))); assert_ast("if if a then b else c then d else e", branch!(branch!(id!("a"),id!("b"),id!("c")),id!("d"),id!("e"))); assert_ast("(a ? b : c) ? d : e", branch!(branch!(id!("a"),id!("b"),id!("c")),id!("d"),id!("e"))); }
    
    #[test] fn scope_bindings() { let ast = scope!(array![binding_val!(id!("a"),int!(1)), binding_val!(id!("b"),int!(2))], plus!(id!("a"),id!("b"))); assert_ast("let a=1;b=2 in a+b", ast.clone()); assert_ast("let a=1;b=2; in a+b", ast); }
    #[test] fn comments() { assert_ast("if #comments\r\n a /* \r\n /* */then/**/b else c", branch!(id!("a"),id!("b"),id!("c"))); assert_ast(r#" [ " #not a comment ", " /* also not a comment " , " */" ]"#, array!(str!(" #not a comment "), str!(" /* also not a comment "), str!(" */"))); }
    #[test] fn complex() { assert_ast(" 1 _: [ \"test\" , 0x1 , 0b10 , 0o3 , false , if xyz == 1 then 2 else 3] ", member_of!(int!(1),array!(str!("test"),int!(1),int!(2),int!(3),bool!(false),branch!(equal!(id!("xyz"),int!(1)),int!(2),int!(3))))); }
    #[test] fn eval_array_concat_op() { assert_eval("[1,2] | [3,4]", array![int!(1),int!(2),int!(3),int!(4)],); assert_eval("[1,2] | []", array![int!(1),int!(2)]); assert_eval("[] | [1,2]", array![int!(1),int!(2)]); assert_eval("[] | []", array![]); assert_eval("[\"a\",\"b\"] | [\"c\"]", array![str!("a"),str!("b"),str!("c")],); }
    #[test] fn eval_array_concat_type_error() { assert_eval_error("[1] | [\"a\"]", "Array element types are incompatible for concatenation: Integer vs String"); }
    #[test] fn eval_array_concat_arg_not_array_error_left() { assert_eval_error("1 | [\"a\"]", "First argument to '|' must be an array"); }
    #[test] fn eval_array_concat_arg_not_array_error_right() { assert_eval_error("[\"a\"] | 1", "Second argument to '|' must be an array"); }
    #[test] fn eval_bitwise_and_op() { assert_eval("1 && 3", int!(1&3)); assert_eval("0b101 && 0b011", int!(0b101&0b011)); assert_eval("5 && 2", int!(5&2)); }
    #[test] fn eval_logical_and_op() { assert_eval("true and true", bool!(true)); assert_eval("true and false", bool!(false)); assert_eval("false and true", bool!(false)); assert_eval("false and false", bool!(false)); assert_eval("false and (1/0 == 1)", bool!(false)); }
    #[test] fn eval_bitwise_or_op() { assert_eval("1 bitor 2", int!(1|2)); assert_eval("0b101 bitor 0b010", int!(0b101|0b010)); assert_eval("5 bitor 2", int!(5|2)); }
    #[test] fn eval_complex_expression_with_scope_and_ops() { assert_eval("let a = [1,2]; b = [3,4]; c = 10; d = 20 in (a|b)[0] + (c && d) + (c bitor d)", int!(27)); }
    #[test] fn ast_fun_definition_simple() { assert_ast("fun x = x + 1", Value::FunctionDef {name:None,params:vec![id!("x")],body:Arc::new(plus!(id!("x"),int!(1)))}); }
    #[test] fn ast_fun_definition_in_let() { assert_ast("let add = fun x y = x + y in add", scope!(array![binding_val!(id!("add"),Value::FunctionDef{name:None,params:vec![id!("x"),id!("y")],body:Arc::new(plus!(id!("x"),id!("y")))})],id!("add"))); }
    #[test] fn ast_fun_definition_nested() { assert_ast("fun f = fun g = g + 1", Value::FunctionDef{name:None,params:vec![id!("f")],body:Arc::new(Value::FunctionDef{name:None,params:vec![id!("g")],body:Arc::new(plus!(id!("g"),int!(1)))})}); }
    #[test] fn eval_fun_call_simple() { assert_eval("let f = fun x = x + 1 in f(10)", int!(11)); }
    #[test] fn eval_fun_call_two_params() { assert_eval("let add = fun x y = x + y in add(3, 4)", int!(7)); }
    #[test] fn eval_fun_call_arg_count_mismatch_too_many() { assert_eval_error("let f = fun x = x + 1 in f(1, 2)", "Argument count mismatch for function Some(\"f\"): expected 1, got 2"); }
    #[test] fn eval_fun_call_arg_count_mismatch_too_few() { assert_eval_error("let f = fun x y = x + y in f(1)", "Argument count mismatch for function Some(\"f\"): expected 2, got 1"); }
    #[test] fn eval_fun_call_no_args_expected_but_given() { assert_eval_error("let f = fun = 10 in f(1)", "Argument count mismatch for function Some(\"f\"): expected 0, got 1"); }
    #[test] fn eval_fun_call_no_args_defined_no_args_given() { assert_eval("let f = fun = 10 in f()", int!(10)); }
    #[test] fn eval_closure_simple() { assert_eval("let a = 10; let f = fun x = x + a; in f(5)", int!(15)); }
    #[test] fn eval_closure_shadowing_param() { assert_eval("let a = 10; let f = fun a = a + 5; in f(1)", int!(6)); }
    #[test] fn eval_closure_shadowing_let_in_body() { assert_eval("let a = 10; let f = fun x = let a = 1 in x + a; in f(5)", int!(6)); }
    #[test] fn eval_higher_order_function_return_and_call() { assert_eval("let f = fun x = fun y = x + y; let add5 = f(5); in add5(10)", int!(15)); }
    #[test] fn eval_higher_order_function_pass_as_arg() { assert_eval("let apply = fun func val = func(val); let inc = fun x = x + 1; in apply(inc, 5)", int!(6)); }
    #[test] fn eval_recursion_simple_factorial() { assert_eval("let fac = fun n = if n == 0 then 1 else n * fac(n-1) in fac(3)", int!(6)); }
    #[test] fn eval_function_redefinition_uses_latest() { assert_eval("let f = fun x = x + 1; let f = fun x = x * 2; in f(10)", int!(20)); }
    #[test] fn eval_closure_context_persistence() { assert_eval("let a = 10; let f = fun x = x + a; let a = 20; in f(5)", int!(15)); }
    #[test] fn eval_named_function_in_call_itself() { assert_eval("let f = fun x = x + 1 in (f)(10)", int!(11)); }
    #[test] fn eval_fun_assigned_to_new_var() { assert_eval("let f = fun x = x+1; let g = f; in g(5)", int!(6)); }

    #[test] fn ast_do_block_simple_expression() { assert_ast("do 1", Value::DoBlock { bindings: vec![], final_expr: Arc::new(int!(1)) }); }
    #[test] fn ast_do_block_one_binding_updated() { assert_ast("do let x = 10; x", Value::DoBlock { bindings: vec![binding_val!(id!("x"), int!(10))], final_expr: Arc::new(id!("x")) }); }
    #[test] fn ast_do_block_multiple_bindings_updated() { assert_ast("do let x = 1; let y = x + 1; (x, y)", Value::DoBlock { bindings: vec![binding_val!(id!("x"),int!(1)),binding_val!(id!("y"),plus!(id!("x"),int!(1)))], final_expr: Arc::new(Value::Tuple(Arc::new(vec![id!("x"),id!("y")]))) }); }
    #[test] fn ast_do_block_no_bindings_complex_expr() { assert_ast("do (1+2)*3", Value::DoBlock { bindings: vec![], final_expr: Arc::new(mul!(plus!(int!(1),int!(2)), int!(3))) }); }
    
    #[test] fn ast_array_pattern_empty() { assert_ast("[]", array_pattern_val!(elements: [], rest: None)); }
    #[test] fn ast_array_pattern_single_element() { assert_ast("[a]", array_pattern_val!(elements: [id!("a")], rest: None)); }
    #[test] fn ast_array_pattern_single_element_trailing_comma() { assert_ast("[a,]", array_pattern_val!(elements: [id!("a")], rest: None)); }
    #[test] fn ast_array_pattern_multiple_elements() { assert_ast("[a,b, c]", array_pattern_val!(elements: [id!("a"),id!("b"),id!("c")], rest: None)); }
    #[test] fn ast_array_pattern_multiple_elements_trailing_comma() { assert_ast("[a,b,c,]", array_pattern_val!(elements: [id!("a"),id!("b"),id!("c")], rest: None)); }
    #[test] fn ast_array_pattern_rest_only() { assert_ast("[|r]", array_pattern_val!(elements: [], rest: Some(id!("r")))); }
    #[test] fn ast_array_pattern_rest_only_spaced() { assert_ast("[ | r ]", array_pattern_val!(elements: [], rest: Some(id!("r")))); }
    #[test] fn ast_array_pattern_elements_and_rest() { assert_ast("[a,b|r]", array_pattern_val!(elements: [id!("a"),id!("b")], rest: Some(id!("r")))); }
    #[test] fn ast_array_pattern_elements_and_rest_spaced() { assert_ast("[a, b | r]", array_pattern_val!(elements: [id!("a"),id!("b")], rest: Some(id!("r")))); }
    #[test] fn ast_array_pattern_elements_trailing_comma_and_rest() { assert_ast("[a, b, | r]", array_pattern_val!(elements: [id!("a"),id!("b")], rest: Some(id!("r")))); }

    #[test] fn ast_op_let_simple_identifier_binding() { assert_ast("let x=1 in x", scope!(array![binding_val!(id!("x"),int!(1))],id!("x"))); }
    #[test] fn ast_op_let_array_pattern_binding() { assert_ast("let [a|b] = [1,2,3] in a", scope!(array![binding_val!(array_pattern_val!(elements:[id!("a")],rest:Some(id!("b"))),array![int!(1),int!(2),int!(3)])],id!("a"))); }
    #[test] fn ast_op_let_multiple_bindings_mixed() { assert_ast("let x = 1; let [a|b] = [2,3] in a", scope!(array![binding_val!(id!("x"),int!(1)),binding_val!(array_pattern_val!(elements:[id!("a")],rest:Some(id!("b"))),array![int!(2),int!(3)])],id!("a"))); }
    #[test] fn ast_op_let_empty_array_pattern() { assert_ast("let [] = [] in 1", scope!(array![binding_val!(array_pattern_val!(elements:[],rest:None),array![])],int!(1))); }
    #[test] fn ast_op_let_complex_array_pattern() { assert_ast("let [x,y|z] = [1,2,3,4] in (x,y,z)", scope!(array![binding_val!(array_pattern_val!(elements:[id!("x"),id!("y")],rest:Some(id!("z"))),array![int!(1),int!(2),int!(3),int!(4)])],tuple!(id!("x"),id!("y"),id!("z")))); }

    #[test] fn ast_do_block_array_pattern_binding() { assert_ast("do let [a|b] = [1,2,3]; a", Value::DoBlock{bindings:vec![binding_val!(array_pattern_val!(elements:[id!("a")],rest:Some(id!("b"))),array![int!(1),int!(2),int!(3)])],final_expr:Arc::new(id!("a"))}); }
    #[test] fn ast_do_block_multiple_bindings_mixed_patterns() { assert_ast("do let x = 1; let [a|b] = [2,3,4]; let y = 5; a", Value::DoBlock{bindings:vec![binding_val!(id!("x"),int!(1)),binding_val!(array_pattern_val!(elements:[id!("a")],rest:Some(id!("b"))),array![int!(2),int!(3),int!(4)]),binding_val!(id!("y"),int!(5))],final_expr:Arc::new(id!("a"))}); }

    #[test] fn eval_do_block_empty_do_error() { let result = parse("do"); assert!(result.is_err(), "Parser should error for 'do' without a final expression. Got: {:?}", result); let result_with_let = parse("do let x = 1;"); assert!(result_with_let.is_err(), "Parser should error for 'do' with only bindings and no final expression. Got: {:?}", result_with_let); }
}
