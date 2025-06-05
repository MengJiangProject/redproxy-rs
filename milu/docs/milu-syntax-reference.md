# Milu Language Syntax Reference

This document provides a reference for the Milu language syntax, including both existing features and proposed extensions. It uses a BNF-like notation to describe the grammar.

## Table of Contents
- Introduction
- Lexical Elements
  - Comments
  - Identifiers
  - Literals
    - Integers
    - Booleans
    - Strings (Standard and Template)
    - Arrays
    - Tuples
- General Constructs
  - Program Structure
- Definitions
  - Variable Bindings (`let ... in ...`)
  - Function Definitions
  - User-Defined Type Definitions (`type`)
    - Enums (Sum Types)
    - Structs (Product Types)
  - Generic Function Definitions
- Expressions
  - Primary Expressions
  - Postfix Operations (Accessors, Calls, `?` operator)
  - Unary Operations
  - Binary Operations (and Operator Precedence Overview)
  - Conditional Expressions (`if ... then ... else ...`)
  - `match` Expressions
- Standard Library Types (Conceptual)
  - `Option<T>`
  - `Result<T,E>`
- Appendix: Operator Precedence Table (Simplified)

---
## 1. Introduction
Milu is an embedded Domain Specific Language (DSL) designed for tasks like request filtering and log formatting. It is statically typed (with type inference), pure functional (aspirational), and expression-based. Each Milu script or program evaluates to a single value.

This document uses an Extended Backus-Naur Form (EBNF)-like notation to describe Milu's grammar. It aims for clarity and descriptiveness rather than formal rigor suitable for automatic parser generation.
*   `::=` : "is defined as"
*   `|` : "or" (alternatives)
*   `""` : Terminal symbols (keywords, operators).
*   `non_terminal_name` : Non-terminal symbols defined by other rules.
*   `rule?` : Optional (0 or 1 occurrence).
*   `rule*` : Zero or more occurrences.
*   `rule+` : One or more occurrences.
*   `()` : Grouping.
*   `--` : Precedes comments in BNF rules.

---
## 2. Lexical Elements

### 2.1. Comments

```ebnf
comment ::= line_comment | block_comment
line_comment ::= "#" character_not_newline* newline_character
block_comment ::= "/*" (character | newline_character)* "*/"
```
**Examples:**
```milu
# This is a line comment.
let x = 10; # This is an end-of-line comment.

/* This is a
   multi-line block comment. */
let y = /* comment inside expression */ 20;
```

### 2.2. Identifiers
Identifiers are used for variable, function, type, and variant names. They must start with a letter or underscore, followed by zero or more letters, digits, or underscores. Conventionally, type and variant names use PascalCase.
```ebnf
identifier ::= (letter | "_") (letter | digit | "_")*
letter ::= "a"..."z" | "A"..."Z" -- (standard letters)
digit ::= "0"..."9"
```
**Examples:**
```milu
let my_variable = 42;
let _internal_val = "secret";
let functionName1 = (); 
// type MyType = ...
// type MyEnum = MyVariant | ...
```

### 2.3. Literals
#### 2.3.1. Integers
Integers are 64-bit signed. Underscores can be used as visual separators.
```ebnf
integer_literal ::= decimal_literal | hex_literal | octal_literal | binary_literal
decimal_literal ::= "-"? digit ("_"? digit)*
hex_literal ::= "-"? ("0x" | "0X") hex_digit ("_"? hex_digit)*
octal_literal ::= "-"? ("0o" | "0O") oct_digit ("_"? oct_digit)*
binary_literal ::= "-"? ("0b" | "0B") bin_digit ("_"? bin_digit)*

hex_digit ::= digit | "a"..."f" | "A"..."F"
oct_digit ::= "0"..."7"
bin_digit ::= "0" | "1"
```
**Examples:**
```milu
123
-42
1_000_000
0xFF
-0xcafe
0o77
0b1010
```

#### 2.3.2. Booleans
```ebnf
boolean_literal ::= "true" | "false"
```
**Examples:**
```milu
true
false
```

#### 2.3.3. Strings
Strings are sequences of characters. Standard strings are in double quotes, template strings in backticks.

```ebnf
string_literal ::= standard_string | template_string

standard_string ::= "\"" standard_string_character* "\""
standard_string_character ::= any_character_except_quote_backslash | escape_sequence

template_string ::= "`" template_string_character* "`"
template_string_character ::= any_character_except_backtick_dollar | escape_sequence | dollar_not_followed_by_brace | embedded_expression
embedded_expression ::= "${" expression "}"

escape_sequence ::= "\\" ("n" | "r" | "t" | "b" | "f" | "\\" | "\"" | "`" | "$" | "/" | unicode_escape | whitespace_escape)
unicode_escape ::= "u{" hex_digit{1,6} "}"
whitespace_escape ::= whitespace+ -- (backslash followed by whitespace consumes both)
```
**Examples:**
```milu
"hello world"
"line1\nline2"
"path: C:\\Program Files"
"unicode: \u{1F604}"

`Hello, ${name}!`
`Value is ${obj.property}`
`Escapes: \` (backtick), \$ (dollar not starting expr)`
```

#### 2.3.4. Arrays
Arrays are ordered, homogeneous collections.
```ebnf
array_literal ::= "[" (expression ("," expression)* ","?)? "]"
```
**Examples:**
```milu
[1, 2, 3]
["a", "b", "c"]
[] // Empty array
[1, 2, 3,] // Trailing comma is allowed
```

#### 2.3.5. Tuples
Tuples are ordered, heterogeneous collections.
```ebnf
tuple_literal ::= "(" (expression ("," expression)* ","?)? ")"
-- Special case: `()` is the empty tuple. A single element tuple `(expr,)` needs a comma.
```
**Examples:**
```milu
(1, "hello", true)
(10, 20)
() // Empty tuple
("value",) // Single element tuple
```

---
## 3. General Constructs

### 3.1. Program Structure
A Milu script is typically a single expression.
```ebnf
program ::= expression (";;"?)? -- Optional double semicolon at the end
```

---
## 4. Definitions

### 4.1. Variable Bindings (`let ... in ...`)
`let` bindings introduce local variables or functions. Bindings are immutable.
```ebnf
let_expression ::= "let" (binding (";" binding)* ";"? ) "in" expression
binding ::= identifier generic_params? argument_def_list? ("->" type_name)? "=" expression  -- General form for functions or simple variables
          | identifier ":" type_name "=" expression -- Variable with explicit type, no args/generics

-- For clarity, separating out function and variable binding forms:
-- simple_variable_binding ::= identifier (":" type_name)? "=" expression
-- function_binding ::= identifier generic_params? argument_def_list ("->" type_name)? "=" expression

argument_def_list ::= "(" (argument_def ("," argument_def)* ","?)? ")"
argument_def ::= identifier (":" type_name)?
generic_params ::= "<" identifier ("," identifier)* ">"
type_name ::= identifier ( "<" type_name ("," type_name)* ">" )? -- Simple type or generic instantiation
```
**Examples:**
```milu
let x = 10 in x * x

let
    a = 5;
    b: Integer = a + 2; // b is 7, with optional type annotation
in
    a + b // Evaluates to 12

let message = "hello" in `${message} world`;
```

### 4.2. Function Definitions
Functions are defined using the `let` binding syntax as shown above.
**Examples:**
```milu
let add(x: Integer, y: Integer) -> Integer = x + y;
let greet(name: String) = `Hello, ${name}!`; // Return type inferred
let factorial(n) = if n == 0 then 1 else n * factorial(n - 1);

add(3, 4) // Call
```

### 4.3. User-Defined Type Definitions (`type`)
The `type` keyword defines custom data structures: enums (sum types) and structs (product types).
```ebnf
type_definition ::= "type" identifier generic_params? "=" type_body ";"?
type_body ::= variant ("|" variant)*  -- For Enums
            | identifier "{" field_definition ("," field_definition)* ","? "}" -- For Structs (single variant style)

variant ::= variant_name
          | variant_name "(" type_name ("," type_name)* ")" -- Tuple-like data
          | variant_name "{" field_definition ("," field_definition)* ","? "}" -- Record-like data
variant_name ::= identifier -- Typically PascalCase
field_definition ::= identifier ":" type_name
```

#### 4.3.1. Enums (Sum Types)
**BNF (Specialized from above):**
```ebnf
enum_definition ::= "type" identifier generic_params? "=" variant ("|" variant)* ";"?
```
**Examples:**
```milu
// Simple Enum
type Status = Idle | Running | Error(String);

// Enum with different data structures per variant
type WebEvent =
    | PageView
    | KeyPress(String)
    | Click { x: Integer, y: Integer };

// Instantiation
let current_status = Status::Idle;
let err_status = Status::Error("File not found");
let click_event = WebEvent::Click { x: 10, y: 20 };
```

#### 4.3.2. Structs (Product Types)
Defined as a type with a single variant (constructor) of the same name, containing named fields.
**BNF (Specialized from above):**
```ebnf
struct_definition ::= "type" identifier generic_params? "=" identifier "{" field_definition ("," field_definition)* ","? "}" ";"?
-- Where the second identifier (constructor name) is the same as the first (type name).
```
**Examples:**
```milu
type Point = Point { x: Integer, y: Integer };
type User = User { id: Integer, username: String, isActive: Boolean };

// Instantiation
let p1 = Point { x: 10, y: 20 };
let user1 = User { id: 1, username: "alice", isActive: true };

// Field Access (uses `member_access_expression` rule)
let current_x = p1.x;
```

### 4.4. Generic Function Definitions
(Covered by the updated `binding` rule within `let_expression` which includes `generic_params?`)
**Examples:**
```milu
let identity<T>(value: T) -> T = value;
let id_num = identity(10); // T inferred as Integer

// Assuming Option<T> is defined (see Standard Library Types section)
let get_or_default<T>(opt: Option<T>, default_val: T) -> T =
    match opt {
        Option::Some(v) => v,
        Option::None => default_val,
    };
```

---
## 5. Expressions
Milu is an expression-oriented language. The general order of parsing an `expression` can be thought of as:
`expression ::= let_expression | match_expression | conditional_expression | binary_operation_root`
where `binary_operation_root` is the entry point for expressions involving binary operators (e.g., starting with logical OR and cascading up in precedence).

### 5.1. Primary Expressions
```ebnf
primary_expression ::= literal             -- e.g., 42, "hello", true, [], ()
                     | identifier          -- e.g., my_var
                     | "(" expression ")"  -- Parenthesized expression
                     -- Type constructors for enums/structs can also be primary in some contexts
                     -- e.g., Point {x:1, y:1} or Option::Some(v)
```

### 5.2. Postfix Operations (Accessors, Calls, `?` operator)
Postfix operations apply to a preceding expression, typically a `primary_expression` or another `postfix_expression`.
```ebnf
postfix_expression ::= primary_expression (postfix_op)*
postfix_op ::= array_access_suffix
             | tuple_access_suffix
             | member_access_suffix
             | function_call_suffix
             | question_mark_suffix

array_access_suffix ::= "[" expression "]"
tuple_access_suffix ::= "." digit+
member_access_suffix ::= "." identifier
function_call_suffix ::= "(" (expression ("," expression)* ","?)? ")"
question_mark_suffix ::= "?" -- Proposed for Option/Result propagation
```
**Examples:**
```milu
my_array[0]
my_tuple.1
user.name
my_function(arg)
calculate_value(input)? // Proposed '?' operator
```

### 5.3. Unary Operations
```ebnf
unary_expression ::= ("!" | "-" | "~") postfix_expression -- Applied to result of postfix_expression
                   | postfix_expression -- If no unary op
```
**Examples:**
```milu
!is_valid
-total_value
~flags
```

### 5.4. Binary Operations (and Operator Precedence Overview)
Binary operations combine two expressions. Milu has a hierarchy of precedence (see Appendix).
A simplified EBNF structure (full cascade omitted for brevity):
```ebnf
-- General form: expr_level_N ::= expr_level_N+1 (op_N expr_level_N+1)*
-- Example for multiplicative expressions:
multiplicative_expression ::= unary_expression (("*" | "/" | "%") unary_expression)*
additive_expression ::= multiplicative_expression (("+" | "-") multiplicative_expression)*
-- ... and so on for shift, relational, equality, bitwise, logical operators ...
binary_operation_root ::= logical_or_expression -- Lowest regular precedence binary op
-- (e.g. logical_or_expression ::= logical_and_expression (("||" | "or") logical_and_expression)* )
```
**Examples:**
```milu
x + y * z
a > b && c < d
name =~ "^admin"
item _: my_array
```

### 5.5. Conditional Expressions (`if ... then ... else ...`)
```ebnf
conditional_expression ::= "if" expression "then" expression "else" expression
                         | binary_operation_root ("?" expression ":" conditional_expression)? -- Ternary operator
-- Note: `expression` in `if/then/else` and ternary parts are generally `binary_operation_root` or higher precedence.
```
**Examples:**
```milu
if x > 10 then "large" else "small"
is_valid ? process(data) : default_value
```

### 5.6. Proposed: `match` Expressions
```ebnf
match_expression ::= "match" expression "{" (match_arm ("," match_arm)* ","?)? "}"
match_arm ::= pattern ("if" expression)? "=>" expression
pattern ::= literal
          | identifier -- Binds the value
          | "_" -- Wildcard, ignores the value
          | type_name "::" variant_name -- Simple enum variant
          | type_name "::" variant_name "(" pattern ("," pattern)* ","? ")" -- Enum variant with tuple data
          | type_name "::" variant_name "{" field_pattern ("," field_pattern)* ","? "}" -- Enum variant with record data
          | type_name "{" field_pattern ("," field_pattern)* ","? "}" -- Struct pattern
          | "(" pattern ("," pattern)* ","? ")" -- Tuple pattern
          | "[" (pattern ("," pattern)* ("," "..." identifier?)? )? "]" -- Array pattern (with optional rest)
          | pattern ("|" pattern)+ -- Alternative patterns
field_pattern ::= identifier ":" pattern
                | identifier -- Shorthand: binds field value to variable of same name
```
**Examples:**
```milu
// type Option<T> = Some(T) | None;
match Option::Some(10) {
    Option::Some(x) if x > 5 => `Value ${x} > 5`,
    Option::Some(x) => `Value is ${x}`,
    Option::None => "No value",
}
```

---
## 6. Standard Library Types (Conceptual)
These types are proposed to be part of a standard library or prelude, defined using the `type` syntax.

### 6.1. `Option<T>`
Represents an optional value.
```milu
// type Option<T> = Some(T) | None;
```
**Construction:** `Option::Some(value)`, `Option::None`.
**Consumption:** Primarily via `match` and the `?` operator.

### 6.2. `Result<T, E>`
Represents a value that can be a success (`Ok`) or an error (`Err`).
```milu
// type Result<T, E> = Ok(T) | Err(E);
```
**Construction:** `Result::Ok(value)`, `Result::Err(error_value)`.
**Consumption:** Primarily via `match` and the `?` operator.

---
## 7. Appendix: Operator Precedence Table (Simplified)

| Precedence | Operator             | Associativity | Notes                                      |
|------------|----------------------|---------------|--------------------------------------------|
| Highest    | `()` (Grouping)      | N/A           |                                            |
|            | `[]` (Array Access)  | L-to-R        |                                            |
|            | `.` (Tuple/Member Access) | L-to-R    |                                            |
|            | `()` (Function Call) | L-to-R        |                                            |
|            | `?` (Option/Result Prop.)| L-to-R    | Proposed                                   |
|            | `!` `~` `-` (Unary)  | R-to-L        | Logical NOT, Bitwise NOT, Unary Negation   |
|            | `*` `/` `%`          | L-to-R        | Multiplication, Division, Remainder        |
|            | `+` `-`              | L-to-R        | Addition, Subtraction                      |
|            | `<<` `>>` `>>>`      | L-to-R        | Bitwise Shifts                             |
|            | `<` `<=` `>` `>=`    | L-to-R        | Comparison                                 |
|            | `==` `!=`            | L-to-R        | Equality                                   |
|            | `=~` `!~` `_:`       | L-to-R        | Regex Match, Not Match, Member Of          |
|            | `&` (Bitwise AND)    | L-to-R        |                                            |
|            | `^` (Bitwise XOR)    | L-to-R        |                                            |
|            | `|` (Bitwise OR)     | L-to-R        |                                            |
|            | `&&` `and`           | L-to-R        | Logical AND                                |
|            | `^^` `xor`           | L-to-R        | Logical XOR (Note: `xor` alias may vary)   |
|            | `||` `or`            | L-to-R        | Logical OR                                 |
|            | `?:` (Ternary Cond.) | R-to-L        | `cond ? true_expr : false_expr`            |
|            | `if/then/else`       | N/A           | (Binds less tightly than operators)        |
|            | `match`              | N/A           | Proposed (Block structure)                 |
| Lowest     | `let ... in ...`     | N/A           | (Block structure)                          |

*(Note: This table is a simplified representation. `let...in`, `if/else`, and `match` are block structures or have specific parsing rules beyond simple operator precedence.)*
