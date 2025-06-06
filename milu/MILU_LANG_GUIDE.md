# Milu Language Guide

Milu is an embedded DSL (Domain Specific Language) described as statically typed, pure functional, and lazy evaluated (though laziness is more of an aspiration or internal detail than a directly controllable feature for script writers based on current stdlib). Each Milu program or script is a single expression that evaluates to a value.

This guide covers the syntax and standard library of the Milu language.

## Part 1: Syntax

### 1.1. Comments

Milu supports two types of comments:

-   **Line Comments**: Start with `#` and continue to the end of the line.
    ```milu
    # This is a line comment
    let a = 1 # Another comment after an expression
    ```

-   **Block Comments**: Start with `/*` and end with `*/`. These can span multiple lines.
    ```milu
    /* This is a
       multi-line
       block comment. */
    let x = /* comment inside expression */ 10
    ```

### 1.2. Data Types and Literals

Milu supports the following fundamental data types:

-   **Integer**: Represents 64-bit signed integers.
    -   **Decimal**: `123`, `0`, `-42`
    -   **Hexadecimal**: `0xFF`, `0xcafe` (case-insensitive prefix)
    -   **Octal**: `0o77`, `0o123` (case-insensitive prefix)
    -   **Binary**: `0b1010`, `0b11110000` (case-insensitive prefix)
    -   Underscores can be used as visual separators: `1_000_000`, `0xFF_EC_DE`.

-   **Boolean**: Represents logical `true` or `false`.
    -   Literals: `true`, `false`.

-   **String**: Represents sequences of characters.
    -   **Standard Strings**: Enclosed in double quotes (`"`).
        -   Examples: `"hello"`, `"a line with a newline\n"`
        -   Supported escape sequences:
            -   `\n`: Newline
            -   `\r`: Carriage return
            -   `\t`: Tab
            -   `\b`: Backspace
            -   `\f`: Form feed
            -   `\\`: Backslash
            -   `\"`: Double quote
            -   `\/`: Forward slash
            -   `\u{XXXX}`: Unicode character (1 to 6 hex digits, e.g., `\u{1F602}` for 😂).
            -   `\` followed by whitespace: Consumes the backslash and all subsequent whitespace until a non-whitespace character (e.g., `"a\   b"` becomes `"ab"`).
    -   **Template Strings**: Enclosed in backticks (`` ` ``). Allow for embedding expressions.
        -   Example: `` `Hello, ${name}!` ``
        -   Embedded expressions: `${expression}`. The `expression` is any valid Milu expression.
        -   Escape sequences within template strings:
            -   Same as standard strings (`\n`, `\t`, `\u{XXXX}`, etc.).
            -   Additionally: `\\`` (for a literal backtick), `\$` (for a literal dollar sign not starting an expression).
        -   A `$` not followed by `{` is a literal dollar sign.

-   **Array**: Represents ordered, homogeneous collections of values (all elements must be of the same type).
    -   Literal: `[element1, element2, ...]`
    -   Examples: `[1, 2, 3]`, `["a", "b", "c"]`, `[]` (empty array, type `[Any]`).
    -   Type mismatch in elements will result in an error (e.g., `[1, "a"]` is invalid).

-   **Tuple**: Represents ordered, heterogeneous collections of values (elements can be of different types).
    -   Literal: `(element1, element2, ...)`
    -   Examples: `(1, "hello", true)`, `(1, 2)`, `(1, "a")`, `()` (empty tuple).

-   **NativeObject**: A special type representing objects provided by the host environment (e.g., the `request` object in filter rules). These objects have properties and methods accessible via dot notation.

-   **UserDefinedFunction**: Represents functions defined within Milu scripts using `let name(args) = body in ...`.

*(Note: There is no explicit `Null` or `undefined` type in Milu. Fields like `request.connector` might return an empty string if not set.)*

### 1.3. Operators

Milu supports a rich set of operators with defined precedence and associativity.

| Precedence | Operator             | Associativity | Syntax Example(s)        | Notes                                      |
|------------|----------------------|---------------|--------------------------|--------------------------------------------|
| 99         | Grouping             | N/A           | `(expression)`           | Used to control evaluation order.          |
| 8          | Member Access        | left-to-right | `object.property`        | Access property of NativeObject.           |
| 8          | Tuple Index          | left-to-right | `my_tuple.0`, `my_tuple.1` | Accesses element at 0-based index N. e.g., `(10, "hi").0` is `10`, `(10, "hi").1` is `"hi"`. |
| 8          | Array/Index Access   | left-to-right | `array[index]`           | Access element of Array or Indexable NativeObject. 0-based index. |
| 8          | Function Call        | left-to-right | `func(arg1, arg2)`       | Calls a function.                          |
| 7          | Logical NOT          | right-to-left | `!condition`             |                                            |
| 7          | Bitwise NOT          | right-to-left | `~integer`               |                                            |
| 7          | Unary Negation       | right-to-left | `-number`                |                                            |
| 6          | Multiplication       | left-to-right | `a * b`                  |                                            |
| 6          | Division             | left-to-right | `a / b`                  | Error on division by zero.                 |
| 6          | Remainder            | left-to-right | `a % b`                  | Error on division by zero.                 |
| 5          | Addition             | left-to-right | `a + b`                  |                                            |
| 5          | Subtraction          | left-to-right | `a - b`                  |                                            |
| 4.1        | Bitwise Left Shift   | left-to-right | `a << b`                 |                                            |
| 4.1        | Bitwise Right Shift  | left-to-right | `a >> b`                 | Arithmetic shift.                          |
| 4.1        | Bitwise Unsigned R.S.| left-to-right | `a >>> b`                | Logical shift.                             |
| 4          | Less Than            | left-to-right | `a < b`                  |                                            |
| 4          | Less Than Or Equal   | left-to-right | `a <= b`                 |                                            |
| 4          | Greater Than         | left-to-right | `a > b`                  |                                            |
| 4          | Greater Than Or Equal| left-to-right | `a >= b`                 |                                            |
| 3          | Equality             | left-to-right | `a == b`                 | Returns `false` for different types.       |
| 3          | Inequality           | left-to-right | `a != b`                 | Returns `true` for different types.        |
| 3          | Regex Match          | left-to-right | `string =~ regex_string` | `regex_string` is the pattern.             |
| 3          | Regex Not Match      | left-to-right | `string !~ regex_string` |                                            |
| 3          | Member Of            | left-to-right | `element _: array`       | Checks if `element` is in `array`.         |
| 2.5        | Bitwise AND          | left-to-right | `a & b`                  |                                            |
| 2.4        | Bitwise XOR          | left-to-right | `a ^ b`                  |                                            |
| 2.3        | Bitwise OR           | left-to-right | `a \| b`                | (escaped pipe for table)                   |
| 2          | Logical AND          | left-to-right | `a && b`, `a and b`      | `and` is an alias. Not short-circuiting in current stdlib impl. |
| 1.5        | Logical XOR          | left-to-right | `a ^^ b`, `a xor b`      | `xor` is an alias.                         |
| 1          | Logical OR           | left-to-right | `a \|\| b`, `a or b`     | `or` is an alias. Not short-circuiting in current stdlib impl. |
| 0          | Conditional (ternary)| right-to-left | `cond ? expr_if_true : expr_if_false` |      |
| 0          | Conditional (if-then-else) | left-to-right | `if cond then expr_if_true else expr_if_false` | |
| 0          | Scope Binding        | left-to-right | `let var = val in expr`  | See Variable Bindings.                     |

### 1.4. Variable Bindings (`let ... in ...`)

Milu uses `let ... in ...` expressions to introduce local bindings (variables or functions) that are available within a specific scope.

-   **Syntax**:
    ```milu
    let
        name1 = value1;
        name2 = value2;
        # ... more bindings
    in
        expression_using_bindings
    ```
-   Bindings are immutable. Once a name is bound to a value, it cannot be reassigned within the same `let` block's immediate scope.
-   Multiple bindings are separated by semicolons (`;`). A trailing semicolon after the last binding is optional.
-   The `in` keyword separates the binding declarations from the main expression of the `let` block. This main expression is what the entire `let ... in ...` construct evaluates to.
-   **Shadowing**: A binding inside a `let` expression can shadow a name from an outer scope.
    ```milu
    let x = 10 in (let x = 20 in x) # Evaluates to 20
    ```
-   Bindings are resolved lexically. An expression on the right-hand side of a binding (e.g., `let a = 1; b = a + 1 in ...`) refers to names defined in outer scopes or earlier in the *same* `let` block *if the language were eagerly evaluating or had specific support for sequential dependency within the block*. However, Milu's `let` block bindings are typically resolved against the outer scope *at the time of definition for the RHS expressions*, unless function closures are involved. For simple variable bindings, it's best to assume RHS expressions see the outer scope or previously fully defined variables in the same block.
    *Example:*
    ```milu
    let x = 5
    in
        let
            a = x + 1;  # 'x' is 5 from outer scope
            b = a * 2   # 'a' is (5+1)=6 from the binding above
        in
            a + b       # (6) + (12) = 18
    ```

### 1.5. Control Flow

Milu provides conditional evaluation through `if-then-else` expressions.

-   **`if ... then ... else ...`**:
    -   Syntax: `if condition then expression1 else expression2`
    -   The `condition` must evaluate to a Boolean.
    -   If `true`, `expression1` is evaluated and its result is returned.
    -   If `false`, `expression2` is evaluated and its result is returned.
    -   Both `expression1` and `expression2` must evaluate to the same type.
    -   Example: `if x > 10 then "large" else "small"`

-   **Ternary Conditional Operator `? :`**:
    -   Syntax: `condition ? expression1 : expression2`
    -   This is an alternative syntax for `if-then-else`.
    -   Example: `x > 10 ? "large" : "small"`

*(Note: Milu does not have traditional loop constructs like `for` or `while` as it emphasizes a functional, expression-based style. Iteration is typically achieved through built-in functions that operate on arrays or through recursion in user-defined functions.)*

### 1.6. Function Definition and Calls

-   **Function Definition (within `let` blocks)**:
    -   Functions are defined using a `let` binding syntax:
        ```milu
        let function_name(param1, param2, ...) = body_expression
        in
            # ... expression using function_name ...
        ```
    -   Example:
        ```milu
        let add(x, y) = x + y
        in
            add(5, 3) # Evaluates to 8
        ```
    -   Functions are first-class citizens and capture their lexical environment (closures).
    -   Recursive functions are supported:
        ```milu
        let factorial(n) = if n == 0 then 1 else n * factorial(n - 1)
        in
            factorial(5) # Evaluates to 120
        ```
    -   Currently, explicit type annotations for parameters or return types in function definitions are not supported in the syntax. Type inference is used.

-   **Function Calls**:
    -   Syntax: `function_name(argument1, argument2, ...)`
    -   Arguments are evaluated before the function call.
    -   Example: `split("a,b,c", ",")`

### 1.7. Accessors

-   **Array Element Access**:
    -   Syntax: `my_array[index]`
    -   `index` is 0-based.
    -   Negative indices are supported: `-1` refers to the last element, `-2` to the second last, and so on.
    -   Accessing an out-of-bounds index results in a runtime error.
    -   Example: `let arr = [10, 20, 30] in arr[1]` (evaluates to `20`), `arr[-1]` (evaluates to `30`).

-   **Tuple Element Access**:
    -   Syntax: `my_tuple.N` (e.g., `my_tuple.0`, `my_tuple.1`)
    -   Description: Accesses the element at the 0-based position `N` in the tuple.
    -   Example: `let t = (10, "x", true) in t.0` (evaluates to `10`), `t.1` (evaluates to `"x"`).

-   **Native Object Property Access**:
    -   Syntax: `my_object.property_name`
    -   Example: `request.source.host`

## Part 2: Standard Library and Operators

Milu provides a set of built-in operators and functions for common operations. Operators are the primary way to perform these actions. Underlying functions (like `Plus`, `Not`, etc.) implement these operators but are not typically called directly by name.

### 2.1. Unary Operators

-   **Logical NOT (`!`)**
    -   Syntax: `!condition`
    -   Operand: `condition` must be a Boolean.
    -   Description: Returns the logical negation of the `condition`.
    -   Example: `!true` evaluates to `false`.
    -   *(Internal function: `Not`)*

-   **Bitwise NOT (`~`)**
    -   Syntax: `~integer`
    -   Operand: `integer` must be an Integer.
    -   Description: Returns the bitwise complement of the `integer`.
    -   Example: `~0` evaluates to `-1`.
    -   *(Internal function: `BitNot`)*

-   **Unary Negation (`-`)**
    -   Syntax: `-number`
    -   Operand: `number` must be an Integer.
    -   Description: Returns the negation of the `number`.
    -   Example: `-5` evaluates to `-5`; `-(-5)` evaluates to `5`.
    -   *(Internal function: `Negative`)*

### 2.2. Arithmetic Operators

These operators work on Integer operands.

-   **Multiplication (`*`)**: `a * b`
-   **Division (`/`)**: `a / b` (Error on division by zero)
-   **Remainder (`%`)**: `a % b` (Error on division by zero)
-   **Addition (`+`)**: `a + b`
-   **Subtraction (`-`)**: `a - b`
    -   Operands: `a` and `b` must be Integers.
    -   Return Type: Integer.
    -   Examples:
        -   `5 * 3` evaluates to `15`.
        -   `15 / 3` evaluates to `5`.
        -   `15 % 4` evaluates to `3`.
        -   `5 + 3` evaluates to `8`.
        -   `5 - 3` evaluates to `2`.
    -   *(Internal functions: `Multiply`, `Divide`, `Mod`, `Plus`, `Minus`)*

### 2.3. Bitwise Shift Operators

These operators work on Integer operands.

-   **Bitwise Left Shift (`<<`)**: `a << b`
-   **Bitwise Right Shift (`>>`)**: `a >> b` (Arithmetic shift)
-   **Bitwise Unsigned Right Shift (`>>>`)**: `a >>> b` (Logical shift, treats `a` as unsigned)
    -   Operands: `a` (value to shift) and `b` (number of positions) must be Integers.
    -   Return Type: Integer.
    -   Examples:
        -   `1 << 2` evaluates to `4`.
        -   `-8 >> 1` evaluates to `-4`.
        -   `ShiftRightUnsigned(-8, 1)` (evaluates to `(-8 as u64) >> 1`, a large positive number).
        -   `8 >>> 1` evaluates to `4`. (Same as `8 >> 1` for positive numbers).
    -   *(Internal functions: `ShiftLeft`, `ShiftRight`, `ShiftRightUnsigned`)*

### 2.4. Comparison Operators

These operators compare two values. For `==` and `!=`, if types are different, they return `false` and `true` respectively. For other comparison operators, operands are typically expected to be of the same compatible type (Integer, String).

-   **Less Than (`<`)**: `a < b`
-   **Less Than Or Equal (`<=`)**: `a <= b`
-   **Greater Than (`>`)**: `a > b`
-   **Greater Than Or Equal (`>=`)**: `a >= b`
-   **Equality (`==`)**: `a == b`
-   **Inequality (`!=`)**: `a != b`
    -   Operands: `a` and `b` can be of type Any.
    -   Return Type: Boolean.
    -   Examples:
        -   `5 > 3` evaluates to `true`.
        -   `"apple" == "apple"` evaluates to `true`.
        -   `5 == "5"` evaluates to `false` (different types).
        -   `5 != "5"` evaluates to `true`.
    -   *(Internal functions: `Lesser`, `LesserOrEqual`, `Greater`, `GreaterOrEqual`, `Equal`, `NotEqual`)*

### 2.5. Regex Operators

-   **Regex Match (`=~`)**: `text =~ pattern`
    -   Operands: `text` (String) and `pattern` (String, a valid regex).
    -   Description: Returns `true` if `text` matches the regex `pattern`.
    -   Error: If `pattern` is an invalid regex.
    -   Example: `"hello" =~ "^h"` evaluates to `true`.
    -   *(Internal function: `Like`)*

-   **Regex Not Match (`!~`)**: `text !~ pattern`
    -   Operands: `text` (String) and `pattern` (String, a valid regex).
    -   Description: Returns `true` if `text` does not match the regex `pattern`.
    -   Error: If `pattern` is an invalid regex.
    -   Example: `"hello" !~ "^h"` evaluates to `false`.
    -   *(Internal function: `NotLike`)*

### 2.6. Membership Operator

-   **Member Of (`_:`)**: `element _: list`
    -   Operands: `element` (Any) and `list` (Array).
    -   Description: Checks if `element` is present in the `list`. Requires `element` to be of the same type as the elements in `list`.
    -   Example: `2 _: [1, 2, 3]` evaluates to `true`.
    -   *(Internal function: `IsMemberOf`)*

### 2.7. Bitwise Logical Operators

These operators work on Integer operands.

-   **Bitwise AND (`&`)**: `a & b`
-   **Bitwise XOR (`^`)**: `a ^ b`
-   **Bitwise OR (`|`)**: `a | b`
    -   Operands: `a` and `b` must be Integers.
    -   Return Type: Integer.
    -   Examples:
        -   `5 & 3` (binary `101 & 011`) evaluates to `1`.
        -   `5 ^ 3` (binary `101 ^ 011`) evaluates to `6`.
        -   `5 | 3` (binary `101 | 011`) evaluates to `7`.
    -   *(Internal functions: `BitAnd`, `BitXor`, `BitOr`)*

### 2.8. Logical Operators

These operators work on Boolean operands. They also have keyword aliases (`and`, `or`, `xor`).
*(Note: The standard library implementations currently evaluate both operands before performing the logical operation, so they do not short-circuit.)*

-   **Logical AND (`&&` or `and`)**: `a && b` or `a and b`
-   **Logical XOR (`^^` or `xor`)**: `a ^^ b` or `a xor b` (Note: `xor` alias might not be standard, `^^` is primary)
-   **Logical OR (`||` or `or`)**: `a || b` or `a or b`
    -   Operands: `a` and `b` must be Booleans.
    -   Return Type: Boolean.
    -   Examples:
        -   `true && false` evaluates to `false`.
        -   `true or false` evaluates to `true`.
    -   *(Internal functions: `And`, `Xor`, `Or`)*

### 2.9. Built-in Functions

These functions are called by their names and do not have direct operator syntax.

-   **`to_string(value: Any) => String`**
    -   Description: Converts any Milu value to its string representation.
    -   Examples:
        -   `to_string(123)` evaluates to `"123"`.
        -   `to_string(true)` evaluates to `"true"`.
        -   `to_string([1, 2])` evaluates to `"[1,2]"`.
        -   `to_string((1, "a"))` evaluates to `"(1,"a")"`.

-   **`to_integer(value: String) => Integer`**
    -   Description: Converts a string representation of an integer to an Integer type.
    -   Error: If the string cannot be parsed into an integer.
    -   Example: `to_integer("123")` evaluates to `123`.

-   **`split(text: String, delimiter: String) => Array[String]`**
    -   Description: Splits the `text` string by the `delimiter` string and returns an array of substrings.
    -   Examples:
        -   `split("a,b,c", ",")` evaluates to `["a", "b", "c"]`.
        -   `split("apple", "")` evaluates to `["", "a", "p", "p", "l", "e", ""]`.

-   **`strcat(parts: Array[String]) => String`**
    -   Description: Concatenates an array of strings into a single string. Useful with template strings or `Split`.
    -   Example: `strcat(["hello", " ", "world"])` evaluates to `"hello world"`.

-   **`cidr_match(ip_address: String, cidr_pattern: String) => Boolean`**
    -   Description: (Context-Specific, e.g., for Rule Filters) Checks if the given `ip_address` (string) falls within the specified `cidr_pattern` (string, e.g., "192.168.1.0/24").
    -   Returns `false` if IP address or CIDR pattern is invalid.
    -   Example: `cidr_match(request.source.host, "192.168.0.0/16")`

*(Note: Some internal stdlib function names like `Index`, `Access`, `If`, `Scope` correspond to syntactic constructs (`[]`, `.`, `if/?:`, `let in`) and are not called directly by these names.)*

## Part 3: Practical Examples

This section provides examples of how Milu can be used, particularly in the context of this proxy (e.g., for rule filters or custom log formats).

### 3.1. Rule Filter Examples

Rule filters determine if a rule should be applied to a request. They must evaluate to a Boolean.

1.  **Block requests from a specific IP address:**
    ```milu
    request.source.host == "192.168.1.100"
    ```
    *Usage in `config.yaml` rule:*
    ```yaml
    # rules:
    #   - filter: request.source.host == "192.168.1.100"
    #     target: deny
    ```

2.  **Allow only requests to a specific domain:**
    ```milu
    request.target.host == "example.com"
    ```

3.  **Block requests to any `.internal` TLD:**
    ```milu
    request.target.host =~ "\\.internal$"
    ```
    *Explanation: `request.target.host =~ "\\.internal$"` uses the regex match operator `=~`. The pattern `\\.internal$` matches any host ending with `.internal`. Note the double backslash `\\` to ensure a literal backslash is passed to the regex engine for the dot `.`.*

4.  **Route traffic based on listener name and target port:**
    ```milu
    request.listener == "http_proxy" && request.target.port == 8080
    ```

5.  **Using `let` for complex conditions:**
    ```milu
    let
        is_local_subnet = cidr_match(request.source.host, "192.168.1.0/24");
        is_admin_user = request.source.host == "10.0.0.1"; # Assuming admin has a static IP
    in
        is_local_subnet && !is_admin_user # Allow local subnet but not if it's the admin
    ```

6.  **Deny requests to common local/private CIDR blocks if not coming from localhost:**
    ```milu
    let
        target_ip = request.target.host; # Assuming target.host is an IP string
        is_private_target = cidr_match(target_ip, "10.0.0.0/8") ||
                            cidr_match(target_ip, "172.16.0.0/12") ||
                            cidr_match(target_ip, "192.168.0.0/16") ||
                            cidr_match(target_ip, "127.0.0.0/8") ||
                            target_ip == "localhost";
        is_from_localhost = request.source.host == "127.0.0.1";
    in
        is_private_target && !is_from_localhost
    ```
    *Usage in `config.yaml` rule (to deny such requests):*
    ```yaml
    # rules:
    #   - filter: |
    #       let
    #           target_ip = request.target.host;
    #           is_private_target = cidr_match(target_ip, "10.0.0.0/8") ||
    #                               cidr_match(target_ip, "172.16.0.0/12") ||
    #                               cidr_match(target_ip, "192.168.0.0/16") ||
    #                               cidr_match(target_ip, "127.0.0.0/8") ||
    #                               target_ip == "localhost";
    #           is_from_localhost = request.source.host == "127.0.0.1";
    #       in
    #           is_private_target && !is_from_localhost
    #     target: deny
    ```

### 3.2. Access Log Formatting Examples

If using `format: {script: "..."}` for `accessLog` in `config.yaml`.

1.  **Simple space-separated log:**
    ```milu
    # Milu script for accessLog format:
    `src=${request.source} dst=${request.target} listener=${request.listener} connector=${request.connector}`
    ```
    *Output Example:*
    `src=192.168.1.50:12345 dst=example.com:80 listener=http_listener connector=direct_connector`

2.  **Custom structured log using string concatenation and `ToString`:**
    ```milu
    # Milu script for accessLog format:
    let
        timestamp_placeholder = "TODO_GET_TIMESTAMP_FUNCTION"; # Assuming a timestamp function isn't available yet
        log_parts = [
            "[", timestamp_placeholder, "] ",
            "Source: ", request.source, ", ",
            "Target: ", request.target, ", ",
            "TargetType: ", request.target.type, ", ",
            "Listener: ", request.listener,
            if request.connector != "" then ", Connector: " + request.connector else ""
        ]
    in
        strcat(log_parts)
    ```
    *Output Example (if `request.connector` is set):*
    `[TODO_GET_TIMESTAMP_FUNCTION] Source: 10.1.1.10:54321, Target: api.example.com:443, TargetType: domain, Listener: https_listener, Connector: upstream_proxy`

    *Output Example (if `request.connector` is empty):*
    `[TODO_GET_TIMESTAMP_FUNCTION] Source: 10.1.1.10:54321, Target: api.example.com:443, TargetType: domain, Listener: https_listener`

*(Note: The availability of specific fields like `request.connector` might depend on when the log entry is generated in the proxy's lifecycle.)*
