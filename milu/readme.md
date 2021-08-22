# Milu
Milu is a "[four-unlike](https://en.wikipedia.org/wiki/P%C3%A8re_David%27s_deer#Naming_and_etymology)" embeded DSL that is (or to be) 

- Statically typed
- Pure functional
- Lazy evaluated
- Heavyly over-designed
- Basicly copy-and-pasted

# Syntax

milu's syntax is like a a bit of haskell, and a bit of ocaml, some javascript, and `_:` opreator from swift. 
Each milu program is one and only one expression that evaluates into a value.

## Builtin operators and precedence

|Precedence|Operator|Associativity|Syntax|
|----------|--------|-------------|-------|
|99|Grouping|n/a|`( … )`|
|8|Access|left-to-right|`… . …`|
|8|Index|left-to-right|`… [ … ]`|
|8|Call|left-to-right|`… ( … )`|
|7|Logical NOT (!)|left-to-right|`! …`|
|7|Bitwise NOT (~)|left-to-right|`~ …`|
|7|Unary negation (-)|left-to-right|`- …`|
|6|Multiplication (*)|left-to-right|`… * …`|
|6|Division (/)|left-to-right|`… / …`|
|6|Remainder (%)|left-to-right|`… % …`|
|5|Addition (+)|left-to-right|`… + …`|
|5|Subtraction (-)|left-to-right|`… - …`|
|4.1|Bitwise Left Shift (<<)|left-to-right|`… << …`|
|4.1|Bitwise Right Shift (>>)|left-to-right|`… >> …`|
|4.1|Bitwise Unsigned Right Shift (>>>)|left-to-right|`… >>> …`|
|4|Less Than (<)|left-to-right|`… < …`|
|4|Less Than Or Equal (<=)|left-to-right|`… <= …`|
|4|Greater Than (>)|left-to-right|`… > …`|
|4|Greater Than Or Equal (>=)|left-to-right|`… >= …`|
|3|Equality (==)|left-to-right|`… == …`|
|3|Inequality (!=)|left-to-right|`… != …`|
|3|Regex Match (=~)|left-to-right|`… =~ …`|
|3|Regex Not Match (!~)|left-to-right|`… !~ …`|
|3|Member Of (_:)|left-to-right|`… _: …`|
|2.5|Bitwise AND (&)|left-to-right|`… & …`|
|2.4|Bitwise XOR (^)|left-to-right|`… ^ …`|
|2.3|Bitwise OR (\|) |left-to-right|`… \| …  `|
|2|Logical AND (&&)|left-to-right|`… && …` or `… and … `|
|1.5|Logical XOR (^^)|left-to-right|`… ^^ …` or `… xor … `|
|1|Logical OR (\|\|)|left-to-right|`… \|\| …` or `… or …`|
|0|Conditional (ternary) operator|right-to-left|`… ? … : …` or `if … then … else …`|
|0|Scope binding operator (let)|right-to-left|`let … = … in …`|