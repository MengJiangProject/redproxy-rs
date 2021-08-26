- [x] done: basic expression evaluation
```
1+1=2
```
---
- [x] done: builtin functions
```
split("a,b",",") == ["a","b"]
```

---
- [x] done: static type inference

```
[1,2,3] : array[integer]
```

---
- [x] done: access array by index, access object by identifier
```
[1,2,3][0] == 1
a.b == c
```
---
- [x] done: `if ... then ... else` and `:?` opreator

```
if a==b then c else d
```
---
- [x] done: inline comments `/* ... */` and line comments `# ... `
```
#comments
[1/*comments */,2/**/,3]
```

---
- [x] done: memberof opreator 
```
1 in [1,2,3]
```

---
- [x] done: let expression
```
let 
    a=1;
    b=a*2;
in a+b
```

compiles to AST:
```
scope
    array
        tuple
            a
            1
        tuple
            b
            2
    call
        plus
        a
        b
```
---
- [x] done: access tuple member by index

```
(1,2,3).1 == 2
```

---
- [ ] todo: combine bitwise operator with with logical operator

change `1&2` to `1&&2`, free the `|` opreator for later use.

---
- [ ] todo: array contcat
```
[1|[2,3]] == [1,2,3]
```

---
- [ ] todo: add function definition
```
syntax: fun {id,}+ = expr 

example:
let fib a = 
        if a == 1 or a == 2
        then 1
        else fib(a-2)+fib(a-1)
in let x=10 in fib(x)

ast:

let
    [tuple]
        id: fib
        func:
            [tuple]: (a,int)
            if 
                a == 1 or a == 2
                1
                fib(a-2)+fib(a-1)
```
---
- [ ] todo: generic funtion signatures:

```
to_string(a) : Any->string
to_integer(a) : string->int
split(s,d) : string->string->[string]
repeat(x,n) : T -> integer -> [T]
```

---
- [ ] todo: do block definition
```
do
    let x = 1;
    let y = x;
    let x = 2;
    (x,y) == (2,1)
```
---
- [ ] todo: pattern match
let [a|b] = [1,2,3] in (1,[2,3]) == (a,b) 

---
- [ ] todo: curry functions

```
let plus(a,b) : integer -> integer -> integer = a+b
in let x = plus(1) in x(2)
```

AST:
let
    [tuple]
        plus
        func
            (a,b)
            (integer,integer,integer)
            plus
                a
                b
    let
        [tuple]
            x
            call
                plus
                [1]
        call
            x
            2

type_of(call(x,2))
    type_of(x,[2])
        type_of(call(plus,1))
            type_of(plus,[1]) as int -> int
        as int -> int
    as int
as int

value_of(call(x,2))
    value_of(x,[2])
        value_of(call(plus,1))
            value_of(plus,[1])
                value_of(+,[a,b])
                    value_of(a) = 1
                    value_of(b) = 2
                = 3
            = 3
        = 3
    = 3
= 3

combinator:
let
    plus(a,b) : int->int->int = a+b
    carry(fn,x) : (int->int->int)->int->int = fn(x)
in
    carry(plus,1)(2)