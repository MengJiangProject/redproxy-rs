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
- [ ] todo: access tuple member by index

```
(1,2,3).1 == 2
```

---
- [ ] todo: array contcat
```
[1|[2,3]] == [1,2,3]
```

---
- [ ] todo: add function definition
```
let fib(a) : int->[int] =
    let n = fib(a-1);
        x = a + n[0];
    in
        if a == 1
        then [1]
        else [x|n]
in fib(10)
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