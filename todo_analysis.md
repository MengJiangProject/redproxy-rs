# Analysis of TODO Files

This document lists the incomplete features and tasks found in `todo.md` and `milu/todo.md`.

## Incomplete Tasks from `todo.md` (Root Directory)

*   **SOCKS Protocol:** Support BIND and UDP ASSOCIATE operations.
*   **H11C Parsers:** Implement support for HTTP GET/POST methods.
*   **GraphQL Integration:** Explore potential GraphQL integration.
*   **Configuration Reload:** Enable full configuration reload, not just rules.
*   **Flow Tap:** Implement flow tapping capabilities. (Note: Challenges exist in generating L3 packets from L4 protocol data).

## Incomplete Tasks from `milu/todo.md` (Milu Language)

*   **Operators:**
    *   Combine bitwise and logical operators (e.g., change `1&2` to `1&&2`).
    *   Free up the `|` operator for other potential uses.
*   **Array Manipulation:**
    *   Implement array concatenation (e.g., `[1|[2,3]] == [1,2,3]`).
*   **Functions:**
    *   Add support for function definitions using the syntax `fun {id,}+ = expr`.
    *   Implement generic function signatures (e.g., `to_string(a) : Any->string`, `repeat(x,n) : T -> integer -> [T]`).
    *   Enable currying of functions.
*   **Control Flow & Syntax:**
    *   Introduce `do` block definitions for sequential execution and variable scoping.
    *   Implement pattern matching capabilities (e.g., `let [a|b] = [1,2,3] in (1,[2,3]) == (a,b)`).
