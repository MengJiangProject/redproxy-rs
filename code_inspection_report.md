# Code Inspection Report

This document outlines findings from a manual inspection of critical code sections.
The inspection focuses on potential issues such as overly complex code, lack of tests,
code duplication, performance bottlenecks, and missing or outdated documentation.

## 1. Network Protocol Implementations

### 1.1. `src/common/socks.rs` (SOCKS Protocol)

*   **Overall:** Implements SOCKSv4 and SOCKSv5, including authentication (NoAuth, PasswordAuth) and UDP frame handling.
*   **Complexity:**
    *   Moderately complex due to protocol details and generic authentication.
    *   `frames` submodule for UDP adds a layer of complexity.
*   **Tests:**
    *   Good unit test coverage for request/response parsing and writing (v4, v5, auth).
    *   UDP frame encoding/decoding is tested.
    *   **Potential Gap:** Lack of integration-style tests for full SOCKS handshakes. The `todo.md` lists BIND and UDP ASSOCIATE as incomplete, which implies test gaps.
*   **Code Duplication:**
    *   Some structural similarity in `read_v4`/`read_v5`, `write_v4`/`write_v5`.
    *   Address parsing logic (INET4, DOMAIN, INET6) is repeated in several places (request reading, response reading, UDP frame decoding/encoding). Consider refactoring into a helper.
*   **Performance:**
    *   Uses `async/await` appropriately.
    *   Byte-by-byte reading in handshakes is typical but could be a minor bottleneck under extreme load.
    *   String allocations for domains/credentials are acceptable for most proxy scenarios.
*   **Documentation/Clarity:**
    *   Well-defined constants.
    *   Descriptive function names.
    *   Inline comments are present but could be more comprehensive, especially for authentication and less common SOCKS features.
    *   **Missing:** Module-level documentation explaining the SOCKS implementation overview and capabilities.
*   **Error Handling:**
    *   Uses `easy_error` with context, which is good.
    *   Error messages are generally reasonable.
*   **Outstanding TODOs:**
    *   `todo.md`: "support BIND and UDP ASSOCIATE in socks protocol." Implementation and tests for these commands might be incomplete.

### 1.2. `src/common/http.rs` (HTTP Protocol)

*   **Overall:** Basic HTTP/1.x request/response header parser. Does not handle message bodies.
*   **Complexity:**
    *   Straightforward for its scope (header parsing).
*   **Tests:**
    *   Basic unit tests for request/response parsing.
    *   **Potential Gaps:**
        *   Edge cases in header parsing (malformed headers, casing, empty values).
        *   No tests for `write_to` or `write_with_body` methods.
*   **Code Duplication:**
    *   `HttpRequest::write_to` and `HttpResponse::write_to` share very similar logic for writing the initial line and headers. Could be refactored.
    *   The `header()` method for retrieving a header value is identical in `HttpRequest` and `HttpResponse`. Could be a trait method or a free function.
*   **Performance:**
    *   `read_line` allocates Strings per line, acceptable for many proxy uses but not for ultra-high performance.
    *   Multiple small `write` calls for headers; buffering could offer minor gains.
*   **Documentation/Clarity:**
    *   Generally clear code and method names.
    *   **Missing:** Module-level documentation (e.g., scope of the parser, what it doesn't handle like bodies, HTTP/2).
*   **Error Handling:**
    *   Uses `easy_error`. Error messages could be more specific regarding the location/nature of parsing errors.
*   **Outstanding TODOs:**
    *   `todo.md`: "support HTTP GET/POST in h11c parsers." This parser is a prerequisite but doesn't handle bodies, which are essential for POST.

## 2. `milu` Scripting Language (`milu/src/`)

*   **Overall Design:**
    *   Expression-oriented scripting language.
    *   Parser (`nom`) builds an AST represented by the `Value` enum, which also serves as runtime values.
    *   Supports integers, strings, booleans, arrays, tuples, identifiers, operator/function calls, user-defined functions, and native Rust object interop.
    *   Evaluation uses an `Evaluatable` trait.
    *   `ScriptContext` handles scoped variable/function lookup and built-ins.
    *   Includes a standard library (`stdlib`).
*   **Parser (`milu/src/parser/`)**:
    *   Uses `nom` parser combinators. `rules.rs` defines the grammar with macros.
    *   Covers literals, identifiers, collections, operators, if/else, let bindings, and function definitions.
    *   Separate parsing for strings and template strings.
    *   Error handling via `SyntaxError` wrapping `nom` errors.
*   **Script Engine (`milu/src/script/`)**:
    *   `value.rs`: Defines `Value`, evaluation logic (`type_of`, `value_of`), and dependency tracking (`unresovled_ids`).
    *   `types.rs`: Defines the `Type` system.
    *   `functions.rs`: Defines `Call`, `UserDefinedFunction`, `ParsedFunction`, and the `Callable` trait.
    *   `context.rs`: `ScriptContext` for scoping and stdlib function registration.
    *   `stdlib/`: Implements built-in functions.
*   **Potential Issues & Areas for Review:**
    *   **Complexity:**
        *   `nom` parser rules in `rules.rs` can be dense and complex, typical for such grammars.
        *   The dual role of `Value` (AST node & runtime value) is common but leads to a large enum.
    *   **Tests:**
        *   Parser tests (`milu/src/parser/tests.rs`) and script execution tests (`milu/src/script/tests.rs`) exist.
        *   `milu/todo.md` lists many significant planned features (full function definitions, generics, pattern matching, currying). Test coverage for these is N/A. The thoroughness of current feature testing should be verified by examining test files.
    *   **Code Duplication:**
        *   Macros like `op_rule!` (parser) and `cast_value!` (script values) effectively reduce boilerplate.
        *   Stdlib function implementation might have some boilerplate if `NativeCallable` (or equivalent) abstraction is insufficient.
    *   **Performance Bottlenecks:**
        *   Typical tree-walking interpreter performance characteristics apply.
        *   Cloning of `Value` (even with `Arc` for collections) might occur during evaluation.
        *   Deep recursion in `value_of`/`type_of` could lead to stack issues for very complex scripts.
    *   **Documentation/Clarity:**
        *   `MILU_LANG_GUIDE.md` is a positive asset for language users.
        *   Internal code comments in `milu/src/` appear sparse in some complex areas (e.g., `nom` rules).
        *   The lifecycle and distinction between `ParsedFunction` and `UserDefinedFunction` could be better documented internally.
        *   Many parser functions in `rules.rs` are `pub` due to macro usage; their visibility should be reviewed.
    *   **Error Handling:**
        *   Consistent use of `SyntaxError` for parsing and `easy_error::Error` for runtime.
        *   Runtime stack traces might be limited without explicit construction.
    *   **Outstanding TODOs (from `milu/todo.md`):**
        *   Significant language features are planned: enhanced operators, array concatenation, full function definitions, generic function signatures, `do` blocks, pattern matching, and currying. This indicates the language is actively evolving.

## 3. Configuration Loading (`src/config.rs`)

*   **Overall Design:**
    *   `Config` struct defines the main configuration structure.
    *   Uses `serde` and `serde_yaml_ng` for parsing YAML configuration files.
    *   `Config::load(path)` handles file reading and deserialization.
    *   Key sections (`listeners`, `connectors`, `rules`) are `serde_yaml_ng::Sequence`, with parsing delegated to respective modules.
    *   Supports optional features (`metrics`, `access_log`) via `cfg` attributes.
    *   `Timeouts` and `IoParams` structs provide default values.
*   **Complexity:**
    *   `src/config.rs` itself is simple. Complexity is in `serde` and the modules handling specific sections (listeners, connectors, rules).
*   **Milu Script Integration (confirmed in `src/rules/mod.rs` and `src/rules/filter.rs`):**
    *   The `filter` field within a rule definition in the YAML configuration is a string containing a Milu script.
    *   On loading (`Rule::init`), this script string is parsed by `milu::parser::parse` into a Milu AST (`Value`), which is stored.
    *   `Filter::validate` performs a basic type check on the script (ensures boolean return).
    *   During evaluation (`Filter::evaluate`), a `ScriptContext` is created with request-specific variables, and the Milu script AST is executed using `value_of(ctx)`.
*   **Tests:**
    *   `test_load` in `src/config.rs` checks if `config.yaml` can be loaded and parsed by module-specific `from_config` functions without panic.
    *   **Potential Gap:** Test doesn't assert content or behavior of the loaded config. More specific tests for various config options (especially for rules and Milu script integration) should reside in respective modules.
*   **Code Duplication:**
    *   Minimal within `src/config.rs`.
*   **Performance:**
    *   Async file I/O. YAML parsing overhead is acceptable for startup. Milu script parsing also happens at init/reload. Rule evaluation performance depends on script complexity and Milu interpreter efficiency.
*   **Documentation/Clarity:**
    *   Struct/field names are descriptive. `camelCase` for YAML keys is good.
    *   Minimal comments in `src/config.rs`. Module-level documentation explaining the overall structure and referencing `CONFIG_GUIDE.md` would be beneficial.
    *   Use of `serde_yaml_ng::Sequence` defers concrete type understanding to other modules.
*   **Error Handling:**
    *   Consistent use of `easy_error` with context.
*   **Outstanding TODOs:**
    *   `todo.md`: "full config reload, currently only rules are hot replacable." Current loading is for startup; full hot-reloading is a more complex feature.

## 4. General Error Handling

*   **Overall Pattern:**
    *   Consistent use of the `easy_error` crate across modules (SOCKS, HTTP, config, Milu runtime, rules).
    *   `ResultExt` trait is used to add contextual information to errors.
    *   `bail!` and `err_msg` macros are commonly used for error generation.
*   **Strengths:**
    *   Provides a uniform approach to error handling.
    *   Contextual information aids in debugging.
*   **Potential Areas for Review:**
    *   For components intended as libraries (e.g., potentially `milu`), defining more specific, typed errors rather than relying solely on string messages can enhance usability for programmatic error handling by consumers. For the main application, the current approach might be sufficient.
    *   Stack trace information for errors originating from Milu scripts or deep within the application logic might be limited unless explicitly captured and propagated.

---
This concludes the initial code inspection based on the specified areas. Further deep dives into test coverage for each module and performance profiling would provide more detailed insights.
