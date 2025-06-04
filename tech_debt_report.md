# Technical Debt Report

This report consolidates findings from code TODOs, `todo.md` files, dependency analysis, and detailed code inspections. It aims to provide a comprehensive overview of identified technical debt, categorized and prioritized to guide future development efforts.

## Prioritization Levels

*   **High:** Items with significant impact on security, core functionality, stability, or those that introduce major development friction.
*   **Medium:** Items important for maintainability, future development, robustness, or moderate feature enhancements.
*   **Low:** Nice-to-haves, minor code clarity improvements, or low-impact documentation tasks.

## 1. Feature Gaps & Incomplete Implementations

This section covers missing features, incomplete protocol support, and planned enhancements for the Milu scripting language.

### 1.1. Core Application Features

*   **Full Configuration Reload:** Currently, only rules are hot-reloadable. Implementing full config reload (listeners, connectors) is crucial for dynamic environments.
    *   *Source:* `todo.md`, Code Inspection (`src/config.rs`)
    *   *Priority:* **Medium**
*   **Load Balancing Algorithms:** The existing algorithms in `src/connectors/loadbalance.rs` are marked as not yet ready due to data collection challenges.
    *   *Source:* `TODO_documentation.md`
    *   *Priority:* **Medium**
*   **SOCKS Protocol - BIND and UDP ASSOCIATE:** Support for these SOCKS commands is pending.
    *   *Source:* `todo.md`, Code Inspection (`src/common/socks.rs`)
    *   *Priority:* **Medium**
*   **H11C Parsers - HTTP GET/POST Support:** Full support for GET/POST methods in h11c parsers needs implementation, particularly body handling.
    *   *Source:* `todo.md`, Code Inspection (`src/common/http.rs`)
    *   *Priority:* **Medium**
*   **GraphQL Integration:** Exploration for potential GraphQL integration is listed as a future task.
    *   *Source:* `todo.md`
    *   *Priority:* **Low**
*   **Flow Tap:** Implementation for flow tapping capabilities is a pending feature.
    *   *Source:* `todo.md`
    *   *Priority:* **Low**

### 1.2. Milu Scripting Language Enhancements

*   **Function Definitions:** Adding full support for user-defined functions (`fun {id,}+ = expr`) is critical for language usability and expressiveness.
    *   *Source:* `milu/todo.md`
    *   *Priority:* **High**
*   **Generic Function Signatures:** Implementing generic type signatures for functions (e.g., `to_string(a) : Any->string`).
    *   *Source:* `milu/todo.md`
    *   *Priority:* **Medium**
*   **`do` Block:** Introduce `do` blocks for sequential execution and clearer scoping.
    *   *Source:* `milu/todo.md`
    *   *Priority:* **Medium**
*   **Pattern Matching:** Add pattern matching capabilities (e.g., `let [a|b] = [1,2,3]`).
    *   *Source:* `milu/todo.md`
    *   *Priority:* **Medium**
*   **Array Concatenation:** Implement array concatenation operators/functions.
    *   *Source:* `milu/todo.md`
    *   *Priority:* **Low**
*   **Currying Functions:** Enable currying for Milu functions.
    *   *Source:* `milu/todo.md`
    *   *Priority:* **Low**

## 2. Security Vulnerabilities & Risks

*   **Rate Limiting and DDoS Protection:** The authentication common code (`src/common/auth.rs`) has a TODO for implementing rate limiting and DDoS protection. This is crucial for service robustness and security.
    *   *Source:* `TODO_documentation.md`
    *   *Priority:* **High**

## 3. Test Coverage Gaps

*   **SOCKS Protocol Integration Tests:** Lack of integration-style tests for full SOCKS handshakes (v4/v5, auth, BIND, UDP Associate).
    *   *Source:* Code Inspection (`src/common/socks.rs`)
    *   *Priority:* **Medium**
*   **HTTP Protocol Tests:**
    *   Edge cases in header parsing (malformed headers, casing, etc.).
    *   No tests for `write_to` or `write_with_body` methods.
    *   *Source:* Code Inspection (`src/common/http.rs`)
    *   *Priority:* **Low**
*   **Milu Scripting Language Tests:**
    *   Verify thoroughness of current parser and script execution tests.
    *   Add test coverage for new Milu features as they are implemented.
    *   *Source:* Code Inspection (`milu/src/`)
    *   *Priority:* **Medium**
*   **Configuration Loading Tests:** Current tests only check if loading panics. Need tests to assert correct parsing of various configuration options and behaviors, especially for rules and Milu script integration.
    *   *Source:* Code Inspection (`src/config.rs`)
    *   *Priority:* **Medium**

## 4. Code Quality & Maintainability

### 4.1. Application Code
*   **SOCKS Address Parsing Duplication:** Address parsing logic (INET4, DOMAIN, INET6) is repeated in several places in `src/common/socks.rs`. Refactor into a shared helper.
    *   *Source:* Code Inspection
    *   *Priority:* **Low**
*   **HTTP `write_to` and `header()` Duplication:** Logic for writing headers and retrieving header values is duplicated in `HttpRequest` and `HttpResponse` in `src/common/http.rs`.
    *   *Source:* Code Inspection
    *   *Priority:* **Low**
*   **Rust Specialization:** A TODO in `src/context.rs` suggests using Rust's specialization feature when it's ready for potential performance/clarity gains.
    *   *Source:* `TODO_documentation.md`
    *   *Priority:* **Low**

### 4.2. Milu Scripting Language Code
*   **Parser Rule Complexity:** `nom` parser rules in `milu/src/parser/rules.rs` are dense. Improving clarity with comments or refactoring could aid maintainability.
    *   *Source:* Code Inspection
    *   *Priority:* **Medium** (if actively causing maintenance issues)
*   **Operator Logic (`1&2` vs `1&&2`):** Planned change in Milu to differentiate bitwise and logical operators.
    *   *Source:* `milu/todo.md`
    *   *Priority:* **Low**
*   **Review Visibility of Parser Functions:** Many parser functions in `milu/src/parser/rules.rs` are `pub` due to macro usage; review if this is necessary.
    *   *Source:* Code Inspection
    *   *Priority:* **Low**

### 4.3. Error Handling & Debugging
*   **Limited Runtime Stack Traces:** Errors from Milu scripts or deep application logic might have limited stack trace information. Enhancing this would aid debugging.
    *   *Source:* Code Inspection (Milu, General)
    *   *Priority:* **Medium**
*   **Specific Error Types for Milu (as a library):** If Milu is intended for use as a standalone library, more specific error types would be beneficial over generic string messages.
    *   *Source:* Code Inspection
    *   *Priority:* **Low** (for current application context)

## 5. Documentation Deficiencies

### 5.1. Code-Level Documentation
*   **SOCKS Module (`src/common/socks.rs`):** Missing module-level documentation explaining implementation overview and capabilities. Inline comments could be more comprehensive for auth/less common features.
    *   *Source:* Code Inspection
    *   *Priority:* **Low**
*   **HTTP Module (`src/common/http.rs`):** Missing module-level documentation (scope, features not handled e.g., bodies, HTTP/2).
    *   *Source:* Code Inspection
    *   *Priority:* **Low**
*   **Milu Internal Documentation:**
    *   Sparse comments in complex areas like `nom` parser rules.
    *   Lifecycle and distinction between `ParsedFunction` and `UserDefinedFunction` could be better documented.
    *   *Source:* Code Inspection (`milu/src/`)
    *   *Priority:* **Medium**
*   **Configuration Loading (`src/config.rs`):** Minimal comments. Module-level documentation explaining overall structure and referencing `CONFIG_GUIDE.md` would be good.
    *   *Source:* Code Inspection
    *   *Priority:* **Low**

### 5.2. User-Facing Documentation
*   While `MILU_LANG_GUIDE.md` exists, ensure `CONFIG_GUIDE.md` is comprehensive and referenced where appropriate. (Assumption based on good practice).

## 6. Dependency Management

*   **Cargo Dependencies:** Periodically check `Cargo.toml` dependencies against [crates.io](https://crates.io/) for outdated versions, especially those with security advisories or significant updates.
    *   *Source:* `cargo_dependencies.md`
    *   *Priority:* **Medium** (as a recurring task)
*   **Nix Flake Dependencies:** Periodically review Nix flake inputs (`flake.nix`) for updates by checking source repositories or running `nix flake update`.
    *   *Source:* `flake_dependencies.md`
    *   *Priority:* **Medium** (as a recurring task)

## 7. Performance Issues

*   **Milu Interpreter Performance:**
    *   Typical tree-walking interpreter characteristics: consider if performance for complex scripts meets requirements.
    *   Potential for `Value` cloning during evaluation.
    *   Deep recursion in `value_of`/`type_of` for complex scripts could be an issue.
    *   *Source:* Code Inspection (`milu/src/`)
    *   *Priority:* **Medium** (if current performance is a concern or for future complex use cases)
*   **Minor Protocol Optimizations:**
    *   SOCKS: Byte-by-byte reading in handshakes.
    *   HTTP: String allocations per line in `read_line`, multiple small writes for headers.
    *   These are likely minor but noted in the code inspection.
    *   *Source:* Code Inspection
    *   *Priority:* **Low**

This consolidated report should serve as a good starting point for addressing technical debt and planning future development cycles.I have now synthesized all the information from the previous reports and created the `tech_debt_report.md` file. This report includes categorized and prioritized technical debt items.

I will now submit the subtask.
