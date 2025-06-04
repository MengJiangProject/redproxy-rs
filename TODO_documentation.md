# TODO Comments Documentation

This document lists and categorizes TODO comments found in the codebase (excluding markdown files).

## Findings

1.  **File:** `src/common/auth.rs`
    *   **Comment:** `//TODO: ratelimit and DDOS protection`
    *   **Category:** Security, Feature Enhancement
    *   **Action:** Implement rate limiting and DDoS protection mechanisms.

2.  **File:** `src/connectors/loadbalance.rs`
    *   **Comment:** `// TODO: Those Algorithms are not yet ready as i had to find a good way to collect data.`
    *   **Category:** Feature Enhancement, Load Balancing
    *   **Action:** Implement or complete load balancing algorithms. This may require further research or development on data collection methods.

3.  **File:** `src/context.rs`
    *   **Comment:** `// TODO: should use specialization when it's ready.`
    *   **Category:** Code Improvement, Performance
    *   **Action:** Refactor the code to use Rust's specialization feature when it becomes stable. This could potentially improve performance or code clarity.
