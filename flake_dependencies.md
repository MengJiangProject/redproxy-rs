# Nix Flake Dependencies

This file lists the Nix flake inputs (dependencies) as specified in `flake.nix`.

**Note:** Nix flakes manage dependencies differently from traditional package managers. Versions are often pinned to specific Git repository commits (managed by `flake.lock`, not directly visible in `flake.nix`) or track branches. For inputs sourced from GitHub or other repositories, "up-to-dateness" means checking the original repository for newer commits or releases on the tracked branch.

## Flake Inputs

1.  **fenix:**
    *   **Source URL:** `github:nix-community/fenix`
    *   **Description:** Provides Rust toolchains for Nix. Its `nixpkgs` input is configured to follow the main `nixpkgs` input of this flake, ensuring consistency.
    *   **Version Check:** To check for updates, review the `nix-community/fenix` GitHub repository for newer commits or tags.

2.  **flake-utils:**
    *   **Source URL:** `github:numtide/flake-utils`
    *   **Description:** A helper library for creating Nix flakes, simplifying the process of supporting multiple systems.
    *   **Version Check:** To check for updates, review the `numtide/flake-utils` GitHub repository for newer commits or tags.

3.  **nixpkgs:**
    *   **Source URL:** `nixpkgs/nixos-unstable`
    *   **Description:** The main Nix Packages collection, tracking the `nixos-unstable` branch. This provides the vast majority of system packages and build tools.
    *   **Version Check:** `nixos-unstable` is a rolling release branch. "Updating" typically involves running `nix flake update` which fetches the latest commit for this branch as per the flake's registry or input definition. To see what's new in `nixos-unstable` itself, one would check the commit history of the official Nixpkgs repository.
