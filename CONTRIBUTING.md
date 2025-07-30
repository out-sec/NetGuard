# Contributing to NetGuard

Thank you for your interest in contributing to NetGuard, a high-performance Network Intrusion Detection System (NIDS). This document provides detailed guidelines to ensure a smooth and collaborative contribution process.

## Getting Started
1. **Fork the Repository**:
   Create a fork of the repository on GitHub by navigating to [https://github.com/out-sec/NetGuard](https://github.com/out-sec/NetGuard) and clicking "Fork".
2. **Clone Your Fork**:
   ```
   git clone https://github.com/your-username/NetGuard.git
   ```
3. **Set Up the Development Environment**:
   Follow the setup instructions in [DEVELOPMENT.md](DEVELOPMENT.md) to configure your environment.
4. **Create a Branch**:
   ```
   git checkout -b feature/your-feature-name
   ```
   Use descriptive branch names (e.g., `feature/add-dns-parser`, `bugfix/http-rule-parsing`).

## Contribution Process
1. **Identify an Issue**:
   Browse the [GitHub Issues](https://github.com/out-sec/NetGuard/issues) page to find tasks or propose a new feature/bug fix by opening an issue.
2. **Discuss Your Contribution**:
   For significant changes (e.g., new protocol parsers or major refactors), discuss your approach in the relevant issue to align with project goals.
3. **Implement Changes**:
   - Adhere to the coding standards outlined in [DEVELOPMENT.md](DEVELOPMENT.md).
   - Write clear, maintainable code with appropriate comments.
   - Add or update unit tests in the `tests/` directory.
   - Update documentation (e.g., `docs/design.md`) if your changes affect the architecture or usage.
4. **Commit Changes**:
   - Use clear, descriptive commit messages following the conventional commit format: `<type>(<scope>): <description>` (e.g., `feat(parsing): add DNS packet parser`).
   - Types include `feat` (new feature), `fix` (bug fix), `docs` (documentation), `test` (tests), etc.
5. **Submit a Pull Request**:
   - Push your branch to your fork:
     ```
     git push origin feature/your-feature-name
     ```
   - Open a pull request (PR) against the `main` branch of the main repository.
   - Provide a detailed PR description, including the purpose, changes made, and references to related issues (e.g., `Fixes #123`).
6. **Code Review**:
   - Address feedback from maintainers promptly.
   - Ensure all CI checks pass (if applicable).
   - Your PR will be merged once approved by at least one maintainer.

## Reporting Bugs
- Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) when opening a new issue.
- Include:
  - A clear description of the bug
  - Steps to reproduce
  - Expected and actual behavior
  - Environment details (OS, compiler, libpcap version)
  - Relevant logs or screenshots

## Suggesting Features
- Open a GitHub Issue with the `[Feature Request]` prefix in the title.
- Describe:
  - The feature and its use case
  - Potential implementation details
  - Any alternatives considered

## Code of Conduct
All contributors must adhere to the project’s [Code of Conduct](CODE_OF_CONDUCT.md) to ensure a respectful and inclusive community.

## Questions?
For clarification, open an issue on [GitHub](https://github.com/out-sec/NetGuard/issues) or contact the maintainers at [contact@out-sec.org](mailto:contact@out-sec.org).