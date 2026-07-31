# Contributing to Autonomous AI Pentesting Tool

First off, thank you for considering contributing to the Autonomous AI Pentesting Tool! It's contributions like yours that make open-source security tools better for everyone.

---

## Code of Conduct & Legal Terms

By contributing to this repository, you agree that your contributions will be licensed under its [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).

This project is built strictly for authorized security assessments, research, and defensive testing. Contributions must adhere to legal and ethical standards for security research.

---

## How Can I Contribute?

### 1. Reporting Bugs
Before creating bug issues, please check the existing issues list to see if the problem has already been reported.

When creating a bug report, please include:
- A clear, descriptive title.
- Steps to reproduce the issue.
- Expected behavior vs actual behavior.
- Relevant log output or terminal traces.
- Your setup details (OS, Python version, Docker version, MCP client used).

### 2. Suggesting Enhancements & New Tools
Enhancement suggestions are tracked as GitHub issues. When creating an issue, please explain:
- The capability or security tool wrapper you'd like to see added.
- Why this enhancement would be useful to security operators.
- Any relevant tool syntax or API integration specifications.

### 3. Submitting Pull Requests (PRs)

1. **Fork the Repository**: Create your own fork of the repository on GitHub.
2. **Clone & Set Up**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/AI-Pentesting-Tool.git
   cd AI-Pentesting-Tool
   ```
3. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/my-cool-feature
   ```
4. **Make Your Changes**:
   - Ensure backend code follows Python 3.12+ type hints and standard FastAPI patterns.
   - Run tests before committing (`pytest backend/tests/`).
   - Format code using `ruff`.
5. **Commit & Push**:
   ```bash
   git commit -m "feat(backend): add support for custom tool parser"
   git push origin feature/my-cool-feature
   ```
6. **Open a Pull Request**: Submit a PR to the `main` branch of the official repository. Describe your changes clearly and link any related issues.

---

## Development Setup

See README.md

---

Thank you for helping build an elite autonomous pentesting platform!
