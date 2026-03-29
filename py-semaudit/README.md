# Security Audit (`py-semaudit`)

This directory contains the security audit automation script for the `java-crypt` project.

## 1. Setup Python Virtual Environment

The security audit tools (like Semgrep) should be installed in a Python virtual environment to keep dependencies isolated. From the **project root directory**, create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

*(Note: On Windows, use `.venv\Scripts\activate` to activate the virtual environment).*

## 2. Install Semgrep Package

With the virtual environment activated, install the required `semgrep` package:

```bash
pip install semgrep
```

## 3. Running the Audit Script

The `audit.sh` script runs both a dependency scan and a source code scan. It should be executed from the **project root directory** (where the `pom.xml` is located).

### How to run:

Make sure the script is executable (you only need to do this once):
```bash
chmod +x py-semaudit/audit.sh
```

Run the script:
```bash
./py-semaudit/audit.sh
```

### What it does:

The script performs two critical security checks:
1. **Software Composition Analysis (SCA):** Runs the OWASP Dependency-Check Maven plugin. It scans all third-party libraries defined in `pom.xml` for known security vulnerabilities. It is configured to fail if any vulnerability with a CVSS score of 7.0 (High/Critical) or greater is detected.
2. **Static Application Security Testing (SAST):** Activates the local Python `.venv` (if it exists) and runs `semgrep`. It analyzes the project's source code against official Java security rules and auto-detected patterns to find potential security anti-patterns or logic flaws.

### What to look out for:

- **SCA (Dependencies) FAILED:** If this step fails, it means one or more of your Maven dependencies have high-severity vulnerabilities. You should check the console output or the generated OWASP report in the `target/` directory and update the vulnerable dependencies in your `pom.xml`.
- **SAST (Source Code) FAILED:** If this step fails, Semgrep has found risky code patterns directly in your source code. Review the Semgrep console output for specific files, line numbers, and remediation advice to fix the flagged anti-patterns.
- **Overall Audit Status:** The script provides a final summary. It exits with a code of `1` (Error) if either of the checks fails, and `0` (Success) if both pass. This makes it ideal for use in automated CI/CD pipelines.
