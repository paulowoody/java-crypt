#!/usr/bin/env bash

# Colors for better readability
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}--- Starting Security Audit for java-crypt ---${NC}"

# 1. Run OWASP Dependency-Check (SCA)
echo -e "\n[1/2] Scanning third-party dependencies..."
mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7.0
SCA_EXIT=$?

# 2. Run Semgrep (SAST)
echo -e "\n[2/2] Scanning source code logic..."
# We use the local venv if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi
semgrep scan --config p/java --config auto --error
SAST_EXIT=$?

# 3. Final Summary
echo -e "\n${GREEN}--- Audit Summary ---${NC}"

if [ $SCA_EXIT -eq 0 ]; then
    echo -e "SCA (Dependencies): ${GREEN}PASSED${NC}"
else
    echo -e "SCA (Dependencies): ${RED}FAILED (High severity vulnerabilities found)${NC}"
fi

if [ $SAST_EXIT -eq 0 ]; then
    echo -e "SAST (Source Code): ${GREEN}PASSED${NC}"
else
    echo -e "SAST (Source Code): ${RED}FAILED (Security anti-patterns found)${NC}"
fi

# Exit with error if either tool failed
if [ $SCA_EXIT -ne 0 ] || [ $SAST_EXIT -ne 0 ]; then
    echo -e "\n${RED}Overall Audit: FAILED${NC}"
    exit 1
else
    echo -e "\n${GREEN}Overall Audit: SUCCESS${NC}"
    exit 0
fi
