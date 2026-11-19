## Security checklist
- [ ] No secrets, tokens or passwords added to code, config or Dockerfiles
- [ ] New dependencies are needed and not known-vulnerable (see the security-scan check)
- [ ] User input is validated; no string-built SQL, shell commands or file paths from user input
- [ ] Any new security exception has a reason, an approver and an expiry date
