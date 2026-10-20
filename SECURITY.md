# Security Policy for Guard Agent JVM

## Supported Versions

I provide security updates for the following versions of guard-agent-jvm:

| Version | Supported |
| ------- | --------- |
| 3.x | :white_check_mark: bug and security fixes |

## Reporting a Vulnerability

I take the security of Guard Agent JVM seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do not disclose the vulnerability publicly** until I have fixed it.
2. **Report the vulnerability through GitHub's security advisory feature**:
   - Go to the [Security tab](https://github.com/Guard-Core/guard-agent-jvm/security/advisories) of the Guard Agent JVM repository
   - Click on "New draft security advisory"
   - Fill in the details of the vulnerability
   - Submit the advisory

   Alternatively, you can report vulnerabilities through [GitHub's private vulnerability reporting feature](https://github.com/Guard-Core/guard-agent-jvm/security/advisories/new).

3. Include the following information in your report:
   - A description of the vulnerability and its potential impact
   - Steps to reproduce the issue
   - Affected versions
   - Any potential mitigations or workarounds

I will acknowledge your report within 48 hours and send a detailed response within 7 days, including the next steps in handling the vulnerability.

## Security Considerations

The agent carries security-sensitive material by design: HMAC signing
secrets, AES-256-GCM payload encryption keys, and redaction behavior. Report
anything that weakens the signatures, leaks key material, weakens redaction,
breaks the at-least-once delivery guarantee, or makes the agent block or
crash the host application.

The agent is telemetry: detection and enforcement decisions live in the
engine ([guard-core-jvm](https://github.com/Guard-Core/guard-core-jvm/security/advisories)).
