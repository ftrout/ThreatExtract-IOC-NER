# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of ThreatExtract-IOC-NER seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them by:
1. Opening a private security advisory on GitHub
2. Emailing the maintainers directly

### What to Include

Please include the following information in your report:
- Type of vulnerability (e.g., code injection, data exposure, etc.)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue and potential attack vectors

### Response Timeline

- **Initial Response**: Within 48 hours of report submission
- **Status Update**: Within 7 days with an assessment
- **Resolution**: Depending on severity, typically within 30-90 days

## Security Best Practices for Users

### Model Security

When using ThreatExtract-IOC-NER in production:

1. **Validate Inputs**: Always validate and sanitize text inputs before processing
2. **Output Validation**: Verify extracted IOCs against known patterns before acting on them
3. **Access Control**: Restrict access to the model API endpoints
4. **Logging**: Maintain audit logs of model usage for security monitoring

### Data Handling

1. **Sensitive Data**: Be cautious when processing text that may contain sensitive information
2. **Data Retention**: Implement appropriate data retention policies for processed text
3. **Anonymization**: Consider anonymizing or redacting sensitive data before processing

### Deployment Security

1. **Environment Isolation**: Run the model in isolated environments
2. **Dependency Updates**: Keep all dependencies updated to latest secure versions
3. **API Security**: Use authentication and rate limiting for API endpoints
4. **HTTPS**: Always use HTTPS for production deployments

## Responsible Disclosure

We kindly ask security researchers to:
- Give us reasonable time to investigate and address vulnerabilities
- Avoid exploiting vulnerabilities beyond what is necessary for proof-of-concept
- Not access, modify, or delete data belonging to others
- Act in good faith to avoid privacy violations and service disruption

## Scope

This security policy applies to:
- The ThreatExtract-IOC-NER model and codebase
- Associated training scripts and utilities
- The Gradio demo application

This policy does not apply to:
- Third-party dependencies (report to their respective maintainers)
- User-deployed instances and modifications
