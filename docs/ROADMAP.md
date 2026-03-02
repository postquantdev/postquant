# PostQuant Roadmap

## Phase 1: TLS Scanner (March 2026)
- [ ] CLI framework and argument parsing
- [ ] TLS endpoint connection and cipher suite detection
- [ ] Quantum vulnerability classification (red/yellow/green)
- [ ] Terminal output with color-coded grades
- [ ] JSON and text output formats

## Phase 2: Code Scanner (April 2026)
- [ ] Python crypto detection (cryptography, PyCryptodome, hashlib)
- [ ] JavaScript/TypeScript crypto detection (crypto, node-forge, webcrypto)
- [ ] Go crypto detection (crypto/*, x/crypto)
- [ ] Java crypto detection (javax.crypto, Bouncy Castle)
- [ ] Semgrep rule integration
- [ ] File-level and line-level reporting

## Phase 3: CBOM + Risk Scoring (May 2026)
- [ ] Cryptographic Bill of Materials generation (JSON, CSV)
- [ ] Risk scoring engine (algorithm vulnerability x data sensitivity x exposure x lifespan)
- [ ] Priority-ranked migration recommendations
- [ ] NIST SP 800-208 compliance mapping
- [ ] PDF report generation

## Phase 4: Platform (June 2026)
- [ ] Web dashboard for scan results
- [ ] Team management and multi-user access
- [ ] CI/CD integrations (GitHub Actions, GitLab CI)
- [ ] Scheduled scanning and regression detection
- [ ] Enterprise tier with SSO and audit logs

## Future
- Container and Kubernetes scanning
- Cloud provider config analysis (AWS, Azure, GCP)
- Automated remediation suggestions
- IDE plugins (VS Code, JetBrains)
