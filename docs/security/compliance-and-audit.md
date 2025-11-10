# Compliance and Audit

## Overview

PKI operates within a complex regulatory and compliance landscape. Public certificate authorities face stringent requirements from the CA/Browser Forum, industry regulations (PCI-DSS, HIPAA, SOX), and government mandates (FedRAMP, NIST). Private PKI infrastructures must align with organizational policies, industry standards, and contractual obligations.

Compliance is not just checkbox exercises for auditors—it represents codified best practices developed through decades of security incidents and industry evolution. Organizations that treat compliance as security guidance rather than overhead build more resilient PKI infrastructure.

**Core principle**: Compliance frameworks encode hard-won lessons from industry failures. Following them isn't bureaucracy—it's learning from others' expensive mistakes.

## Regulatory Landscape

### Public CA Requirements

**CA/Browser Forum Baseline Requirements**:

The CA/Browser Forum establishes requirements for publicly trusted certificate authorities. These requirements are not optional—violation can result in browser distrust.

Key requirements:

- **Domain validation**: Approved methods only (DNS, HTTP, email with restrictions)
- **Certificate lifetimes**: Maximum 398 days for TLS certificates (since September 2020)
- **Key size minimums**: RSA 2048+ bits, ECC P-256+
- **Revocation**: Must support OCSP and CRL
- **Certificate Transparency**: All public certificates must be logged
- **Incident reporting**: Material incidents reported within specified timeframes
- **Annual audits**: WebTrust or ETSI audit required

Non-compliance consequences:

- Certificate distrust by browsers (Chrome, Firefox, Safari, Edge)
- Public incident reports damaging reputation
- Potential removal from root programs
- Legal and financial liability
- Customer loss

**Industry-Specific Regulations**:

Organizations in regulated industries face additional PKI requirements:

*Payment Card Industry (PCI-DSS)*:

- Requirement 3: Protect stored cardholder data (encryption keys)
- Requirement 4: Encrypt transmission of cardholder data (TLS certificates)
- Requirement 8: Strong authentication (certificate-based authentication)
- Key management requirements including generation, distribution, storage, rotation, and destruction

*Healthcare (HIPAA)*:

- Administrative safeguards for access control
- Technical safeguards for encryption
- Transmission security standards
- Audit controls and logging
- Certificate-based authentication for ePHI access

*Financial Services (SOX, GLBA)*:

- Strong authentication requirements
- Encryption of sensitive financial data
- Audit trails for all transactions
- Key management documentation
- Disaster recovery for certificate services

*Government (FIPS 140-2/3, NIST SP 800-57)*:

- FIPS 140-2 Level 2+ for key storage
- NIST-approved algorithms only
- Specific key management lifecycle requirements
- Detailed documentation requirements
- Regular security assessments

### Private PKI Standards

Even private PKI deployments should align with industry standards:

**NIST SP 800-57**: Recommendations for Key Management provides comprehensive guidance on cryptographic key management throughout the key lifecycle.

**ISO/IEC 27001**: Information security management system standard includes requirements for cryptographic controls.

**ANSI X9 Standards**: Banking industry standards for financial cryptography, key management, and certificate usage.

**ETSI Standards**: European telecommunications standards for certificate policies, qualified certificates, and trust service providers.

## Compliance Documentation

### Certificate Policy (CP)

A Certificate Policy is the high-level statement of the purpose and applicability of certificates. Every CA should have a documented CP.

**CP Structure** (RFC 3647):

1. **Introduction**
   - Overview
   - Document name and identification
   - PKI participants (CA, RA, subscribers, relying parties)
   - Certificate usage (permitted and prohibited)
   - Policy administration

2. **Publication and Repository Responsibilities**
   - Repositories (where certificates and CRLs published)
   - Publication frequency
   - Access controls
   - Root CA certificate distribution

3. **Identification and Authentication**
   - Naming (DN structure, uniqueness requirements)
   - Initial identity validation
   - Identification for re-key and renewal
   - Authentication for revocation requests

4. **Certificate Life-Cycle Operational Requirements**
   - Certificate application
   - Certificate issuance
   - Certificate acceptance
   - Key pair and certificate usage
   - Certificate renewal, re-key, and modification
   - Certificate revocation and suspension
   - Security audit procedures

5. **Facility, Management, and Operational Controls**
   - Physical security controls
   - Procedural controls
   - Personnel security controls
   - Audit logging procedures
   - Records archival
   - Key changeover
   - Compromise and disaster recovery

6. **Technical Security Controls**
   - Key pair generation and installation
   - Private key protection
   - Other aspects of key pair management
   - Activation data
   - Computer security controls
   - Life cycle technical controls
   - Network security controls
   - Time-stamping

7. **Certificate, CRL, and OCSP Profiles**
   - Certificate profile (extensions, key usage, validity periods)
   - CRL profile
   - OCSP profile

8. **Compliance Audit and Other Assessments**
   - Frequency and circumstances of assessment
   - Identity/qualifications of assessor
   - Assessor's relationship to assessed entity
   - Topics covered by assessment
   - Actions taken as a result of deficiency
   - Communication of results

9. **Other Business and Legal Matters**
   - Fees
   - Financial responsibility
   - Confidentiality
   - Privacy
   - Intellectual property rights
   - Representations and warranties
   - Disclaimers of warranties
   - Limitations of liability
   - Indemnities
   - Term and termination
   - Individual notices and communications
   - Amendments
   - Dispute resolution
   - Governing law
   - Compliance with applicable law
   - Miscellaneous provisions
   - Other provisions

### Certification Practice Statement (CPS)

The CPS is the detailed implementation document describing how the CA implements its Certificate Policy.

**CPS vs CP**:

- CP: "What" (policy and rules)
- CPS: "How" (implementation and procedures)

Example CPS content:

```markdown
## 4.9 Certificate Revocation

### 4.9.1 Circumstances for Revocation

Certificates will be revoked under the following circumstances:

1. **Key Compromise**: If the subscriber's private key has been compromised, or is 
   suspected of being compromised, the certificate SHALL be revoked immediately.

2. **CA Compromise**: If this CA's private key is compromised, all certificates 
   issued by this CA SHALL be revoked.

3. **Cessation of Operation**: When a subscriber ceases operation, their 
   certificate SHALL be revoked within 24 hours of notification.

4. **Affiliation Change**: If a subscriber's affiliation changes (e.g., employee 
   leaves company), their certificate SHALL be revoked within 24 hours.

5. **Information Inaccuracy**: If any information in the certificate is found to 
   be inaccurate or misleading, the certificate SHALL be revoked within 24 hours 
   of discovery.

### 4.9.2 Who Can Request Revocation

The following parties may request certificate revocation:

- The subscriber (certificate owner)
- The Registration Authority that validated the subscriber
- An authorized representative of the subscriber's organization
- The Certificate Authority (our CA) at its own discretion
- Law enforcement with proper authorization

### 4.9.3 Procedure for Revocation Request

Revocation requests SHALL be submitted through one of the following methods:

1. **Online Revocation Portal** (primary method):
   - Subscriber logs in with authentication credentials
   - Selects certificate to revoke
   - Provides reason for revocation
   - Confirms revocation request

2. **Email Request**:
   - Send to revocation@example-ca.com
   - Must be digitally signed with certificate being revoked
   - Include certificate serial number and reason

3. **Phone Request** (emergency only):
   - Call 24/7 hotline: +1-555-PKI-REVOKE
   - Authenticate with three security questions
   - Revocation processed immediately, documentation follows

### 4.9.4 Revocation Request Grace Period

There is no grace period. Revocation requests are processed immediately upon 
receipt and verification.

### 4.9.5 Time Within Which CA Must Process Revocation Request

- **Key compromise**: Within 1 hour of verified request
- **Other reasons**: Within 4 hours of verified request
- **Batch revocations**: Within 24 hours

### 4.9.6 Revocation Checking Requirement for Relying Parties

Relying parties SHOULD check certificate revocation status before trusting a 
certificate. Our CA provides both OCSP and CRL for revocation checking.

- OCSP responder: http://ocsp.example-ca.com
- CRL: http://crl.example-ca.com/ca.crl
- CRL updated: Every 24 hours or immediately after revocations

### 4.9.7 CRL Issuance Frequency

- **Regular CRLs**: Published every 24 hours
- **Delta CRLs**: Published every 6 hours
- **Emergency CRLs**: Published within 1 hour of critical revocations

### 4.9.8 Maximum Latency for CRLs

- Regular CRL: 24 hours
- Delta CRL: 6 hours  
- Emergency CRL: 1 hour

### 4.9.9 On-line Revocation/Status Checking Availability

OCSP responder is available 24/7 with 99.9% uptime SLA.

- Response time: < 200ms for 95% of requests
- Cache time: 24 hours for "good" status
- Must-staple: Not required but supported
- OCSP signing: Delegated OCSP signing certificate, rotated monthly

### 4.9.10 On-line Revocation Checking Requirements

OCSP responder SHALL:
- Respond to all valid requests within 5 seconds
- Return "good", "revoked", or "unknown" status
- Sign responses with current OCSP signing certificate
- Support HTTP GET and POST methods

### 4.9.11 Other Forms of Revocation Advertisements

Certificate Transparency logs are monitored for certificates issued by this CA. 
While not a revocation mechanism, CT logs provide additional visibility.

### 4.9.12 Special Requirements Related to Key Compromise

In the event of key compromise:

1. Certificate holder notifies CA immediately
2. CA revokes certificate within 1 hour
3. Revocation reason set to "keyCompromise"
4. Revocation date backdated to estimated compromise time if known
5. Incident investigation initiated
6. Security team notified for potential broader compromise
7. Replacement certificate issued after new key generated

### 4.9.13 Circumstances for Suspension

Certificate suspension is NOT supported by this CA. All revocations are permanent. 
Certificates that need temporary suspension should be revoked and re-issued.

Rationale: Suspension creates ambiguity for relying parties and complexity in 
revocation checking. Clean revocation and re-issuance provides better security.

### 4.9.14 Who Can Request Suspension

Not applicable - suspension not supported.

### 4.9.15 Procedure for Suspension Request

Not applicable - suspension not supported.
```

## Audit Requirements

### Internal Audits

Organizations should conduct regular internal PKI audits:

**Audit Scope**:

- Certificate issuance procedures followed correctly
- Validation procedures adequate and executed
- Access controls functioning as designed
- Audit logs complete and reviewed
- Key management procedures followed
- Incident response procedures tested
- Backup and recovery procedures validated
- Compliance with CP/CPS

**Audit Frequency**:

- **Quarterly**: Process compliance checks
- **Bi-annually**: Technical security controls
- **Annually**: Comprehensive audit of entire PKI
- **Ad-hoc**: After significant changes or incidents

**Audit Methodology**:

1. **Planning**
   - Define audit scope
   - Assign audit team
   - Schedule with stakeholders
   - Prepare audit procedures

2. **Evidence Collection**
   - Review policies and procedures
   - Examine audit logs
   - Interview personnel
   - Test security controls
   - Validate configurations
   - Sample certificate issuances

3. **Analysis**
   - Compare actual practices to documented procedures
   - Identify control gaps or weaknesses
   - Assess compliance with policies
   - Evaluate risk of identified issues

4. **Reporting**
   - Document findings
   - Rate severity of issues
   - Recommend remediation
   - Assign responsible parties
   - Set remediation deadlines

5. **Follow-up**
   - Track remediation progress
   - Verify fixes implemented
   - Re-test controls
   - Close audit findings

### External Audits

Public CAs require annual WebTrust or ETSI audits. Private CAs should consider periodic external audits for validation.

**WebTrust for Certification Authorities**:

Audit program covering:

- CA business practices disclosure
- Service integrity
- CA environmental controls
- Certificate life-cycle management
- Subscriber account management
- CA key life-cycle management
- Logical and physical security
- Network security

**ETSI Audits** (European Standard):

Alternative to WebTrust, common in Europe:

- ETSI EN 319 401: General requirements for trust service providers
- ETSI EN 319 411-1: Requirements for TSPs issuing certificates (general)
- ETSI EN 319 411-2: Requirements for TSPs issuing EU qualified certificates

**Preparing for External Audits**:

1. **Pre-audit preparation** (2-3 months before):

   - Conduct internal audit and remediate findings
   - Ensure all documentation current
   - Verify audit log completeness
   - Test all procedures
   - Train personnel on audit expectations

2. **Documentation preparation**:

   - Certificate Policy
   - Certification Practice Statement
   - Security policies and procedures
   - Disaster recovery plans
   - Incident response plans
   - Audit log samples
   - Personnel security documentation
   - Physical security documentation
   - Technical system documentation

3. **During audit**:

   - Provide requested documentation promptly
   - Arrange interviews with personnel
   - Provide access to systems as needed
   - Answer auditor questions thoroughly
   - Document all audit activities

4. **Post-audit**:

   - Review audit report
   - Develop remediation plan for findings
   - Implement corrections
   - Document corrective actions
   - Prepare for re-audit or follow-up

## Audit Logging

### What to Log

Comprehensive audit logging is essential for compliance and security. Log all security-relevant events:

**Authentication and Authorization**:

- All login attempts (successful and failed)
- Logout events
- Role or permission changes
- Multi-factor authentication events
- Session timeouts
- Privilege escalation attempts

**Certificate Lifecycle**:

- Certificate requests submitted
- Validation procedures executed
- Approval or rejection decisions
- Certificate issuance
- Certificate renewal
- Certificate revocation
- Certificate expiry
- Revocation list publication

**Key Management**:

- Key generation
- Key import/export
- Key backup
- Key restoration
- Key destruction
- HSM access
- Key usage (signing operations)

**System Administration**:

- Configuration changes
- Software updates
- User account creation/deletion
- Role assignments
- System reboots
- Service starts/stops
- Backup operations

**Security Events**:

- Intrusion detection alerts
- Firewall blocks
- Anti-virus detections
- Failed validation attempts
- Rate limiting triggers
- Anomaly detections
- HSM tamper alerts

### Log Content Requirements

Each log entry should contain:

```json
{
  "timestamp": "2025-11-09T14:35:22.127Z",
  "event_type": "certificate_issuance",
  "severity": "info",
  "user": "alice@example.com",
  "user_role": "RA_operator",
  "source_ip": "10.1.2.45",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "certificate": {
    "serial_number": "4A:3F:8C:21:9D:5E:FF:01",
    "subject_dn": "CN=api.example.com,O=Example Corp",
    "validity_period": "90_days",
    "key_algorithm": "RSA",
    "key_size": 2048
  },
  "validation": {
    "method": "DNS-01",
    "timestamp": "2025-11-09T14:33:15.422Z"
  },
  "result": "success",
  "details": "Certificate issued after successful DNS validation"
}
```

### Log Protection and Retention

**Log protection**:

- Send logs to centralized SIEM immediately
- Use write-once/append-only storage
- Encrypt logs at rest and in transit
- Implement access controls (only auditors and security)
- Hash logs for integrity verification
- Consider blockchain or similar for tamper evidence

**Retention requirements**:

- **CA audit logs**: Minimum 7 years (often longer by regulation)
- **System logs**: Minimum 1 year
- **Security event logs**: Minimum 3 years
- **Transaction logs**: Per regulatory requirements (often 7+ years)

Archive older logs to cost-effective storage while maintaining retrieval capability.

## Compliance Monitoring

### Continuous Compliance

Implement automated compliance monitoring:

**Policy Compliance Checks**:

```python
class ComplianceMonitor:
    """
    Automated compliance monitoring for PKI
    """
    
    def check_certificate_policy_compliance(self, cert: Certificate) -> ComplianceResult:
        """
        Verify certificate complies with Certificate Policy
        """
        result = ComplianceResult()
        
        # Check key size
        if cert.key_algorithm == 'RSA' and cert.key_size < 2048:
            result.add_violation(
                'KEY_SIZE',
                f'RSA key size {cert.key_size} below minimum 2048'
            )
        
        # Check validity period
        validity_days = (cert.not_after - cert.not_before).days
        if validity_days > 398:
            result.add_violation(
                'VALIDITY_PERIOD',
                f'Validity {validity_days} days exceeds maximum 398'
            )
        
        # Check approved issuing CA
        if cert.issuer_cn not in self.approved_cas:
            result.add_violation(
                'UNAUTHORIZED_CA',
                f'Certificate issued by unauthorized CA: {cert.issuer_cn}'
            )
        
        # Check required extensions
        required_extensions = ['keyUsage', 'extendedKeyUsage', 'subjectAltName']
        for ext in required_extensions:
            if ext not in cert.extensions:
                result.add_violation(
                    'MISSING_EXTENSION',
                    f'Required extension missing: {ext}'
                )
        
        # Check signature algorithm
        if cert.signature_algorithm in ['sha1', 'md5']:
            result.add_violation(
                'WEAK_SIGNATURE',
                f'Weak signature algorithm: {cert.signature_algorithm}'
            )
        
        return result
```

**Process Compliance Monitoring**:

- Are validation procedures documented and followed?
- Are approval workflows executed correctly?
- Are revocation procedures followed?
- Are audit logs being reviewed regularly?
- Are backups being performed and tested?
- Are incident response procedures current?

**Compliance Dashboards**:

Create dashboards showing:

- Policy compliance percentage
- Violations by type
- Violations by team/owner
- Remediation progress
- Audit readiness score
- Control effectiveness

### Compliance Reporting

Generate regular compliance reports for stakeholders:

**Monthly Reports** (to PKI operations team):

- Certificate issuance volume
- Validation success/failure rates
- Policy violations detected
- Remediation status
- Security events
- System availability

**Quarterly Reports** (to security leadership):

- Compliance posture summary
- Significant violations and remediation
- Audit findings and status
- Risk assessment
- Upcoming audit/assessment schedule
- Resource needs

**Annual Reports** (to executives and board):

- Overall PKI health
- Major incidents and response
- Compliance achievements
- External audit results
- Industry compliance status
- Strategic recommendations

## Common Compliance Challenges

### Challenge: Documentation Lag

**Problem**: Actual practices diverge from documented procedures as systems evolve.

**Solution**:

- Assign documentation owners
- Review and update procedures quarterly
- Link procedure updates to change management
- Version control all documentation
- Automated reminders for review
- Audit actual practice against docs regularly

### Challenge: Audit Log Overload

**Problem**: Too many logs to review effectively; important events lost in noise.

**Solution**:

- Implement log aggregation and analysis (SIEM)
- Define critical vs informational events
- Automated alerting on critical events
- Regular sampling of routine logs
- Focus manual review on anomalies
- Retention policies to archive old logs

### Challenge: Compliance vs Agility

**Problem**: Compliance controls slow down certificate issuance and rotation.

**Solution**:

- Automate compliance checks in workflows
- Pre-approved certificate profiles
- Self-service for compliant requests
- Fast-track processes with automated validation
- Educate teams on why controls exist
- Continuously improve process efficiency

### Challenge: Multi-Jurisdiction Compliance

**Problem**: Different regulations in different countries.

**Solution**:

- Document requirements by jurisdiction
- Implement most stringent requirements globally
- Separate PKI instances if necessary
- Engage legal counsel for interpretation
- Monitor regulatory changes
- Participate in industry groups

## Best Practices

**Do's**:

- Document everything (policies, procedures, decisions)
- Conduct regular internal audits
- Prepare for external audits proactively
- Implement comprehensive audit logging
- Review logs regularly for anomalies
- Monitor compliance continuously
- Train personnel on compliance requirements
- Update documentation as practices evolve
- Treat compliance as security enhancement, not overhead

**Don'ts**:

- Don't wait for audits to discover issues
- Don't ignore minor compliance violations
- Don't skip documentation because "everyone knows"
- Don't implement processes without documenting them
- Don't assume compliance without testing
- Don't treat audit findings as suggestions
- Don't let documentation become obsolete

## Conclusion

Compliance and audit are not obstacles to overcome but frameworks that encode industry best practices. Organizations that embrace compliance as a path to better security, clearer processes, and reduced risk build more mature PKI infrastructures.

The goal is not perfect compliance scores but a culture where compliance reflects actual secure practices. When your documented procedures match what you actually do, and both align with security best practices, you've achieved compliance maturity.

Invest in compliance infrastructure—documentation, logging, monitoring, training—and you invest in operational excellence. The audit will take care of itself when your actual practices embody security best practices.

## References

### Regulatory Frameworks and Standards

**CA/Browser Forum Baseline Requirements**
- CA/Browser Forum. "Baseline Requirements for the Issuance and Management of Publicly-Trusted Certificates." Current version.
  - [Cabforum - Baseline Requirements Documents](https://cabforum.org/baseline-requirements-documents/)
- Industry standard for public CAs
- Validation methods, key protection, audit requirements
- Mandatory for browser root program inclusion

**WebTrust Principles and Criteria for Certification Authorities**
- CPA Canada/AICPA. "WebTrust Principles and Criteria for Certification Authorities." Current version.
  - [Cpacanada - Audit And Assurance](https://www.cpacanada.ca/en/business-and-accounting-resources/audit-and-assurance/overview-of-webtrust-services)
- Audit framework for public CAs
- WebTrust for CAs, EV SSL, Code Signing
- Required for major browser root programs

**ETSI Standards for Trust Service Providers**
- ETSI EN 319 401. "General Policy Requirements for Trust Service Providers." V2.3.1, 2021.
  - [Etsi - Etsi En](https://www.etsi.org/deliver/etsi_en/319400_319499/319401/)
- European trust service provider requirements
- Alignment with eIDAS Regulation
- Qualified trust services

**eIDAS Regulation**
- European Parliament. "Regulation (EU) No 910/2014 on electronic identification and trust services." July 2014.
  - [Europa - Txt](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32014R0910)
- European electronic identification framework
- Qualified electronic signatures and seals
- Trust service provider supervision

### Certificate Policy and CPS Guidelines

**RFC 3647 - Internet X.509 Public Key Infrastructure Certificate Policy and Certification Practices Framework**
- Chokhani, S., et al. "Internet X.509 Public Key Infrastructure Certificate Policy and Certification Practices Framework." November 2003.
  - [Ietf - Rfc3647](https://tools.ietf.org/html/rfc3647)
- Standard framework for CP/CPS documentation
- Section-by-section guidance
- Industry-standard structure

**NIST SP 800-32 - Introduction to Public Key Technology and the Federal PKI Infrastructure**
- NIST. "Introduction to Public Key Technology and the Federal PKI Infrastructure." February 2001.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-32/final)
- Federal PKI policy requirements
- CP/CPS examples
- Certificate profiles

**Federal PKI CP and CPS Examples**
- Federal PKI Policy Authority. "Federal Bridge Certification Authority Certificate Policy." Current.
  - [Idmanagement - Fpki](https://www.idmanagement.gov/fpki/)
- Government CP/CPS templates
- Assurance level definitions

### Industry-Specific Compliance

**PCI DSS - Payment Card Industry Data Security Standard**
- PCI Security Standards Council. "Payment Card Industry (PCI) Data Security Standard." Version 4.0, March 2022.
  - [Pcisecuritystandards - Document Library](https://www.pcisecuritystandards.org/document_library)
- Requirement 3: Protect stored cardholder data
- Requirement 4: Encrypt transmission of cardholder data
- Certificate and key management requirements

**HIPAA Security Rule**
- U.S. Department of Health & Human Services. "HIPAA Security Rule." 45 CFR Parts 160, 162, and 164, 2003.
  - [Hhs - For Professionals](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- Technical safeguards: Access control, encryption
- Administrative safeguards: Security management process
- PHI protection requirements

**SOC 2 - Service Organization Control**
- AICPA. "SOC 2 - SOC for Service Organizations: Trust Services Criteria." Current.
  - [Aicpa - Frc](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome.html)
- Security, Availability, Processing Integrity, Confidentiality, Privacy
- Type I (point in time) vs Type II (period of time)
- Common for cloud service providers

**ISO/IEC 27001 - Information Security Management**
- ISO/IEC. "Information technology — Security techniques — Information security management systems — Requirements." 2022.
  - [Iso - 82875.Html](https://www.iso.org/standard/82875.html)
- Annex A.10: Cryptography
- Information security management system (ISMS)
- Risk-based approach to security

**FISMA - Federal Information Security Management Act**
- NIST SP 800-53. "Security and Privacy Controls for Information Systems and Organizations." Revision 5, 2020.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- SC-12: Cryptographic Key Establishment and Management
- SC-13: Cryptographic Protection
- Federal system authorization requirements

### Audit Standards and Guidance

**ISAE 3402 / SSAE 18 - Auditing Standards**
- IAASB. "International Standard on Assurance Engagements (ISAE) 3402, Assurance Reports on Controls at a Service Organization." 2011.
- AICPA. "Statement on Standards for Attestation Engagements No. 18 (SSAE 18)." 2017.
- Service organization control reporting
- Type I and Type II reports

**WebTrust Audit Guidelines**
- CPA Canada. "WebTrust Principles and Criteria for Certification Authorities - Practitioner Guidance." Current.
- Audit procedures for CA assessments
- Testing methodologies
- Evidence collection requirements

**NIST SP 800-53A - Assessing Security and Privacy Controls**
- NIST. "Assessing Security and Privacy Controls in Information Systems and Organizations." Revision 5, 2022.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final)
- Security control assessment procedures
- Testing methods and techniques
- Evidence requirements

### Browser Root Program Requirements

**Mozilla Root Store Policy**
- Mozilla. "Mozilla CA Certificate Policy." Version 2.8, 2023.
  - [Mozilla - About](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/)
- Inclusion requirements
- Audit requirements (WebTrust or ETSI)
- Incident reporting obligations

**Apple Root Certificate Program**
- Apple. "Apple Root Certificate Program." Current.
  - [Apple - Ca Program.Html](https://www.apple.com/certificateauthority/ca_program.html)
- Annual audits required
- Incident disclosure requirements
- Certificate Transparency logging

**Microsoft Trusted Root Program**
- Microsoft. "Trusted Root Certificate Program Requirements." Current version.
  - [Microsoft - Security](https://docs.microsoft.com/en-us/security/trusted-root/program-requirements)
- Audit requirements
- Operational requirements
- Program participation agreement

**Google Chrome Root Program**
- Chrome Root Program. "Chrome Root Program Policy." Current.
  - [Chromium - Chromium Security](https://www.chromium.org/Home/chromium-security/root-ca-policy)
- TLS server authentication certificates
- Alignment with CA/Browser Forum requirements
- Chrome Certificate Transparency policy

### Logging and Monitoring Standards

**NIST SP 800-92 - Guide to Computer Security Log Management**
- NIST. "Guide to Computer Security Log Management." September 2006.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- Log generation, transmission, storage, analysis
- Security event management
- Log retention requirements

**RFC 5424 - The Syslog Protocol**
- Gerhards, R. "The Syslog Protocol." March 2009.
  - [Ietf - Rfc5424](https://tools.ietf.org/html/rfc5424)
- Standard format for log messages
- Facility and severity levels
- Transport protocols

**Common Event Format (CEF)**
- ArcSight/Micro Focus. "Common Event Format (CEF) Implementation Standard."
- Standardized event logging format
- SIEM integration
- Event correlation

### Penetration Testing Standards

**PTES - Penetration Testing Execution Standard**
- Penetration Testing Execution Standard. "PTES Technical Guidelines." Current.
  - [Pentest-standard](http://www.pentest-standard.org/)
- Pre-engagement, intelligence gathering, threat modeling
- Exploitation, post-exploitation, reporting
- Industry-standard methodology

**OWASP Testing Guide**
- OWASP. "OWASP Web Security Testing Guide." Version 4.2, 2020.
  - [Owasp - Www Project Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- Cryptography testing
- Authentication testing
- Session management testing

**NIST SP 800-115 - Technical Guide to Information Security Testing and Assessment**
- NIST. "Technical Guide to Information Security Testing and Assessment." September 2008.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- Testing and examination techniques
- Security assessment planning
- Reporting requirements

### Privacy and Data Protection

**GDPR - General Data Protection Regulation**
- European Parliament. "General Data Protection Regulation (GDPR)." 2018.
  - [Gdpr-info](https://gdpr-info.eu/)
- Data protection by design and by default
- Data breach notification (72 hours)
- Data subject rights

**CCPA - California Consumer Privacy Act**
- State of California. "California Consumer Privacy Act." 2018 (amended 2020).
  - [Ca - Ccpa](https://oag.ca.gov/privacy/ccpa)
- Consumer data rights
- Security safeguards
- Breach notification requirements

### Key Escrow and Recovery

**NIST SP 800-130 - A Framework for Designing Cryptographic Key Management Systems**
- NIST. "A Framework for Designing Cryptographic Key Management Systems." August 2013.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-130/final)
- CKMS architecture and components
- Key recovery considerations
- Escrowed encryption standard critique

**The Crypto Wars and Key Escrow Debate**
- Abelson, H., et al. "Keys Under Doormats: Mandating insecurity by requiring government access to all data and communications." MIT Computer Science and AI Laboratory Technical Report, July 2015.
- Cryptographic policy debates
- Security implications of key escrow
- Government access to encrypted data

### Continuous Compliance

**DevSecOps and Compliance Automation**
- NIST SP 800-190. "Application Container Security Guide." September 2017.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- Security in CI/CD pipelines
- Automated compliance checking
- Infrastructure as code security

**Policy as Code**
- Open Policy Agent (OPA). "OPA Documentation." Current.
  - [Openpolicyagent](https://www.openpolicyagent.org/)
- Declarative policy enforcement
- Automated compliance validation
- Integration with deployment pipelines

### Industry Resources and Guidance

**CA Security Council**
- CA Security Council. "Guidelines and Best Practices." Current.
  - [Casecurity](https://casecurity.org/)
- Industry collaboration
- Emerging threat information
- Best practice sharing

**PKI Consortium**
- PKI Consortium. "PKI Resources and Standards." Current.
  - [Pkic](https://pkic.org/)
- Industry working groups
- PKI best practices
- Standards development participation

**Cloud Security Alliance - CSA STAR**
- Cloud Security Alliance. "Security, Trust, Assurance, and Risk (STAR) Registry." Current.
  - [Cloudsecurityalliance - Star](https://cloudsecurityalliance.org/star/)
- Cloud provider security assessments
- Consensus Assessments Initiative Questionnaire (CAIQ)
- Certification and attestation

### Academic and Research Papers

**PKI Compliance and Audit Research**
- Akhawe, D., et al. "Here's My Cert, So Trust Me, Maybe? Understanding TLS Errors on the Web." WWW 2013.
- Analysis of certificate validation failures
- User behavior with certificate warnings

**Economic Analysis of PKI Compliance**
- Camp, L.J., Wolfram, C. "Pricing Security." CERT Coordination Center, 2000.
- Economic incentives in PKI
- Compliance cost-benefit analysis
