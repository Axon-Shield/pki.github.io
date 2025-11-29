# Key Management Best Practices

## Overview

Private keys are the crown jewels of PKI infrastructure. A compromised private key undermines all cryptographic guarantees: authentication, integrity, and confidentiality. Yet key management is often the weakest link in PKI deployments—not because the cryptography is weak, but because keys are generated, stored, accessed, and retired carelessly.

**Core principle**: The security of your entire PKI infrastructure is only as strong as your weakest key management practice.

## The Key Management Lifecycle

```
┌──────────────┐
│  Generation  │  ← Secure randomness, appropriate algorithms
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Storage    │  ← HSM, encryption, access control
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    Usage     │  ← Authentication, authorization, audit
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Rotation   │  ← Periodic renewal, compromise response
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Archival   │  ← Long-term storage for decryption/validation
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Destruction  │  ← Secure deletion, zeroization
└──────────────┘
```

This comprehensive guide covers all aspects of secure key management throughout the complete lifecycle. By following these best practices, organizations can protect their most critical cryptographic assets and maintain the integrity of their PKI infrastructure.

## Key Generation

The security of a private key begins at generation. Weak randomness, improper algorithms, or insecure generation environments compromise keys before they're ever used.

### Cryptographic Requirements

Private key generation requires high-quality entropy. Use cryptographically secure random number generators (CSPRNGs) provided by the operating system or HSM, never custom random implementations.

For RSA keys, 2048 bits is the minimum acceptable size in 2025, with 3072 bits recommended for most use cases and 4096 bits for long-lived or highly sensitive keys. Always use 65537 as the public exponent.

For ECDSA keys, use curves P-256, P-384, or P-521. P-384 is recommended for most use cases, providing strong security with reasonable performance.

### Key Generation Location

Where keys are generated matters as much as how they're generated. For root and intermediate CAs, generate keys inside a FIPS 140-2 Level 3+ HSM whenever possible. The private key never leaves the hardware boundary, providing maximum protection.

For offline root CAs, generation on an air-gapped, hardened workstation is acceptable if proper security procedures are followed. This requires physical security, full disk encryption, minimal software, and multi-party key ceremonies with witnesses.

For server certificates and less-critical keys, generation on properly secured production servers is acceptable, but implement file encryption, strict access controls, and monitoring.

### Key Ceremonies

High-value key generation should follow formal ceremonies with multiple participants, witnesses, comprehensive checklists, and complete documentation. Every step from equipment verification through secure storage should be documented and signed by all participants.

A root CA key ceremony typically involves the Chief Security Officer, PKI Administrator, System Administrator, Security Auditor, plus external witnesses. The process takes place in a physically secure location with video recording and requires hours of careful execution.

## Key Storage

After generation, private keys must be protected throughout their operational lifetime. The storage mechanism must match the key's value and risk profile.

### Hardware Security Modules

HSMs provide the strongest protection for cryptographic keys. They are tamper-resistant hardware devices certified to FIPS 140-2 Level 3 or higher. Private keys generated or imported into an HSM can be marked non-exportable, ensuring they never leave the hardware boundary.

HSM selection should consider security certifications (FIPS 140-2/3, Common Criteria), cryptographic capabilities (supported algorithms and key sizes), performance requirements, operational features (backup, clustering, audit logging), and deployment model (on-premises, PCIe card, cloud HSM).

Configure HSMs with role separation (Security Officer, Crypto Officer, Crypto User, Auditor), multi-party authorization for sensitive operations, strong authentication, network isolation, comprehensive audit logging, and encrypted backups.

### Software-Based Storage

When HSMs are not available, software-based key storage requires additional protective layers. Always encrypt private keys at rest using strong encryption (AES-256-GCM) with keys derived from passwords using Scrypt or Argon2.

Store private key files in restricted directories like /etc/ssl/private/ with permissions 0400 (read-only by owner). Never store keys in web-accessible locations, temporary directories, version control, or unencrypted backups.

Consider dedicated secret management systems like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault for better key protection and lifecycle management.

### Backup and Escrow

Backup strategies must balance availability with security. For CA keys and keys needed for decryption, implement backup using Shamir's Secret Sharing to split the key across multiple custodians. A threshold scheme like 3-of-5 means any three custodians can reconstruct the key, but compromise of two custodians doesn't expose the key.

Store backup shares in geographically distributed secure locations. Document the reconstruction procedure and test it regularly. Never skip backup testing—discovering backup failure during an emergency is catastrophic.

Key escrow (third-party holds backup) introduces significant risks and should be avoided for signing and authentication keys. If legally required for data encryption keys, use reputable providers, multi-party authorization for release, comprehensive audit logging, and consider split escrow across multiple agents.

## Key Usage

### Access Control

Implement least privilege for all key operations. Define clear roles with specific permissions: Security Officers manage HSM infrastructure, Crypto Officers manage keys, Crypto Users perform cryptographic operations, and Auditors have read-only log access.

Require multi-factor authentication appropriate to key sensitivity. Root CA access requires physical presence, smart cards, biometric verification, and second-person verification. Intermediate CA access requires HSM passwords, client certificates, and time-based one-time passwords. Server keys use service account credentials with API keys or TLS client certificates.

### Audit Logging

Log all cryptographic operations without exception. Required events include key generation, import, export, backup, restoration, deletion, all cryptographic operations (sign, verify, encrypt, decrypt), administrative actions (login, role assignment, configuration changes), and security events (authentication failures, tamper detection, unusual patterns).

Send logs to a centralized SIEM for analysis. Implement automated anomaly detection for volume spikes, operations outside normal hours, users performing unusual operations, repeated failed authentications, and unusual operation sequences.

Review logs regularly. Manual review catches issues automated systems miss, and regular review demonstrates due diligence for compliance and audit.

## Key Rotation

Periodic key rotation limits exposure from undetected compromise, enables migration to stronger algorithms, and demonstrates security hygiene to auditors.

### Rotation Timing

Different keys require different rotation frequencies. Root CA keys rotate every 10-20 years due to high coordination costs. Intermediate CA keys rotate every 3-5 years, before consuming 75% of their validity period. TLS server certificates should rotate every 90 days when automated (Let's Encrypt model) or annually if manual. Code signing keys rotate every 1-2 years, balancing security with timestamp validation needs.

Event-driven rotation happens in response to key compromise (immediate), personnel changes (case-by-case evaluation), algorithm deprecation (based on risk timeline), or compliance changes (before deadline).

### Rotation Implementation

Implement graceful key rotation to avoid service disruption. For CA rotation, generate the new key, create a new CA certificate signed by the old key (cross-signing), publish both certificates, begin issuing with the new key, wait for a transition period (typically 6 months), then create a self-signed certificate with the new key and retire the old key.

For service certificates, use deployment strategies like gradual rollout (development, staging, canary, production), blue-green deployment (parallel environments with traffic cutover), or rolling updates (update one server at a time).

Always test rotation procedures in non-production before executing in production. Document every rotation, including what was rotated, when, by whom, and verification that the rotation succeeded.

## Key Archival and Destruction

### Long-Term Archival

Archive encryption keys for as long as encrypted data must remain accessible. This typically means data retention period plus a buffer. Archive verification keys (public keys) indefinitely for legal signatures.

Never archive signing keys unless using timestamp servers—archived signing keys enable retroactive signing, compromising non-repudiation. Destroy authentication keys promptly after rotation.

For archived keys, encrypt with AES-256-GCM, use Shamir's Secret Sharing for the encryption key across multiple custodians, store in geographically distributed locations, restrict access to security officer plus legal approval, and verify integrity annually.

### Secure Destruction

When keys are no longer needed, destroy them securely. HSM zeroization is the gold standard—FIPS 140-2 Level 3+ HSMs have certified zeroization procedures that reliably erase key material.

For encrypted key files, overwrite with random data 7+ times, delete the file, destroy the encryption key, and verify the file is unrecoverable. Tools include shred (Linux), sdelete (Windows), and srm.

For keys in memory, explicitly zero the buffer before freeing memory to prevent recovery from memory dumps or swap files. Be aware that compiler optimizations may remove zeroing code—use memory barrier functions or volatile pointers.

For hardware devices (decommissioned HSMs, storage media, backup tapes), physical destruction is appropriate. Methods include degaussing for magnetic media, shredding, incineration, or in extreme cases, acid baths.

Document all key destruction with key identifier, destruction timestamp, destruction method, reason for destruction, verification of successful destruction, and signatures from all ceremony participants.

## Best Practices Summary

Critical do's: Use cryptographically secure random number generators. Generate keys in secure environments (HSM or hardened workstation). Use appropriate key sizes (RSA 3072+, ECDSA P-384+). Encrypt keys at rest. Implement least privilege access. Require multi-factor authentication for sensitive operations. Maintain comprehensive audit logs. Rotate keys on schedule and when compromised. Test backup and restoration procedures. Document all key management activities. Destroy keys securely when no longer needed.

Critical don'ts: Never use weak random number generators. Never reuse private keys across certificates. Never store keys unencrypted. Never commit keys to version control. Never store keys in web-accessible locations. Never skip key backup for keys requiring long-term availability. Never keep keys longer than necessary. Never trust key destruction without verification.

## Conclusion

Key management excellence requires discipline, proper tooling, clear procedures, and organizational commitment. The technical controls (HSMs, encryption, access controls) are necessary but insufficient. Equally critical are operational practices: documented procedures, trained personnel, regular testing, audit logging, and continuous improvement.

Organizations that treat key management as a core competency rather than a compliance checkbox build resilient PKI infrastructure that can withstand sophisticated attacks, recover from incidents, and adapt to evolving threats.

The investment in proper key management is not optional—it's the foundation of everything else in PKI. Strong cryptography built on weak key management is security theater. Strong key management supporting strong cryptography delivers actual security.

## References

### Standards and Guidelines

**NIST SP 800-57 - Recommendation for Key Management**
- NIST. "Recommendation for Key Management: Part 1 - General." Revision 5, May 2020.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- Comprehensive key lifecycle management framework
- Key lengths, algorithms, and cryptoperiods
- Foundation for federal key management practices

**NIST SP 800-152 - A Profile for U.S. Federal Cryptographic Key Management Systems**
- NIST. "A Profile for U.S. Federal Cryptographic Key Management Systems." October 2015.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-152/final)
- Enterprise key management system requirements
- Operational procedures and technical controls

**X9.24 - Retail Financial Services Symmetric Key Management**
- ASC X9. "X9.24-1:2017 Retail Financial Services Symmetric Key Management."
- Banking industry key management standard
- Hardware security requirements

### HSM Certification and Standards

**FIPS 140-2 - Security Requirements for Cryptographic Modules**
- NIST. "Security Requirements for Cryptographic Modules." May 2001 (current).
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/fips/140/2/final)
- Four security levels for cryptographic modules
- Physical security, logical security, and key management requirements
- Industry standard for HSM certification

**FIPS 140-3 - Security Requirements for Cryptographic Modules**
- NIST. "Security Requirements for Cryptographic Modules." March 2019.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- Updated cryptographic module standard (replacing 140-2)
- Alignment with ISO/IEC 19790:2012
- Enhanced testing and validation requirements

**Common Criteria for Information Technology Security Evaluation**
- Common Criteria. ISO/IEC 15408 Parts 1-3.
  - [Commoncriteriaportal](https://www.commoncriteriaportal.org/)
- International standard for computer security certification
- Protection Profiles for cryptographic modules
- Alternative/complement to FIPS 140-2/3

### Cryptographic Algorithms

**NIST FIPS 186-4 - Digital Signature Standard (DSS)**
- NIST. "Digital Signature Standard (DSS)." July 2013.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/fips/186/4/final)
- RSA, ECDSA, and DSA specifications
- Key generation requirements
- Approved curves and parameters

**RFC 8017 - PKCS #1: RSA Cryptography Specifications**
- Moriarty, K., et al. "PKCS #1: RSA Cryptography Specifications Version 2.2." November 2016.
  - [Ietf - Rfc8017](https://tools.ietf.org/html/rfc8017)
- RSA algorithm specification
- Padding schemes (OAEP, PSS)
- Implementation guidance

**NIST SP 800-186 - Recommendations for Discrete Logarithm-based Cryptography**
- NIST. "Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters." February 2023.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-186/final)
- Approved elliptic curves
- Parameter generation and validation
- Security strength analysis

### Random Number Generation

**NIST SP 800-90A - Recommendation for Random Number Generation Using Deterministic Random Bit Generators**
- NIST. "Recommendation for Random Number Generation Using Deterministic Random Bit Generators." June 2015.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- Approved DRBG mechanisms
- Entropy requirements
- Testing and validation

**NIST SP 800-90B - Recommendation for the Entropy Sources Used for Random Bit Generation**
- NIST. "Recommendation for the Entropy Sources Used for Random Bit Generation." January 2018.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-90b/final)
- Entropy source requirements
- Testing methodologies
- Min-entropy estimation

**RFC 4086 - Randomness Requirements for Security**
- Eastlake, D., et al. "Randomness Requirements for Security." June 2005.
  - [Ietf - Rfc4086](https://tools.ietf.org/html/rfc4086)
- Practical guidance on random number generation
- Entropy sources and quality
- Implementation considerations

### Secret Sharing

**Shamir's Secret Sharing - Original Paper**
- Shamir, A. "How to Share a Secret." Communications of the ACM, Vol. 22, No. 11, pp. 612-613, November 1979.
  - [Acm - 10.1145](https://dl.acm.org/doi/10.1145/359168.359176)
- Foundational threshold cryptography paper
- Basis for key backup and recovery schemes

**Verifiable Secret Sharing**
- Feldman, P. "A Practical Scheme for Non-interactive Verifiable Secret Sharing." FOCS 1987.
- Pedersen, T.P. "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing." CRYPTO 1991.
- Enhanced secret sharing with verification
- Prevention of dealer misbehavior

### Password-Based Key Derivation

**RFC 7914 - The scrypt Password-Based Key Derivation Function**
- Percival, C., Josefsson, S. "The scrypt Password-Based Key Derivation Function." August 2016.
  - [Ietf - Rfc7914](https://tools.ietf.org/html/rfc7914)
- Memory-hard KDF resistant to hardware attacks
- Recommended for password-based encryption

**RFC 9106 - Argon2 Memory-Hard Function**
- Biryukov, A., Dinu, D., Khovratovich, D. "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications." September 2021.
  - [Ietf - Rfc9106](https://tools.ietf.org/html/rfc9106)
- Password Hashing Competition winner
- Resistant to GPU and ASIC attacks

**PBKDF2 - Password-Based Key Derivation Function 2**
- RFC 8018 - PKCS #5: Password-Based Cryptography Specification Version 2.1
  - [Ietf - Rfc8018](https://tools.ietf.org/html/rfc8018)
- Widely deployed KDF
- NIST approved for federal use

### Key Storage and Protection

**PKCS #11 - Cryptographic Token Interface Standard**
- OASIS. "PKCS #11 Cryptographic Token Interface Base Specification Version 2.40." 2015.
  - [Oasis-open - Pkcs11 Base](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/)
- Standard interface for HSMs and cryptographic tokens
- Key attributes and access control
- Industry-wide HSM API

**Key Management Interoperability Protocol (KMIP)**
- OASIS. "Key Management Interoperability Protocol Specification Version 2.1." January 2020.
  - [Oasis-open - Kmip Spec](http://docs.oasis-open.org/kmip/kmip-spec/v2.1/)
- Standardized key management communication
- HSM and key management system integration
- Key lifecycle operations

**Trusted Platform Module (TPM) 2.0**
- Trusted Computing Group. "TPM 2.0 Library Specification." 2019.
  - [Trustedcomputinggroup - Tpm Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- Hardware-based key storage for endpoints
- Measured boot and attestation
- Integration with operating systems

### Secure Deletion

**DoD 5220.22-M - National Industrial Security Program Operating Manual**
- U.S. Department of Defense. "National Industrial Security Program Operating Manual." February 2006.
- Data sanitization standards (now superseded by NIST 800-88)
- Historical reference for secure deletion

**NIST SP 800-88 - Guidelines for Media Sanitization**
- NIST. "Guidelines for Media Sanitization." Revision 1, December 2014.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final)
- Clear, purge, and destroy methods
- Media-specific sanitization guidance
- Verification procedures

**Gutmann Method**
- Gutmann, P. "Secure Deletion of Data from Magnetic and Solid-State Memory." USENIX Security Symposium, July 1996.
- 35-pass overwrite method
- Historical significance (somewhat outdated for modern drives)

### Hardware Security Research

**Side-Channel Attacks on Cryptographic Implementations**
- Kocher, P., Jaffe, J., Jun, B. "Differential Power Analysis." CRYPTO 1999.
  - Foundational side-channel attack research
- Kocher, P., et al. "Spectre Attacks: Exploiting Speculative Execution." IEEE S&P 2019.
  - Modern microarchitecture vulnerabilities

**Fault Attacks on Cryptographic Hardware**
- Boneh, D., DeMillo, R.A., Lipton, R.J. "On the Importance of Checking Cryptographic Protocols for Faults." EUROCRYPT 1997.
- Fault injection attacks on RSA
- Hardware attack countermeasures

### Operational Guidance

**CA/Browser Forum - Network and Certificate System Security Requirements**
- CA/Browser Forum. "Network and Certificate System Security Requirements." Current version.
  - [Cabforum - Network Security Requirements](https://cabforum.org/network-security-requirements/)
- Operational security for certificate authorities
- Key protection requirements
- Audit logging and monitoring

**Cloud Security Alliance - SecaaS Category 3: Encryption**
- Cloud Security Alliance. "Security as a Service Implementation Guidance, Category 3: Encryption." 2012.
- Cloud-based key management
- HSM-as-a-Service considerations
- Multi-tenancy security

### Key Ceremony Guidance

**WebTrust Principles and Criteria for Certification Authorities**
- CPA Canada/AICPA. "WebTrust Principles and Criteria for Certification Authorities." Current version.
  - [CPA Canada - WebTrust Services](https://www.cpacanada.ca/business-and-accounting-resources/audit-and-assurance/overview-of-webtrust-services)
- CA operational audits
- Key ceremony documentation requirements
- Trustworthy system principles

**CA Key Ceremony Best Practices**
- Gutmann, P. "Key Ceremony Procedures." 2004.
  - [Wikipedia - Key Ceremony](https://en.wikipedia.org/wiki/Key_ceremony)
- Practical key ceremony guidance
- Common pitfalls and solutions

### Industry Best Practices

**Venafi - State of Machine Identity Management**
- Venafi. "2023 State of Machine Identity Management Report." Annual.
  - Industry survey on key and certificate management
  - Common failures and best practices
  - Incident statistics

**HashiCorp Vault Documentation**
- HashiCorp. "Vault Documentation - Secrets Management."
  - [Vaultproject](https://www.vaultproject.io/docs)
- Modern secrets management patterns
- API-driven key lifecycle
- Open-source reference implementation

**AWS Key Management Service Best Practices**
- Amazon Web Services. "AWS KMS Best Practices." Current.
  - [Amazon - Latest](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- Cloud HSM usage patterns
- Key policies and access control
- Audit and monitoring

### Legal and Compliance

**eIDAS Regulation - Electronic Identification and Trust Services**
- European Parliament. "Regulation (EU) No 910/2014." July 2014.
  - [Europa - Txt](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32014R0910)
- European key management requirements
- Qualified electronic signatures
- Trust service provider obligations

**ETSI TS 119 431 - Policy and Security Requirements for Trust Service Providers**
- ETSI. "Electronic Signatures and Infrastructures (ESI); Policy and security requirements for Trust Service Providers." 2016.
- European technical standards
- Key protection requirements
- Audit and compliance

### Academic Research

**Cryptographic Key Length Recommendations**
- Lenstra, A.K., Verheul, E.R. "Selecting Cryptographic Key Sizes." Journal of Cryptology, Vol. 14, pp. 255-293, 2001.
- Key length adequacy analysis
- Future-proofing considerations

**Practical Key Recovery**
- Heninger, N., et al. "Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices." USENIX Security 2012.
- Real-world analysis of weak key generation
- Entropy problems in practice

**Post-Quantum Key Management**
- Chen, L., et al. "Report on Post-Quantum Cryptography." NIST Internal Report 8105, April 2016.
  - [Nist - Detail](https://csrc.nist.gov/publications/detail/nistir/8105/final)
- Quantum-resistant algorithms
- Migration planning for key management systems
