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
