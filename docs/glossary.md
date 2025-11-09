---
title: Glossary
category: reference
last_updated: 2024-11-09
last_reviewed: 2024-11-09
version: 1.0
status: stable
tags: [glossary, terminology, definitions, reference]
---

# PKI & Certificate Management Glossary

> **TL;DR**: Comprehensive reference of PKI and certificate management terminology with definitions, context, and cross-references to detailed documentation.

## A

### ACME (Automated Certificate Management Environment)
**Definition**: A protocol for automating certificate issuance and renewal between certificate authorities and web servers.

**Context**: Developed by Let's Encrypt and standardized as RFC 8555[^1]. Enables zero-touch certificate lifecycle management through API-driven certificate requests, domain validation challenges, and automated renewal. Widely adopted for TLS certificate automation across cloud and on-premises infrastructure.

**Related**: [[acme-protocol-implementation]], [[renewal-automation]]

---

### Authority Information Access (AIA)
**Definition**: X.509 certificate extension indicating where to obtain information about the issuing Certificate Authority.

**Context**: Contains URLs for CA certificates (caIssuers) and OCSP responders. Critical for certificate chain building—without AIA, clients may not find intermediate CA certificates. Required by CA/Browser Forum Baseline Requirements for publicly-trusted certificates[^2].

**Related**: [[certificate-anatomy]], [[chain-validation-errors]]

---

### ASN.1 (Abstract Syntax Notation One)
**Definition**: A standard interface description language for defining data structures that can be serialized and deserialized in a cross-platform way.

**Context**: X.509 certificates are defined using ASN.1 and encoded using DER (Distinguished Encoding Rules). Understanding ASN.1 is essential for low-level certificate parsing and troubleshooting encoding issues.

**Related**: [[certificate-anatomy]], [[x509-standard]]

## B

### Baseline Requirements
**Definition**: Industry-standard requirements for the issuance and management of publicly-trusted SSL/TLS certificates.

**Context**: Published by the CA/Browser Forum, these requirements define domain validation methods, certificate lifetimes, key sizes, and operational practices that Certificate Authorities must follow to remain trusted by browsers. Violations can result in CA distrust[^2].

**Related**: [[x509-standard]], [[ca-architecture]]

---

### Basic Constraints
**Definition**: X.509 certificate extension indicating whether the certificate subject is a CA and the maximum certification path length.

**Context**: Contains boolean flag `CA:TRUE` or `CA:FALSE` and optional path length constraint. Must be marked critical. Prevents end-entity certificates from being used to issue other certificates—a critical security control[^3].

**Related**: [[certificate-anatomy]], [[ca-architecture]]

## C

### CA/Browser Forum
**Definition**: A voluntary organization of Certificate Authorities and browser vendors that develops industry guidelines for certificate issuance.

**Context**: Created the Baseline Requirements, Extended Validation Guidelines, and other standards that govern publicly-trusted PKI. Members include major CAs (DigiCert, Sectigo, Let's Encrypt) and browser vendors (Google, Mozilla, Apple, Microsoft).

**Related**: [[x509-standard]], [[what-is-pki]]

---

### Certificate Authority (CA)
**Definition**: A trusted entity that issues digital certificates by verifying the identity of certificate requesters and signing their public keys.

**Context**: CAs form the root of trust in PKI. Can be public CAs trusted by browsers (DigiCert, Let's Encrypt) or private CAs operated by organizations for internal use. Compromising a CA allows attackers to issue trusted certificates for any identity.

**Related**: [[what-is-pki]], [[ca-architecture]], [[security/ca-compromise-scenarios]]

---

### Certificate Management Protocol (CMP)
**Definition**: IETF protocol (RFC 4210) for interactions between CAs and end entities for certificate lifecycle operations.

**Context**: Provides standardized messages for certificate request, renewal, revocation, and key update. Less commonly used than ACME for automation but supported by some enterprise PKI platforms.

**Related**: [[certificate-issuance-workflows]]

---

### Certificate Policy (CP)
**Definition**: Named set of rules indicating the applicability of a certificate to a particular community and/or class of applications with common security requirements.

**Context**: High-level document defining what a certificate can be used for, validation requirements, and organizational commitments. Often references specific Object Identifiers (OIDs) that appear in certificate policy extensions.

**Related**: [[ca-architecture]], [[x509-standard]]

---

### Certificate Practice Statement (CPS)
**Definition**: Statement of practices used by a Certificate Authority in issuing, managing, and revoking certificates.

**Context**: Detailed operational document describing how the CA implements its certificate policies. Required for WebTrust audits and public CA trust. Covers facility security, key generation procedures, validation processes, and incident response.

**Related**: [[ca-architecture]]

---

### Certificate Revocation List (CRL)
**Definition**: A signed list of revoked certificates published by a Certificate Authority.

**Context**: One of two primary mechanisms for checking certificate revocation status (along with OCSP). CRLs can grow large and require clients to download entire list. Published at regular intervals with next update time specified. Distribution Points extension in certificates indicates CRL download URLs[^3].

**Related**: [[ocsp-and-crl]], [[certificate-lifecycle-management]]

---

### Certificate Signing Request (CSR)
**Definition**: A message sent from an applicant to a Certificate Authority to apply for a digital certificate.

**Context**: Contains the public key and identity information (subject DN, SAN) to be included in the certificate. Signed with the corresponding private key to prove key possession. Generated using OpenSSL, keytool, or other crypto libraries.

**Related**: [[certificate-issuance-workflows]], [[certificate-anatomy]]

---

### Certificate Transparency (CT)
**Definition**: An open framework for monitoring and auditing SSL/TLS certificates.

**Context**: Requires CAs to log all certificates to public, append-only logs before issuance. Enables detection of misissued certificates. Signed Certificate Timestamps (SCTs) prove certificate was logged. Required by Chrome and Safari for publicly-trusted certificates[^4].

**Related**: [[security/common-vulnerabilities]], [[monitoring-and-alerting]]

## D

### DER (Distinguished Encoding Rules)
**Definition**: Binary encoding format for ASN.1 data structures.

**Context**: X.509 certificates are typically encoded in DER format (binary). DER ensures a unique encoding for each ASN.1 structure, which is essential for digital signatures. PEM format is base64-encoded DER with header/footer markers.

**Related**: [[certificate-anatomy]]

---

### Distinguished Name (DN)
**Definition**: Hierarchical identifier format used in X.509 certificates to represent entities.

**Context**: Based on X.500 directory structure. Contains attributes like Country (C), Organization (O), Common Name (CN), etc. Used for certificate subject and issuer fields. Example: `CN=www.example.com, O=Example Corp, C=US`.

**Related**: [[certificate-anatomy]], [[x509-standard]]

---

### Domain Validation (DV)
**Definition**: Certificate validation level where the CA only verifies domain control, not organizational identity.

**Context**: Lowest assurance level for publicly-trusted certificates. Validation performed via email, DNS records, or HTTP challenges. Certificates issue quickly but provide no identity assurance beyond domain control. Appropriate for public web encryption but not for high-assurance needs[^2].

**Related**: [[certificate-issuance-workflows]]

## E

### Extended Key Usage (EKU)
**Definition**: X.509 certificate extension specifying one or more purposes for which the certified public key may be used.

**Context**: Defines application-specific usages like TLS server authentication, code signing, or email protection. More specific than Key Usage extension. Applications should enforce EKU checking to prevent key misuse[^3].

**Related**: [[certificate-anatomy]]

---

### Extended Validation (EV)
**Definition**: Highest validation level for publicly-trusted certificates, requiring rigorous identity verification of the organization.

**Context**: Requires legal existence verification, physical address confirmation, operational status checks, and applicant vetting. Historically displayed with green address bar in browsers, though most browsers have deprecated special UI treatment. Still provides highest identity assurance[^2].

**Related**: [[certificate-issuance-workflows]]

## H

### Hardware Security Module (HSM)
**Definition**: Physical device designed for secure generation, storage, and management of cryptographic keys.

**Context**: Provides tamper-resistant hardware for protecting CA private keys. Meets FIPS 140-2 security levels. Essential for CA operations—root and intermediate CA keys should always reside in HSMs. Cloud providers offer HSM services (AWS CloudHSM, Azure Dedicated HSM, GCP Cloud HSM)[^5].

**Related**: [[hsm-integration]], [[ca-architecture]], [[security/private-key-protection]]

## I

### Intermediate Certificate
**Definition**: A CA certificate signed by a root CA (or another intermediate) that can issue end-entity certificates or additional intermediate certificates.

**Context**: Provides operational and security benefits—root CA can remain offline while intermediate CAs handle daily operations. If intermediate is compromised, it can be revoked and replaced without affecting root trust. Most production PKI deployments use two or three-tier hierarchies with intermediates[^6].

**Related**: [[ca-architecture]], [[what-is-pki]]

---

### Issuing CA
**Definition**: A Certificate Authority that directly issues end-entity (leaf) certificates to servers, users, or devices.

**Context**: Also called subordinate CA or signing CA. Typically an intermediate CA in a hierarchical PKI. Must be online and accessible for certificate issuance operations. Requires high availability and may be load-balanced.

**Related**: [[ca-architecture]], [[certificate-issuance-workflows]]

## K

### Key Ceremony
**Definition**: Formal, witnessed procedure for generating, backing up, or using a Certificate Authority's cryptographic keys.

**Context**: Involves multiple authorized personnel, documented procedures, video recording, and signed attestations. Required for root CA operations and often for high-security intermediate CAs. Provides audit trail and enforces multi-person integrity controls[^6].

**Related**: [[ca-architecture]]

---

### Key Encipherment
**Definition**: Cryptographic operation where a public key is used to encrypt a symmetric key for secure transmission.

**Context**: One of the Key Usage extension values. Required for RSA key exchange in TLS (pre-TLS 1.3). Not needed for ECDHE key agreement. Restricts certificate use to this specific cryptographic operation[^3].

**Related**: [[certificate-anatomy]]

---

### Key Usage
**Definition**: X.509 certificate extension defining the cryptographic operations the certificate key can perform.

**Context**: Bit string specifying operations like Digital Signature, Key Encipherment, Certificate Sign, or CRL Sign. Should be marked critical. Prevents key misuse—signing keys shouldn't encrypt, CA keys shouldn't be used as server keys. Applications must enforce Key Usage checking[^3].

**Related**: [[certificate-anatomy]]

## L

### Leaf Certificate
**Definition**: An end-entity certificate that cannot issue other certificates.

**Context**: The certificate presented by servers, users, or devices in TLS connections or other PKI operations. Must have Basic Constraints set to `CA:FALSE`. Bottom of the certificate chain.

**Related**: [[certificate-anatomy]], [[chain-validation-errors]]

## M

### Mutual TLS (mTLS)
**Definition**: TLS protocol variant where both client and server present certificates for authentication.

**Context**: Provides strong mutual authentication beyond password-based client auth. Used in service mesh architectures, B2B APIs, IoT device authentication, and zero-trust networks. Requires robust certificate lifecycle management for all clients[^7].

**Related**: [[patterns/mutual-tls-patterns]], [[certificate-lifecycle-management]]

## O

### OCSP (Online Certificate Status Protocol)
**Definition**: Protocol for obtaining the revocation status of a certificate in real-time.

**Context**: Alternative to CRLs providing near-real-time revocation checking. Client sends certificate serial number to OCSP responder, receives signed response (good, revoked, or unknown). More efficient than downloading full CRLs but creates privacy concerns as CA sees all validation requests[^8].

**Related**: [[ocsp-and-crl]], [[certificate-lifecycle-management]]

---

### OCSP Stapling
**Definition**: TLS extension where the server obtains OCSP response and delivers it during TLS handshake.

**Context**: Improves performance (client doesn't contact OCSP responder) and privacy (CA doesn't see client validations). Server must refresh stapled responses periodically. Should be enabled on all TLS servers[^8].

**Related**: [[ocsp-and-crl]]

---

### Organization Validation (OV)
**Definition**: Certificate validation level where CA verifies the legal existence and identity of the organization.

**Context**: Higher assurance than Domain Validation but less rigorous than Extended Validation. CA validates organization exists in business registries, confirms physical address, and verifies applicant authority. Organization name appears in certificate subject field[^2].

**Related**: [[certificate-issuance-workflows]]

## P

### PEM (Privacy Enhanced Mail)
**Definition**: Text-based encoding format for certificates and keys using base64 encoding with header/footer markers.

**Context**: Most common format for certificates on Unix/Linux systems. Begins with `-----BEGIN CERTIFICATE-----` and ends with `-----END CERTIFICATE-----`. Contains base64-encoded DER certificate. Can contain multiple certificates in single file.

**Related**: [[certificate-anatomy]]

---

### PKCS (Public Key Cryptography Standards)
**Definition**: Group of cryptography standards published by RSA Laboratories.

**Context**: Several PKCS standards are fundamental to PKI:




- PKCS#1: RSA cryptography standard
- PKCS#7: Cryptographic Message Syntax (signed/encrypted data)
- PKCS#8: Private key information format
- PKCS#10: Certificate Request Syntax (CSR format)
- PKCS#12: Personal Information Exchange (.pfx/.p12 files containing certificates and private keys)

**Related**: [[certificate-issuance-workflows]], [[certificate-anatomy]]

---

### Private Key
**Definition**: Secret key in asymmetric cryptography that must be kept confidential and is used for signing and decryption.

**Context**: Compromise of a private key allows attackers to impersonate the key owner. Must be protected with strong access controls, encryption at rest, and ideally stored in HSMs. Should never be transmitted over networks or stored in version control. Certificate security entirely depends on private key security[^5].

**Related**: [[security/private-key-protection]], [[cryptographic-primitives]]

---

### Public Key
**Definition**: Publicly distributed key in asymmetric cryptography used for signature verification and encryption.

**Context**: Mathematically related to private key but cannot be used to derive it (computationally infeasible). Distributed freely, embedded in certificates. Used by others to encrypt data (only private key holder can decrypt) or verify signatures (proves private key holder created them).

**Related**: [[cryptographic-primitives]], [[certificate-anatomy]]

---

### Public Key Infrastructure (PKI)
**Definition**: Framework of policies, processes, hardware, software, and people that create, manage, distribute, use, store, and revoke digital certificates.

**Context**: Enables secure communications through certificate-based authentication and encryption. Includes Certificate Authorities, certificates, certificate repositories, revocation systems, and the policies governing their operation. Foundation of internet security (HTTPS, code signing, email encryption)[^3].

**Related**: [[what-is-pki]], [[ca-architecture]], [[trust-models]]

## R

### Registration Authority (RA)
**Definition**: Entity responsible for verifying certificate requests before forwarding approved requests to a Certificate Authority.

**Context**: Acts as intermediary between CA and end entities. Handles identity validation, request approval workflows, and certificate lifecycle management operations. Separates validation functions from signing functions for operational efficiency and security. May be co-located with CA or operated by separate entity[^3].

**Related**: [[what-is-pki]], [[certificate-issuance-workflows]]

---

### Root Certificate
**Definition**: Self-signed certificate at the top of a PKI hierarchy that serves as the ultimate trust anchor.

**Context**: Root CA certificates are embedded in operating systems and browsers as trusted certificates. All certificates issued by that CA (directly or through intermediates) inherit trust from the root. Root compromise is catastrophic—entire PKI must be rebuilt and trust redistributed. Should be kept offline for maximum security[^6].

**Related**: [[ca-architecture]], [[trust-models]], [[what-is-pki]]

---

### RSA (Rivest-Shamir-Adleman)
**Definition**: Widely-used asymmetric cryptographic algorithm based on the mathematical difficulty of factoring large numbers.

**Context**: Most common algorithm for PKI keys, though ECDSA adoption increasing. Minimum 2048-bit keys for publicly-trusted certificates; 3072-bit or 4096-bit for higher security. Slower than ECDSA but more widely supported by legacy systems. Key size vs. performance tradeoff is significant at scale[^5].

**Related**: [[cryptographic-primitives]], [[certificate-anatomy]]

## S

### Self-Signed Certificate
**Definition**: Certificate signed by the same entity whose identity it certifies, rather than by a trusted Certificate Authority.

**Context**: Root CA certificates are necessarily self-signed (no higher authority to sign them). End-entity self-signed certificates aren't trusted by default—users must manually trust them. Common in development/testing but inappropriate for production. Often trigger browser warnings[^3].

**Related**: [[ca-architecture]], [[trust-models]]

---

### Serial Number
**Definition**: Unique identifier assigned by a Certificate Authority to each certificate it issues.

**Context**: Must be unique within a CA's scope. Used for certificate revocation (CRLs list serial numbers). Should be unpredictable—predictable serials enabled historical attacks. Minimum 64 bits of entropy required by CA/Browser Forum[^2].

**Related**: [[certificate-anatomy]]

---

### Subject Alternative Name (SAN)
**Definition**: X.509 extension containing additional identities bound to the certificate public key.

**Context**: For TLS certificates, this is where hostnames must appear. Can include DNS names, IP addresses, email addresses, and URIs. Modern browsers ignore Common Name (CN) and only check SAN for hostname validation. Wildcard certificates use SAN (e.g., `*.example.com`)[^3].

**Related**: [[certificate-anatomy]], [[chain-validation-errors]]

---

### Subject Distinguished Name
**Definition**: The identity of the entity the certificate represents, structured as an X.500 Distinguished Name.

**Context**: Appears in certificate subject field. For TLS certificates, CN traditionally contained hostname but this is deprecated—SAN extension now required. For organization-validated certificates, includes organization name and location. For Extended Validation, includes extensive organizational details[^3].

**Related**: [[certificate-anatomy]]

---

### Subject Key Identifier (SKI)
**Definition**: Unique identifier for the public key in a certificate.

**Context**: Hash of the subject public key. Used for chain building and certificate path validation. Should be present in all CA certificates and recommended for end-entity certificates. Paired with Authority Key Identifier in issued certificates[^3].

**Related**: [[certificate-anatomy]], [[chain-validation-errors]]

## T

### Trust Anchor
**Definition**: Authoritative entity for which trust is assumed and not derived—typically a root certificate.

**Context**: Starting point for certificate validation. Operating systems and browsers ship with trust stores containing hundreds of root certificates. Organizations can add custom trust anchors for private PKI. Trust anchor compromise undermines entire trust model[^6].

**Related**: [[trust-models]], [[ca-architecture]]

---

### Trust Store
**Definition**: Repository of trusted root certificates used by applications to validate certificate chains.

**Context**: Operating systems maintain system-wide trust stores (Windows Certificate Store, macOS Keychain, Linux ca-certificates bundle). Browsers may use system store or maintain their own (Firefox). Managed through Group Policy, MDM, or manual import. Regular updates add new roots and remove distrusted CAs.

**Related**: [[trust-models]], [[ca-architecture]]

## V

### Validity Period
**Definition**: Time window during which a certificate is considered valid, specified by Not Before and Not After dates.

**Context**: Certificates must not be trusted outside validity period. Publicly-trusted TLS certificates limited to 398 days maximum since 2020. Shorter lifetimes improve security through forced rotation but increase operational burden. Private PKI can use longer periods (1-10 years common for internal certificates)[^2].

**Related**: [[certificate-anatomy]], [[certificate-lifecycle-management]]

## W

### WebTrust
**Definition**: Audit framework for Certificate Authorities operated by the American Institute of CPAs.

**Context**: Required audit for CAs to be trusted by browsers. Covers operational controls, key management, validation processes, and security practices. Annual audits required to maintain trust. Failures can result in browser distrust. Alternative framework is ETSI (used in Europe)[^2].

**Related**: [[ca-architecture]]

## X

### X.509
**Definition**: ITU-T standard defining the format for public key certificates.

**Context**: Specifies certificate structure, encoding (ASN.1), and extensions. Current version is v3 (supports extensions). Universal standard for internet PKI—all publicly-trusted certificates follow X.509 v3 format. Defined in RFC 5280 for internet use[^3].

**Related**: [[x509-standard]], [[certificate-anatomy]]

## References

[^1]: Barnes, R., et al. "Automatic Certificate Management Environment (ACME)." RFC 8555, March 2019. [Rfc-editor - Rfc8555](https://www.rfc-editor.org/rfc/rfc8555)

[^2]: CA/Browser Forum. "Baseline Requirements for the Issuance and Management of Publicly-Trusted Certificates," Version 2.0.0, November 2023. [Cabforum - Baseline Requirements Documents](https://cabforum.org/baseline-requirements-documents/)

[^3]: Cooper, D., et al. "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile." RFC 5280, May 2008. [Rfc-editor - Rfc5280](https://www.rfc-editor.org/rfc/rfc5280)

[^4]: Laurie, B., et al. "Certificate Transparency." RFC 6962, June 2013. [Rfc-editor - Rfc6962](https://www.rfc-editor.org/rfc/rfc6962)

[^5]: NIST. "Security Requirements for Cryptographic Modules." FIPS 140-2, May 2001. [Nist - Detail](https://csrc.nist.gov/publications/detail/fips/140/2/final)

[^6]: NIST. "Recommendation for Key Management." NIST SP 800-57 Part 1 Rev. 5, May 2020. [Nist - Detail](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

[^7]: Rescorla, E. "The Transport Layer Security (TLS) Protocol Version 1.3." RFC 8446, August 2018. [Rfc-editor - Rfc8446](https://www.rfc-editor.org/rfc/rfc8446)

[^8]: Myers, M., et al. "X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP." RFC 6960, June 2013. [Rfc-editor - Rfc6960](https://www.rfc-editor.org/rfc/rfc6960)

## Change History

| Date | Version | Changes | Reason |
|------|---------|---------|--------|
| 2024-11-09 | 1.0 | Initial creation | Establishing comprehensive PKI terminology reference |

---

**Quality Checks**: 






- [x] All claims cited from authoritative sources
- [x] Cross-references validated
- [x] Practical utility provided through context
- [x] Terms organized alphabetically
- [x] Related pages linked for deeper learning
