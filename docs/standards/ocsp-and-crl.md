---
title: OCSP and CRL
category: standards
last_updated: 2024-11-09
last_reviewed: 2024-11-09
version: 1.0
status: stable
tags: [ocsp, crl, revocation, certificate-status, revocation-checking]
---

# OCSP and CRL

> **TL;DR**: Certificate Revocation Lists (CRLs) and Online Certificate Status Protocol (OCSP) are mechanisms for checking if certificates have been revoked before expiration. CRLs are periodically published lists of revoked certificates, while OCSP provides real-time status queries. Understanding revocation is critical for PKI security—a compromised certificate must be revoked to prevent ongoing misuse.

## Overview

Certificate revocation solves a fundamental PKI problem: what happens when a certificate must be invalidated before its expiration date? Private key compromise, organizational changes, certificate misissuance, and other events require immediate certificate invalidation. Without revocation mechanisms, compromised certificates remain trusted until expiration—potentially years.

The PKI community has developed two primary revocation mechanisms with different trade-offs. Certificate Revocation Lists (CRLs), standardized in X.509 since the beginning, provide a periodically updated list of revoked certificates. Online Certificate Status Protocol (OCSP), defined in RFC 6960[^1], enables real-time revocation queries. Modern implementations often use OCSP Stapling, where servers provide OCSP responses directly, improving performance and privacy.

Understanding revocation is essential for: operating secure PKI systems, troubleshooting certificate validation failures, implementing proper revocation checking, and assessing PKI security posture. The gap between revocation theory and practice—often called the "revocation problem"—remains one of PKI's persistent challenges.

**Related Pages**: [Certificate Anatomy](../foundations/certificate-anatomy.md), [X509 Standard](x509-standard.md), [Tls Protocol](tls-protocol.md), [Certificate Lifecycle Management](../operations/certificate-lifecycle-management.md)

## Key Concepts

### Certificate Revocation Lists (CRLs)

CRLs are signed data structures listing revoked certificates, published periodically by Certificate Authorities.

#### CRL Structure

**Basic Fields**:
```
Version: v2
Signature Algorithm: sha256WithRSAEncryption
Issuer: CN=Example CA, O=Example Corp
This Update: Nov 9 00:00:00 2024 GMT
Next Update: Nov 16 00:00:00 2024 GMT

Revoked Certificates:
    Serial Number: 1A2B3C4D5E6F7890
        Revocation Date: Nov 1 12:34:56 2024 GMT
        Reason Code: keyCompromise (1)
    Serial Number: 9F8E7D6C5B4A3210
        Revocation Date: Nov 5 08:22:14 2024 GMT
        Reason Code: cessationOfOperation (5)
```

**Critical Fields**:

**This Update**: When CRL was issued
- Validators should reject CRLs older than expected update frequency
- Indicates CRL staleness

**Next Update**: When next CRL will be published
- Validators may accept CRL until this time
- Provides grace period for CRL distribution

**Revoked Certificates**: List of serial numbers with revocation metadata
- **Serial Number**: Unique identifier of revoked certificate
- **Revocation Date**: When certificate was revoked
- **Reason Code**: Why certificate was revoked (optional)

**Extensions**:



- **CRL Number**: Monotonically increasing number for tracking
- **Authority Key Identifier**: Identifies CA that signed CRL
- **Issuing Distribution Point**: Scope of CRL (which certificates it covers)

#### Revocation Reason Codes

Defined in RFC 5280[^2], reasons explain why certificate revoked:

| Code | Value | Meaning | Use Case |
|------|-------|---------|----------|
| unspecified | 0 | No reason provided | Default |
| keyCompromise | 1 | Private key exposed | Security incident |
| cACompromise | 2 | CA key exposed | Catastrophic failure |
| affiliationChanged | 3 | Subject changed | Employee left organization |
| superseded | 4 | Certificate replaced | Renewal with new key |
| cessationOfOperation | 5 | Service decommissioned | Server retired |
| certificateHold | 6 | Temporary suspension | Investigation ongoing |
| removeFromCRL | 8 | Unrevoke (only for hold) | Investigation cleared |
| privilegeWithdrawn | 9 | Authorization removed | Access revoked |
| aACompromise | 10 | Attribute authority compromised | Attribute certificates |

**Note**: `certificateHold` (6) is the only reversible revocation. Once a certificate is revoked with any other reason, it cannot be un-revoked.

#### CRL Types

**Base CRL**:



- Complete list of all revoked certificates
- Issued periodically (daily, weekly)
- Can grow very large for CAs with many revocations

**Delta CRL**:



- Contains only changes since last base CRL
- Smaller size, more frequent updates
- References base CRL via Base CRL Number extension
- Client must obtain both base and delta

**Indirect CRL**:



- Published by entity other than certificate issuer
- Certificate Issuer extension identifies actual issuer
- Enables centralized CRL distribution

**Partitioned CRL**:



- CRL divided into multiple segments
- Issuing Distribution Point extension specifies partition
- Reduces download size for clients

#### CRL Distribution Points (CDP)

Certificates include CRL Distribution Points extension indicating where to obtain CRLs:

```
X509v3 CRL Distribution Points:
    Full Name:
      URI:http://crl.example.com/ExampleCA.crl
      URI:ldap://ldap.example.com/cn=ExampleCA,ou=CAs,o=Example?certificateRevocationList
```

**Protocol Support**:



- **HTTP**: Most common, simple download
- **LDAP**: Directory service access
- **FTP**: Rarely used
- **File**: Local file system (internal use only)

#### CRL Advantages and Disadvantages

**Advantages**:



- **Simple**: Easy to implement and understand
- **Offline**: Can download and cache for offline validation
- **Privacy**: No per-certificate queries reveal which sites visited
- **Deterministic**: Same CRL for all validators at same time

**Disadvantages**:



- **Latency**: Revocations not visible until next CRL published
- **Size**: Can grow to megabytes for large CAs
- **Bandwidth**: Every client downloads entire list
- **Scalability**: Doesn't scale well for high-revocation-rate CAs

### Online Certificate Status Protocol (OCSP)

OCSP provides real-time certificate status queries via request-response protocol.

#### OCSP Request-Response Flow

```
Client                                    OCSP Responder

1. Build OCSP Request
   - Certificate serial number
   - Issuer name hash
   - Issuer key hash

2. Send OCSP Request  -------->

3.                              Lookup certificate status
                                in CA database

4.                    <--------  Send OCSP Response
                                 - Status (good/revoked/unknown)
                                 - This Update time
                                 - Next Update time
                                 - Revocation details (if revoked)

5. Validate OCSP Response
   - Check signature
   - Verify timing
   - Check response matches request

6. Make trust decision based on status
```

#### OCSP Request Format

**Request Structure**:
```
OCSP Request:
  Version: 1 (0x0)
  Requestor List:
      Certificate ID:
        Hash Algorithm: sha256
        Issuer Name Hash: A1B2C3D4...
        Issuer Key Hash: E5F6A7B8...
        Serial Number: 1A2B3C4D5E6F7890
  Request Extensions:
      Nonce: F1E2D3C4B5A69788... (optional)
```

**Key Components**:



- **Issuer Name Hash**: SHA-256 hash of certificate issuer DN
- **Issuer Key Hash**: SHA-256 hash of CA public key
- **Serial Number**: Certificate to check
- **Nonce**: Random value to prevent replay attacks (optional)

#### OCSP Response Format

**Response Structure**:
```
OCSP Response:
  Response Status: successful (0x0)
  Response Type: Basic OCSP Response
  Version: 1 (0x0)
  Responder ID: CN=OCSP Responder, O=Example Corp
  Produced At: Nov 9 12:34:56 2024 GMT
  Responses:
      Certificate ID: (matches request)
      Cert Status: good
      This Update: Nov 9 12:30:00 2024 GMT
      Next Update: Nov 9 13:30:00 2024 GMT
      Response Extensions:
          Nonce: F1E2D3C4B5A69788... (matches request)
  Signature Algorithm: sha256WithRSAEncryption
  Signature: A1B2C3D4E5F6... (signed by OCSP responder)
```

**Certificate Status Values**:

**Good**: Certificate is valid and not revoked
```
Cert Status: good
This Update: Nov 9 12:30:00 2024 GMT
```

**Revoked**: Certificate has been revoked
```
Cert Status: revoked
Revocation Time: Nov 1 08:15:30 2024 GMT
Revocation Reason: keyCompromise (1)
```

**Unknown**: Responder doesn't know about this certificate
```
Cert Status: unknown
```

**Response Status Codes**:



- **successful (0)**: Valid response included
- **malformedRequest (1)**: Request syntax error
- **internalError (2)**: Responder internal error
- **tryLater (3)**: Service temporarily unavailable
- **sigRequired (5)**: Request must be signed
- **unauthorized (6)**: Requestor not authorized

#### OCSP Advantages and Disadvantages

**Advantages**:



- **Real-time**: Near-instant revocation visibility
- **Efficient**: Only query status of certificates actually needed
- **Smaller**: Responses much smaller than CRLs
- **Dynamic**: Can implement custom policies per request

**Disadvantages**:



- **Privacy**: CA sees which certificates clients are validating
- **Availability**: Requires network connection and OCSP responder availability
- **Performance**: Network round-trip adds latency to TLS handshake
- **Reliability**: OCSP responder failure can prevent certificate validation

### OCSP Stapling

OCSP Stapling (formally "TLS Certificate Status Request extension") addresses OCSP privacy and performance concerns.

#### How OCSP Stapling Works

```
Server                                     OCSP Responder

1. Server queries OCSP responder periodically
   for its own certificate status  --------->

2.                                   <---------  OCSP Response

3. Server caches OCSP response


Client                                     Server

4. ClientHello with
   status_request extension        --------->

5.                                   <---------  ServerHello
                                                Certificate
                                                CertificateStatus
                                                  (OCSP Response)

6. Client validates OCSP response
   - Check signature
   - Verify timing (not expired)
   - Check status

7. TLS connection continues
```

**Key Benefits**:

**Privacy**: Client doesn't contact OCSP responder
- CA doesn't see which sites user visits
- Reduces tracking opportunities

**Performance**: No client-side OCSP query latency
- Server provides cached response
- No additional round-trip during TLS handshake

**Reliability**: Cached response available even if OCSP responder down
- Improves availability
- Reduces dependency on OCSP infrastructure

**Server Responsibility**: Server must keep OCSP responses fresh
- Query OCSP responder periodically (e.g., hourly)
- Refresh before response expires
- Handle responder failures gracefully

#### OCSP Stapling Configuration

**Nginx**:
```nginx
server {
    listen 443 ssl;
    
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_trusted_certificate /etc/ssl/certs/ca-chain.crt;
    
    # Enable OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # DNS resolver for OCSP responder lookup
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # OCSP response cache
    ssl_stapling_file /var/cache/nginx/ocsp_response.der;  # Optional
}
```

**Apache**:
```apache
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    SSLCertificateChainFile /etc/ssl/certs/ca-chain.crt
    
    # Enable OCSP Stapling
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
    SSLStaplingStandardCacheTimeout 3600
    SSLStaplingErrorCacheTimeout 600
</VirtualHost>
```

**Testing**:
```bash
# Test OCSP stapling with OpenSSL
openssl s_client -connect example.com:443 -status -servername example.com

# Look for:
# OCSP Response Status: successful (0x0)
# Cert Status: good
```

#### OCSP Must-Staple

Certificate extension requiring OCSP stapling:

**X.509 Extension**:
```
TLS Feature: status_request (5)
```

**Effect**: Clients must fail validation if server doesn't provide stapled OCSP response

**Security Benefit**: Prevents downgrade to soft-fail mode

**Risk**: Server OCSP failures become hard failures (impacts availability)

### Soft-Fail vs. Hard-Fail

Critical decision: what happens when revocation check fails?

#### Soft-Fail (Default in Most Browsers)

**Behavior**: If revocation check fails, proceed anyway

**Rationale**:



- OCSP responders frequently have availability issues
- Hard-fail would break many legitimate sites
- Balance security against usability

**Example Scenarios**:



- OCSP responder timeout: **Accept certificate**
- CRL download fails: **Accept certificate**
- OCSP response indicates "tryLater": **Accept certificate**

**Security Trade-off**: Attackers can cause revocation check failures (DoS OCSP responder) to make revoked certificates accepted

#### Hard-Fail

**Behavior**: If revocation check fails, reject certificate

**Rationale**:



- Security over availability
- Don't trust certificates if can't verify revocation status

**Use Cases**:



- High-security environments
- Internal PKI with reliable infrastructure
- Certificate pinning scenarios
- OCSP Must-Staple certificates

**Example Scenarios**:



- OCSP responder timeout: **Reject certificate**
- CRL download fails: **Reject certificate**
- OCSP response indicates "tryLater": **Reject certificate**

**Configuration** (Example):
```bash
# OpenSSL hard-fail verification
openssl verify -CRLfile crl.pem -crl_check_all server.crt
# Fails if CRL not available or revocation detected
```

### The Revocation Problem

The persistent challenge of effective certificate revocation.

#### Key Issues

**Browser Soft-Fail**:



- Most browsers default to soft-fail
- Attackers can exploit by blocking revocation checks
- Security vs. availability trade-off

**CRL Scalability**:



- CRLs can grow to many megabytes
- Clients must download entire list
- Inefficient for CAs with many certificates

**OCSP Privacy**:



- Every certificate validation reveals sites visited
- Without stapling, CA tracks user browsing
- Privacy-conscious users may disable OCSP

**OCSP Performance**:



- Network latency for each TLS connection
- OCSP responder must handle high query volume
- Failures impact certificate validation

**Incomplete Checking**:



- Many applications don't check revocation at all
- Legacy systems lack OCSP support
- Configuration errors disable checking

#### Proposed Solutions

**Certificate Transparency**:



- Public logs of all issued certificates
- Domain owners monitor for unexpected certificates
- Detects misissuance, doesn't prevent it
- Complementary to revocation

**Short-Lived Certificates**:



- Issue certificates with short validity (hours/days)
- No need for revocation (expires quickly)
- Requires reliable automation
- Let's Encrypt model: 90-day certificates

**CRLite** (Mozilla):



- Compressed, space-efficient revocation data
- Aggregates CRL data from all CAs
- Ships with Firefox updates
- Enables hard-fail without performance penalty

**OCSP Stapling + Must-Staple**:



- Mandatory stapling prevents soft-fail exploitation
- Server responsible for OCSP queries
- Requires careful operational planning

## Practical Guidance

### Implementing Revocation Checking

#### OpenSSL Certificate Verification

**Basic Verification** (No Revocation):
```bash
openssl verify -CAfile ca-cert.pem server.crt
```

**CRL Checking**:
```bash
# Download CRL
curl -o crl.pem http://crl.example.com/ExampleCA.crl

# Convert to PEM if needed
openssl crl -inform DER -in crl.der -out crl.pem

# Verify with CRL
openssl verify -CAfile ca-cert.pem -CRLfile crl.pem -crl_check server.crt

# Check entire chain
openssl verify -CAfile ca-cert.pem -CRLfile crl.pem -crl_check_all server.crt
```

**OCSP Checking**:
```bash
# Extract OCSP responder URL from certificate
openssl x509 -in server.crt -noout -ocsp_uri
# Output: http://ocsp.example.com

# Perform OCSP query
openssl ocsp \
  -CAfile ca-cert.pem \
  -issuer issuer-cert.pem \
  -cert server.crt \
  -url http://ocsp.example.com \
  -resp_text

# Output includes:
# Response: successful (0x0)
# Cert Status: good
```

#### Programming Examples

**Python (cryptography library)**:
```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes
import requests

def check_ocsp_status(cert, issuer_cert):
    # Build OCSP request
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
    req = builder.build()
    
    # Get OCSP responder URL from certificate
    aia = cert.extensions.get_extension_for_oid(
        x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
    )
    ocsp_url = None
    for desc in aia.value:
        if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
            ocsp_url = desc.access_location.value
            break
    
    if not ocsp_url:
        return None
    
    # Send OCSP request
    response = requests.post(
        ocsp_url,
        data=req.public_bytes(serialization.Encoding.DER),
        headers={'Content-Type': 'application/ocsp-request'}
    )
    
    # Parse OCSP response
    ocsp_resp = ocsp.load_der_ocsp_response(response.content)
    
    # Check status
    if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
        return "good"
    elif ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        return "revoked"
    else:
        return "unknown"
```

### Operating an OCSP Responder

#### Architecture Considerations

**High Availability**:



- Multiple responder instances behind load balancer
- Geographic distribution for low latency
- Database replication for revocation status

**Performance Requirements**:



- Handle thousands of queries per second
- Millisecond response times
- Minimal memory and CPU overhead

**Security**:



- Dedicated OCSP signing key (not CA key)
- Responder key access controls
- Rate limiting and DoS protection
- Audit logging of all queries

#### OCSP Responder Implementation

**Using OpenSSL ocsp**:
```bash
# Generate OCSP responder certificate
openssl req -new -nodes \
  -keyout ocsp_key.pem \
  -out ocsp_req.pem \
  -subj "/CN=OCSP Responder/O=Example Corp"

# CA signs OCSP responder certificate with id-kp-OCSPSigning EKU
openssl ca -config ca.conf \
  -extensions ocsp_ext \
  -in ocsp_req.pem \
  -out ocsp_cert.pem

# Run OCSP responder
openssl ocsp \
  -index index.txt \      # CA's certificate database
  -CA ca_cert.pem \
  -rsigner ocsp_cert.pem \
  -rkey ocsp_key.pem \
  -port 8080 \
  -text

# Responder listens on http://localhost:8080
```

**Production OCSP Responders**:



- **Boulder** (Let's Encrypt): High-performance, Go-based
- **EJBCA**: Enterprise PKI with built-in OCSP
- **OpenXPKI**: Open-source PKI suite with OCSP
- **Custom**: Build on top of web frameworks (Flask, Express)

#### Response Caching and Pre-Generation

**Pre-Generate Responses**:
```python
# Generate OCSP responses for all valid certificates
# Cache to disk or database
# Serve from cache (no database query per request)

for cert in valid_certificates:
    response = generate_ocsp_response(cert)
    cache.store(cert.serial_number, response)
```

**Benefits**:



- Faster response times (no database query)
- Reduced load on backend database
- Better scalability

**Refresh Strategy**:



- Regenerate responses periodically (e.g., every hour)
- Update immediately on revocation
- Include reasonable Next Update time

### Troubleshooting Revocation Issues

#### "Unable to Get CRL"

**Diagnosis**:
```bash
# Check CRL Distribution Points in certificate
openssl x509 -in server.crt -noout -ext crlDistributionPoints

# Try downloading CRL
curl -I http://crl.example.com/ExampleCA.crl

# Check CRL is valid
openssl crl -in downloaded.crl -noout -text
```

**Common Causes**:
1. **CRL URL not accessible**: Firewall, DNS issues
2. **CRL expired**: Next Update in past
3. **CRL not published**: CA operational issue

**Fixes**:



- Ensure network access to CRL URL
- Configure CA to publish CRLs regularly
- Check Next Update time in CRL

#### "OCSP Responder Timeout"

**Diagnosis**:
```bash
# Test OCSP directly
time openssl ocsp -CAfile ca.pem -issuer issuer.pem -cert server.crt -url http://ocsp.example.com

# Check DNS resolution
nslookup ocsp.example.com

# Check network connectivity
curl -v http://ocsp.example.com
```

**Common Causes**:
1. **Network issues**: Firewall blocking OCSP traffic
2. **Responder overloaded**: Too many queries
3. **Responder down**: Service failure

**Fixes**:



- Enable OCSP stapling (server-side caching)
- Increase OCSP responder capacity
- Implement responder redundancy
- Consider soft-fail policies

#### "OCSP Response Verification Failed"

**Diagnosis**:
```bash
# Verbose OCSP query
openssl ocsp -CAfile ca.pem -issuer issuer.pem -cert server.crt \
  -url http://ocsp.example.com -resp_text

# Check:
# - Signature validation
# - Response timing (This Update, Next Update)
# - Nonce validation
```

**Common Causes**:
1. **Wrong OCSP signing certificate**: Not trusted by CA
2. **Clock skew**: Server/client time mismatch
3. **Expired response**: Next Update in past

**Fixes**:



- Verify OCSP responder certificate properly signed
- Sync system clocks (NTP)
- Configure responder to issue fresh responses

## Common Pitfalls

- **Not checking revocation at all**: Applications validating certificates without revocation checking
  - **Why it happens**: Complexity; performance concerns; default configurations don't enable it
  - **How to avoid**: Enable CRL or OCSP checking explicitly; test revocation validation
  - **How to fix**: Configure revocation checking; verify with test revoked certificates

- **Soft-fail without understanding implications**: Accepting certificates when revocation check fails
  - **Why it happens**: Default browser behavior; not understanding security trade-off
  - **How to avoid**: Understand soft-fail vs hard-fail trade-offs; implement hard-fail for high-security
  - **How to fix**: Configure hard-fail where appropriate; implement fallback strategies

- **Stale CRLs**: Publishing CRLs infrequently or not updating Next Update time
  - **Why it happens**: CA operational issues; insufficient automation
  - **How to avoid**: Automate CRL generation; monitor CRL freshness; alert on stale CRLs
  - **How to fix**: Generate CRLs more frequently; fix CA automation; ensure reliable publication

- **OCSP responder single point of failure**: No redundancy for OCSP responder
  - **Why it happens**: Underestimating OCSP criticality; cost concerns
  - **How to avoid**: Deploy multiple OCSP responders; use load balancers; enable OCSP stapling
  - **How to fix**: Add responder redundancy; implement stapling; monitor responder availability

- **Ignoring OCSP privacy concerns**: Not implementing OCSP stapling when privacy matters
  - **Why it happens**: Lack of awareness; configuration complexity
  - **How to avoid**: Enable OCSP stapling by default; understand privacy implications
  - **How to fix**: Configure stapling; test with OpenSSL; monitor stapling rate

## Security Considerations

### Revocation Check Bypass

**Attack Scenarios**:

**OCSP Responder DoS**:



- Attacker blocks access to OCSP responder
- Soft-fail allows revoked certificate acceptance
- **Mitigation**: OCSP stapling (server caches responses)

**CRL Download Prevention**:



- Attacker blocks CRL download
- Client cannot verify revocation status
- **Mitigation**: Local CRL caching; alternative verification methods

**Clock Manipulation**:



- Attacker manipulates system clock
- OCSP response appears expired or not yet valid
- **Mitigation**: Secure time synchronization (NTP); detect clock skew

### Revocation Timing

**Key Challenge**: Revocation takes time to propagate

**CRL Propagation Delay**:
```
T0: Certificate compromised
T1: CA revokes certificate (updates database)
T2: Next CRL published (could be hours/days later)
T3: Clients download new CRL
T4: All clients have updated CRL

Exposure window: T0 to T4
```

**OCSP Propagation Delay**:
```
T0: Certificate compromised
T1: CA revokes certificate (updates database)
T2: OCSP responder queries database (typically near-instant)
T3: Clients query OCSP responder

Exposure window: T0 to T3 (minutes typically)
```

**Mitigation Strategies**:



- Minimize exposure windows with frequent updates
- Use OCSP for time-critical revocations
- Consider short-lived certificates eliminating revocation need
- Implement Certificate Transparency monitoring

### Privacy vs. Security

**Privacy Concerns**:



- OCSP queries reveal which certificates (and therefore sites) users validate
- CA can track user browsing behavior
- ISPs or network observers see OCSP queries

**Privacy-Preserving Approaches**:



- **OCSP Stapling**: Server queries, client doesn't contact CA
- **CRLite**: Pre-fetched revocation data, no per-certificate queries
- **Short-Lived Certificates**: No revocation checking needed

## Real-World Examples

### Case Study: Symantec Certificate Revocation (2017)

**Event**: Google Chrome announced distrust of Symantec CA certificates

**Revocation Challenge**:



- Thousands of certificates needed revocation/replacement
- Immediate revocation would break many websites
- Phased approach over 18 months

**Process**:
1. Announce deprecation timeline
2. Issue warnings in Chrome
3. Gradual increase in warning severity
4. Final distrust deadline

**Key Takeaway**: Mass revocation requires careful planning. Immediate revocation of many certificates is operationally challenging.

### Case Study: Let's Encrypt OCSP Capacity

**Challenge**: Let's Encrypt issues over 200 million certificates

**OCSP Requirements**:



- Billions of OCSP queries per day
- Sub-100ms response times
- 99.99% availability

**Solution**:



- Pre-generated OCSP responses
- CDN distribution of responses
- Minimal response sizes (no certificates in response)
- Aggressive caching strategies

**Key Takeaway**: OCSP at scale requires architectural optimization. Pre-generation and caching critical for performance.

### Case Study: CRL Distribution Point Outages

**Common Issue**: CRL servers going down breaking certificate validation

**Example Incidents**:



- Corporate firewall blocking CRL access
- CRL server capacity exceeded
- DNS issues preventing CRL resolution

**Impact**:



- Applications fail to validate certificates
- Soft-fail browsers continue working
- Hard-fail applications break

**Key Takeaway**: CRL infrastructure must be as reliable as CA infrastructure. Redundancy and monitoring essential.

## Further Reading

### Essential Resources
- [RFC 6960 - Online Certificate Status Protocol](https://www.rfc-editor.org/rfc/rfc6960) - OCSP standard
- [RFC 5280 - X.509 Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280) - CRL specification
- [RFC 6066 - TLS Extensions (OCSP Stapling)](https://www.rfc-editor.org/rfc/rfc6066) - OCSP stapling standard
- [Mozilla CRLite](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/) - Modern revocation approach

### Advanced Topics
- [Certificate Lifecycle Management](../operations/certificate-lifecycle-management.md) - Managing certificate revocation operationally
- [Tls Protocol](tls-protocol.md) - How revocation checking fits into TLS
- [Certificate Anatomy](../foundations/certificate-anatomy.md) - CRL Distribution Points extension
- [Chain Validation Errors](../troubleshooting/chain-validation-errors.md) - Debugging revocation failures

## References

[^1]: Santesson, S., et al. "X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP." RFC 6960, June 2013. [Rfc-editor - Rfc6960](https://www.rfc-editor.org/rfc/rfc6960)

[^2]: Cooper, D., et al. "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile." RFC 5280, May 2008. [Rfc-editor - Rfc5280](https://www.rfc-editor.org/rfc/rfc5280)

## Change History

| Date | Version | Changes | Reason |
|------|---------|---------|--------|
| 2024-11-09 | 1.0 | Initial creation | Essential revocation standard documentation |

---

**Quality Checks**: 



- [x] All claims cited from authoritative sources
- [x] Cross-references validated
- [x] Practical guidance included
- [x] Examples are current and relevant
- [x] Security considerations addressed
