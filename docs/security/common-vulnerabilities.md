# Common Vulnerabilities

**Category**: Security  
**Complexity**: Advanced  
**Prerequisites**: [[Certificate Anatomy]], [[Chain of Trust]], [[TLS Protocol]], [[Private Key Protection]]  
**Related**: [[Certificate Pinning]], [[Trust Models]], [[Cryptographic Primitives]]

---

## Overview

PKI systems face numerous vulnerabilities across the certificate lifecycle, from issuance through validation to revocation. Understanding these vulnerabilities is critical for securing certificate infrastructure and preventing attacks that can compromise confidentiality, integrity, and authenticity.

This page catalogs common PKI vulnerabilities, real-world incidents, and practical mitigations.

## Certificate Issuance Vulnerabilities

### Weak Domain Validation

**Vulnerability**: Attackers can obtain valid certificates for domains they don't control by exploiting weak validation processes.

**Attack Vectors**:

**1. Email-based validation bypass**:
```
Traditional approach: CA sends validation email to admin@domain.com
Attack: Attacker gains control of admin email account
Result: Attacker can request valid certificate for domain.com
```

**2. DNS validation bypass**:
```python
# Vulnerability: Temporary DNS control
class DNSValidationAttack:
    """
    Attacker temporarily gains DNS control to pass validation
    """
    
    def attack_scenario(self):
        # Step 1: Attacker initiates certificate request
        ca_challenge = request_certificate("victim.com")
        # CA responds: "Create TXT record _acme-challenge.victim.com with value XYZ"
        
        # Step 2: Attacker exploits DNS weakness
        # Examples:
        # - Subdomain takeover (pointing to attacker's server)
        # - BGP hijacking to route DNS queries
        # - Registrar account compromise
        # - DNS cache poisoning
        
        # Step 3: Attacker creates validation record
        create_dns_record("_acme-challenge.victim.com", "XYZ")
        
        # Step 4: CA validates and issues certificate
        certificate = ca.validate_and_issue()
        
        # Step 5: Attacker removes DNS record (covers tracks)
        delete_dns_record("_acme-challenge.victim.com")
        
        # Result: Valid certificate for victim.com in attacker's hands
        return certificate
```

**3. HTTP validation bypass**:
```
Traditional: CA requests file at http://domain.com/.well-known/acme-challenge/token
Attacks:
- HTTP request interception
- Load balancer misconfiguration
- Shared hosting exploitation
- CDN configuration errors
```

**Real-World Incident**: Let's Encrypt Boulder Bug (2016)
- Vulnerability in validation logic
- Allowed certificates for domains with only partial control
- 2,600+ certificates revoked

**Mitigations**:
```python
class SecureDomainValidation:
    """
    Implement multiple validation checks
    """
    
    def validate_domain(self, domain: str, validation_method: str) -> bool:
        """
        Multi-layered domain validation
        """
        validations = []
        
        # 1. Check domain ownership history
        if not self.verify_consistent_ownership(domain, days=30):
            raise ValidationError("Domain ownership recently changed")
        
        # 2. Multiple validation methods
        if validation_method == 'dns':
            validations.append(self.dns_validation(domain))
            # Also require HTTP validation
            validations.append(self.http_validation(domain))
        
        # 3. Check for suspicious patterns
        if self.detect_suspicious_patterns(domain):
            # Require manual review
            self.flag_for_manual_review(domain)
            return False
        
        # 4. CAA record check (required by RFC 8659)
        caa_records = self.check_caa_records(domain)
        if caa_records and not self.ca_is_authorized(caa_records):
            raise ValidationError("CA not authorized by CAA records")
        
        # 5. Certificate Transparency pre-check
        if self.domain_has_suspicious_ct_history(domain):
            self.flag_for_review(domain)
        
        return all(validations)
    
    def verify_consistent_ownership(self, domain: str, days: int) -> bool:
        """
        Verify domain ownership hasn't changed recently
        """
        whois_history = self.get_whois_history(domain, days)
        
        # Check for recent ownership transfers
        if len(set(record['registrant'] for record in whois_history)) > 1:
            return False
        
        # Check for recent DNS changes
        dns_history = self.get_dns_history(domain, days)
        if self.detect_unusual_dns_changes(dns_history):
            return False
        
        return True
```

### CAA Record Bypass

**Vulnerability**: Certificate Authority Authorization (CAA) records specify which CAs can issue certificates, but not all CAs check them properly.

**Attack**: Attacker requests certificate from CA that doesn't check CAA records.

**Example**:
```dns
; Intended CAA policy
victim.com. CAA 0 issue "trusted-ca.com"

; Attacker requests from different CA
; Vulnerable CA doesn't check CAA records
; Issues certificate despite CAA policy
```

**Detection**:
```python
import dns.resolver

def check_caa_compliance(domain: str, issuing_ca: str) -> bool:
    """
    Verify CA is authorized by CAA records
    """
    try:
        # Query CAA records
        answers = dns.resolver.resolve(domain, 'CAA')
        
        authorized_cas = []
        wildcards_allowed = False
        
        for rdata in answers:
            if rdata.tag == b'issue':
                authorized_cas.append(rdata.value.decode())
            elif rdata.tag == b'issuewild':
                wildcards_allowed = True
                authorized_cas.append(rdata.value.decode())
        
        # Check if issuing CA is authorized
        if not authorized_cas:
            # No CAA records = any CA can issue
            return True
        
        # Verify CA is in authorized list
        for authorized_ca in authorized_cas:
            if issuing_ca in authorized_ca:
                return True
        
        # CA not authorized
        raise CAAViolation(
            f"CA {issuing_ca} not authorized by CAA records. "
            f"Authorized: {authorized_cas}"
        )
        
    except dns.resolver.NXDOMAIN:
        # No CAA records = any CA can issue (per RFC)
        return True
    except dns.resolver.NoAnswer:
        # No CAA records at this level, check parent domain
        parent = '.'.join(domain.split('.')[1:])
        if parent:
            return check_caa_compliance(parent, issuing_ca)
        return True
```

**Mitigation**:
- RFC 8659 requires CAs to check CAA records (since 2019)
- Set CAA records for your domains
- Monitor Certificate Transparency logs for unauthorized issuance

### Weak Key Generation

**Vulnerability**: Certificates issued with weak or compromised keys.

**Attack Scenarios**:

**1. Predictable random number generation**:
```python
# VULNERABLE: Debian OpenSSL Bug (2008)
# Random number generator used only process ID as entropy
# Result: Only 32,767 possible RSA keys

import random
random.seed(os.getpid())  # BAD: Predictable seed
private_key = generate_rsa_key(random)

# Attacker can generate all possible keys and find match
```

**2. Shared keys across systems**:
```python
# VULNERABLE: Using same key for multiple purposes
class WeakKeyPractice:
    """
    Anti-pattern: Key reuse
    """
    
    def __init__(self):
        # Same key used for multiple certificates
        self.shared_key = self.load_key("shared.key")
    
    def issue_cert(self, domain: str):
        # Creates certificate for different domain with same key
        return create_certificate(domain, self.shared_key)
    
    # Risk: Compromise of one domain compromises all
```

**Real-World Impact**: Debian OpenSSL Bug
- Affected: Debian/Ubuntu systems (2006-2008)
- Impact: Weak SSH and SSL keys generated
- Scope: Millions of certificates and SSH keys compromised
- Resolution: Mass revocation and regeneration

**Mitigations**:
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import secrets

class SecureKeyGeneration:
    """
    Generate cryptographically secure keys
    """
    
    def generate_rsa_key(self, key_size: int = 2048) -> rsa.RSAPrivateKey:
        """
        Generate RSA key with secure random number generator
        """
        # Validate key size
        if key_size < 2048:
            raise ValueError("Minimum key size is 2048 bits")
        
        # Use system's CSPRNG
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        return private_key
    
    def verify_key_uniqueness(self, key: rsa.RSAPrivateKey) -> bool:
        """
        Verify key hasn't been generated before
        """
        # Hash the public key
        public_key = key.public_key()
        key_hash = self.hash_public_key(public_key)
        
        # Check against database of issued keys
        if self.key_hash_exists(key_hash):
            raise SecurityError(
                "Key collision detected - regenerate key"
            )
        
        # Store hash for future checks
        self.store_key_hash(key_hash)
        return True
    
    def validate_key_entropy(self, key: rsa.RSAPrivateKey) -> bool:
        """
        Verify key has sufficient entropy
        """
        # Extract key components
        private_numbers = key.private_numbers()
        
        # Test for weak primes
        if not self.is_strong_prime(private_numbers.p):
            raise SecurityError("Weak prime detected in key")
        if not self.is_strong_prime(private_numbers.q):
            raise SecurityError("Weak prime detected in key")
        
        # Verify key strength
        if (private_numbers.p - 1).bit_length() < key.key_size // 2 - 10:
            raise SecurityError("Insufficient key entropy")
        
        return True
```

## Certificate Validation Vulnerabilities

### Incomplete Chain Validation

**Vulnerability**: Applications fail to validate entire certificate chain properly.

**Common Mistakes**:

**1. Only validating leaf certificate**:
```python
# VULNERABLE: Doesn't check intermediate certificates
def vulnerable_validation(cert: Certificate) -> bool:
    # Only checks if leaf certificate is signed
    if verify_signature(cert):
        return True
    return False

# Attack: Attacker uses self-signed intermediate
# Leaf cert signature validates, but chain is broken
```

**2. Missing expiration checks**:
```python
# VULNERABLE: Doesn't verify validity dates
def weak_validation(cert: Certificate) -> bool:
    # Checks signature but ignores notBefore/notAfter
    return verify_certificate_signature(cert)

# Attack: Use expired certificate that was once valid
```

**3. Improper hostname verification**:
```python
# VULNERABLE: Doesn't check hostname matches
def insecure_validation(cert: Certificate, hostname: str) -> bool:
    # Validates certificate but not hostname
    return validate_certificate_chain(cert)

# Attack: Use valid certificate for different domain
```

**Secure Implementation**:
```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
import ssl

class SecureCertificateValidator:
    """
    Comprehensive certificate validation
    """
    
    def __init__(self, trust_store: List[Certificate]):
        self.trust_store = trust_store
    
    def validate_certificate_chain(
        self, 
        cert_chain: List[bytes], 
        hostname: str
    ) -> bool:
        """
        Validate complete certificate chain
        """
        # Parse certificates
        certificates = [
            x509.load_der_x509_certificate(cert_der, default_backend())
            for cert_der in cert_chain
        ]
        
        # 1. Validate each certificate's validity period
        for cert in certificates:
            self.validate_temporal_validity(cert)
        
        # 2. Validate chain signatures
        self.validate_signature_chain(certificates)
        
        # 3. Validate chain to trusted root
        self.validate_trust_anchor(certificates)
        
        # 4. Validate hostname
        self.validate_hostname(certificates[0], hostname)
        
        # 5. Check revocation status
        self.check_revocation(certificates)
        
        # 6. Validate key usage and constraints
        self.validate_key_usage(certificates)
        
        return True
    
    def validate_temporal_validity(self, cert: x509.Certificate):
        """
        Check certificate is within validity period
        """
        now = datetime.now(timezone.utc)
        
        if now < cert.not_valid_before_utc:
            raise ValidationError(
                f"Certificate not yet valid. "
                f"Valid from: {cert.not_valid_before_utc}"
            )
        
        if now > cert.not_valid_after_utc:
            raise ValidationError(
                f"Certificate expired. "
                f"Expired: {cert.not_valid_after_utc}"
            )
    
    def validate_signature_chain(self, certificates: List[x509.Certificate]):
        """
        Verify each certificate is signed by next in chain
        """
        for i in range(len(certificates) - 1):
            cert = certificates[i]
            issuer_cert = certificates[i + 1]
            
            # Verify issuer
            if cert.issuer != issuer_cert.subject:
                raise ValidationError(
                    f"Chain break: Certificate {i} issuer doesn't match "
                    f"certificate {i+1} subject"
                )
            
            # Verify signature
            try:
                issuer_public_key = issuer_cert.public_key()
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_algorithm_parameters
                )
            except Exception as e:
                raise ValidationError(
                    f"Signature verification failed for certificate {i}: {e}"
                )
    
    def validate_trust_anchor(self, certificates: List[x509.Certificate]):
        """
        Verify chain terminates at trusted root
        """
        root_cert = certificates[-1]
        
        # Check if root is in trust store
        for trusted_root in self.trust_store:
            if root_cert.fingerprint == trusted_root.fingerprint:
                return True
        
        raise ValidationError(
            "Certificate chain doesn't terminate at trusted root"
        )
    
    def validate_hostname(self, cert: x509.Certificate, hostname: str):
        """
        Verify certificate is valid for hostname
        """
        # Get Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_names = []
        
        # Get Common Name from subject
        try:
            cn = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
        except (IndexError, KeyError):
            cn = None
        
        # Check hostname matches
        valid_names = san_names + ([cn] if cn else [])
        
        if not any(self.hostname_matches(hostname, name) for name in valid_names):
            raise ValidationError(
                f"Hostname {hostname} doesn't match certificate names: "
                f"{valid_names}"
            )
    
    def hostname_matches(self, hostname: str, cert_name: str) -> bool:
        """
        Check if hostname matches certificate name (including wildcards)
        """
        # Exact match
        if hostname.lower() == cert_name.lower():
            return True
        
        # Wildcard match
        if cert_name.startswith('*.'):
            # Wildcard only matches single level
            pattern = cert_name[2:]  # Remove *.
            if '.' in hostname:
                domain = hostname.split('.', 1)[1]
                return domain.lower() == pattern.lower()
        
        return False
    
    def validate_key_usage(self, certificates: List[x509.Certificate]):
        """
        Verify certificates have appropriate key usage extensions
        """
        leaf_cert = certificates[0]
        
        try:
            # Check leaf certificate key usage
            key_usage = leaf_cert.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value
            
            # For TLS server certificates
            if not key_usage.digital_signature:
                raise ValidationError(
                    "Leaf certificate missing digital_signature key usage"
                )
            
            # Check Extended Key Usage
            eku = leaf_cert.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            
            if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH not in eku:
                raise ValidationError(
                    "Leaf certificate missing serverAuth extended key usage"
                )
                
        except x509.ExtensionNotFound:
            # Key usage extensions are critical for security
            raise ValidationError(
                "Certificate missing required key usage extensions"
            )
        
        # Validate CA certificates in chain
        for cert in certificates[1:]:
            try:
                basic_constraints = cert.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
                
                if not basic_constraints.ca:
                    raise ValidationError(
                        "Intermediate certificate doesn't have CA flag"
                    )
            except x509.ExtensionNotFound:
                raise ValidationError(
                    "CA certificate missing Basic Constraints"
                )
```

### Name Constraint Violations

**Vulnerability**: Intermediate CAs can issue certificates outside their authorized scope.

**Attack**: Compromised intermediate CA issues certificates for unauthorized domains.

**Example**:
```python
# Intermediate CA constrained to *.example.com
# Issues unauthorized certificate for evil.com

class NameConstraintValidator:
    """
    Enforce name constraints from CA certificates
    """
    
    def validate_name_constraints(
        self,
        leaf_cert: x509.Certificate,
        ca_chain: List[x509.Certificate]
    ) -> bool:
        """
        Verify leaf certificate respects name constraints from CA chain
        """
        # Extract leaf certificate names
        leaf_names = self.extract_names(leaf_cert)
        
        # Check constraints from each CA in chain
        for ca_cert in ca_chain:
            try:
                constraints = ca_cert.extensions.get_extension_for_class(
                    x509.NameConstraints
                ).value
                
                # Check permitted subtrees
                if constraints.permitted_subtrees:
                    if not self.name_in_permitted_subtrees(
                        leaf_names, 
                        constraints.permitted_subtrees
                    ):
                        raise ValidationError(
                            f"Certificate names {leaf_names} not in "
                            f"permitted subtrees"
                        )
                
                # Check excluded subtrees
                if constraints.excluded_subtrees:
                    if self.name_in_excluded_subtrees(
                        leaf_names,
                        constraints.excluded_subtrees
                    ):
                        raise ValidationError(
                            f"Certificate names {leaf_names} in "
                            f"excluded subtrees"
                        )
                        
            except x509.ExtensionNotFound:
                # No name constraints in this CA
                continue
        
        return True
```

**Real-World Incident**: TURKTRUST Incident (2013)
- TURKTRUST mistakenly issued intermediate CA certificates
- Recipients used them to issue fraudulent certificates for google.com
- Detection via Certificate Transparency
- Resolution: Revocation and removal from trust stores

### Revocation Check Failures

**Vulnerability**: Applications don't properly check if certificates have been revoked.

**Attack**: Use revoked certificate that application accepts due to missing revocation check.

**Common Failures**:

**1. Not checking CRL/OCSP**:
```python
# VULNERABLE: No revocation check
def validate_without_revocation(cert: Certificate) -> bool:
    # Only validates signature and expiration
    return verify_signature(cert) and not is_expired(cert)

# Attack: Present revoked certificate
# Application accepts it because revocation not checked
```

**2. Soft-fail on OCSP errors**:
```python
# VULNERABLE: Treats OCSP errors as "not revoked"
def weak_revocation_check(cert: Certificate) -> bool:
    try:
        ocsp_response = check_ocsp(cert)
        return ocsp_response.status == 'good'
    except OCSPUnavailable:
        # BUG: Soft fail - assumes not revoked
        return True  # VULNERABLE

# Attack: Block OCSP server, revoked cert accepted
```

**Secure Implementation**:
```python
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes
import requests

class SecureRevocationChecker:
    """
    Comprehensive revocation checking
    """
    
    def __init__(self, require_ocsp: bool = True):
        self.require_ocsp = require_ocsp
        self.crl_cache = {}
    
    def check_revocation(
        self,
        cert: x509.Certificate,
        issuer: x509.Certificate
    ) -> bool:
        """
        Check certificate revocation status
        """
        # Try OCSP first (faster)
        try:
            return self.check_ocsp(cert, issuer)
        except OCSPError as e:
            if self.require_ocsp:
                # Hard fail if OCSP required
                raise ValidationError(
                    f"OCSP check failed: {e}. Certificate rejected."
                )
            # Fall back to CRL
            return self.check_crl(cert, issuer)
    
    def check_ocsp(
        self,
        cert: x509.Certificate,
        issuer: x509.Certificate,
        timeout: int = 5
    ) -> bool:
        """
        Check OCSP status
        """
        # Extract OCSP URL
        try:
            aia = cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            ).value
            
            ocsp_urls = [
                desc.access_location.value
                for desc in aia
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
            ]
            
            if not ocsp_urls:
                raise OCSPError("No OCSP URL in certificate")
            
        except x509.ExtensionNotFound:
            raise OCSPError("No AIA extension in certificate")
        
        # Build OCSP request
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA256())
        ocsp_request = builder.build()
        
        # Send OCSP request
        ocsp_url = ocsp_urls[0]
        try:
            response = requests.post(
                ocsp_url,
                data=ocsp_request.public_bytes(serialization.Encoding.DER),
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=timeout
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise OCSPError(f"OCSP request failed: {e}")
        
        # Parse OCSP response
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        
        # Verify OCSP response
        if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise OCSPError(
                f"OCSP response status: {ocsp_response.response_status}"
            )
        
        # Check certificate status
        cert_status = ocsp_response.certificate_status
        
        if cert_status == ocsp.OCSPCertStatus.REVOKED:
            revocation_reason = ocsp_response.revocation_reason
            revocation_time = ocsp_response.revocation_time
            raise CertificateRevoked(
                f"Certificate revoked at {revocation_time}. "
                f"Reason: {revocation_reason}"
            )
        elif cert_status == ocsp.OCSPCertStatus.UNKNOWN:
            raise OCSPError("OCSP responder doesn't know certificate")
        
        # Certificate is good
        return True
    
    def check_crl(
        self,
        cert: x509.Certificate,
        issuer: x509.Certificate
    ) -> bool:
        """
        Check CRL for revocation
        """
        # Extract CRL distribution points
        try:
            crl_ext = cert.extensions.get_extension_for_class(
                x509.CRLDistributionPoints
            ).value
            
            crl_urls = []
            for dist_point in crl_ext:
                if dist_point.full_name:
                    for name in dist_point.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_urls.append(name.value)
            
            if not crl_urls:
                raise CRLError("No CRL URLs in certificate")
                
        except x509.ExtensionNotFound:
            raise CRLError("No CRL distribution points extension")
        
        # Fetch and cache CRL
        crl_url = crl_urls[0]
        if crl_url in self.crl_cache:
            crl = self.crl_cache[crl_url]
        else:
            crl = self.fetch_crl(crl_url)
            self.crl_cache[crl_url] = crl
        
        # Check if certificate is revoked
        revoked_cert = crl.get_revoked_certificate_by_serial_number(
            cert.serial_number
        )
        
        if revoked_cert:
            raise CertificateRevoked(
                f"Certificate revoked at {revoked_cert.revocation_date}. "
                f"Reason: {revoked_cert.extensions.get_extension_for_class(x509.CRLReason).value}"
            )
        
        return True
    
    def fetch_crl(self, crl_url: str) -> x509.CertificateRevocationList:
        """
        Download and parse CRL
        """
        try:
            response = requests.get(crl_url, timeout=10)
            response.raise_for_status()
            
            crl = x509.load_der_x509_crl(response.content, default_backend())
            
            # Verify CRL signature (should be signed by issuer)
            # Verify CRL is not expired
            if datetime.now(timezone.utc) > crl.next_update_utc:
                raise CRLError(f"CRL expired at {crl.next_update_utc}")
            
            return crl
            
        except requests.RequestException as e:
            raise CRLError(f"Failed to fetch CRL: {e}")
```

## Protocol-Level Vulnerabilities

### SSL/TLS Protocol Attacks

**BEAST (Browser Exploit Against SSL/TLS)**:
```
Vulnerability: CBC mode cipher in TLS 1.0
Attack: Predict IV, decrypt HTTPS cookies
Mitigation: Use TLS 1.2+, prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
```

**CRIME (Compression Ratio Info-leak Made Easy)**:
```
Vulnerability: TLS compression reveals plaintext
Attack: Measure compressed size to guess secrets
Mitigation: Disable TLS compression
```

**POODLE (Padding Oracle On Downgraded Legacy Encryption)**:
```
Vulnerability: SSL 3.0 CBC padding oracle
Attack: Downgrade to SSL 3.0, decrypt via padding oracle
Mitigation: Disable SSL 3.0, use TLS 1.2+
```

**Heartbleed (CVE-2014-0160)**:
```
Vulnerability: Buffer over-read in OpenSSL heartbeat
Attack: Read server memory, potentially exposing keys
Impact: 17% of web servers vulnerable
Mitigation: Update OpenSSL, revoke/reissue certificates
```

**Secure TLS Configuration**:
```python
import ssl

def create_secure_ssl_context() -> ssl.SSLContext:
    """
    Create hardened SSL context
    """
    # Use TLS 1.2 minimum
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Disable insecure features
    context.options |= ssl.OP_NO_COMPRESSION  # Prevent CRIME
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    
    # Prefer server cipher order
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    
    # Use secure ciphers only
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS')
    
    # Enable certificate validation
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    
    # Load trusted CA certificates
    context.load_verify_locations(cafile='/path/to/ca-bundle.crt')
    
    return context
```

### Downgrade Attacks

**Attack**: Force connection to use weaker protocol version or cipher.

```python
# Attacker intercepts ClientHello
# Modifies to remove strong cipher suites
# Server selects weak cipher from remaining options

class DowngradeDetector:
    """
    Detect and prevent protocol downgrade attacks
    """
    
    def validate_tls_handshake(
        self,
        client_hello: bytes,
        server_hello: bytes
    ) -> bool:
        """
        Verify server didn't downgrade connection
        """
        # Parse handshake messages
        client_versions = self.parse_supported_versions(client_hello)
        negotiated_version = self.parse_negotiated_version(server_hello)
        
        # Verify negotiated version is highest mutually supported
        if negotiated_version < max(client_versions):
            raise DowngradeError(
                f"Potential downgrade attack: "
                f"Negotiated {negotiated_version} but client supports "
                f"{max(client_versions)}"
            )
        
        # Check for downgrade protection signals (RFC 8446)
        server_random = self.parse_server_random(server_hello)
        
        if negotiated_version < TLSVersion.TLS_1_3:
            # TLS 1.2 should include downgrade protection
            downgrade_signal = server_random[-8:]
            
            expected_signals = [
                b"DOWNGRD\x01",  # TLS 1.2 downgrade from 1.3
                b"DOWNGRD\x00",  # TLS 1.1 or below downgrade
            ]
            
            if any(signal in downgrade_signal for signal in expected_signals):
                # Server signaling downgrade - could be attack
                if self.client_supports_tls_1_3():
                    raise DowngradeError(
                        "Server signaled downgrade from TLS 1.3"
                    )
        
        return True
```

**Mitigation - SCSV (Signaling Cipher Suite Value)**:
```python
# Client includes TLS_FALLBACK_SCSV in cipher suite list
# Server detects if client supports higher version than negotiated
# Server aborts if downgrade detected

TLS_FALLBACK_SCSV = 0x5600

def server_check_scsv(client_hello: ClientHello) -> bool:
    """
    Server-side downgrade detection
    """
    if TLS_FALLBACK_SCSV in client_hello.cipher_suites:
        # Client is using fallback mechanism
        if client_hello.version < server_max_supported_version:
            # Inappropriate fallback - abort
            raise DowngradeError("Inappropriate fallback detected")
    
    return True
```

## Implementation Vulnerabilities

### Improper Certificate Storage

**Vulnerability**: Certificates and private keys stored insecurely.

**Common Mistakes**:

```python
# VULNERABLE: Hardcoded in source code
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
-----END PRIVATE KEY-----"""

# VULNERABLE: World-readable file permissions
# -rw-r--r-- 1 root root 1704 private.key

# VULNERABLE: Stored in version control
git add certificates/private-key.pem
git commit -m "Add certificate"
git push  # Now in Git history forever

# VULNERABLE: Logged in plaintext
logger.info(f"Using private key: {private_key_pem}")
```

**Secure Storage**:
```python
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class SecureCertificateStorage:
    """
    Secure certificate and key storage practices
    """
    
    def store_private_key(
        self,
        private_key: rsa.RSAPrivateKey,
        path: Path,
        password: bytes
    ):
        """
        Store private key with encryption and proper permissions
        """
        # Encrypt private key
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        
        # Create file with restrictive permissions (owner only)
        os.umask(0o077)  # Remove all group/other permissions
        with open(path, 'wb') as f:
            f.write(pem)
        
        # Verify permissions
        stat_info = path.stat()
        if stat_info.st_mode & 0o077:  # Group or other can access
            raise SecurityError(
                f"Insecure permissions on {path}: {oct(stat_info.st_mode)}"
            )
        
        # Set immutable flag (Linux)
        try:
            os.system(f'chattr +i {path}')
        except:
            pass  # Not all filesystems support
    
    def load_private_key(self, path: Path, password: bytes) -> rsa.RSAPrivateKey:
        """
        Load encrypted private key
        """
        # Verify file permissions before reading
        stat_info = path.stat()
        if stat_info.st_mode & 0o077:
            raise SecurityError(
                f"Insecure permissions on {path}. "
                f"Expected 0600, got {oct(stat_info.st_mode)}"
            )
        
        with open(path, 'rb') as f:
            pem = f.read()
        
        return serialization.load_pem_private_key(
            pem,
            password=password,
            backend=default_backend()
        )
    
    def use_hsm_for_keys(self, key_label: str):
        """
        Store keys in Hardware Security Module (recommended)
        """
        # HSM keeps private keys in tamper-resistant hardware
        # Keys never leave HSM - only sign/decrypt operations performed
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends.pkcs11 import PKCS11Backend
        
        # Connect to HSM
        backend = PKCS11Backend('/usr/lib/libpkcs11.so')
        
        # Access key by label (never extract private key)
        key = backend.get_private_key(key_label)
        
        # Perform operations on HSM
        signature = key.sign(data, hashes.SHA256())
        
        return signature
```

### Insufficient Random Generation

**Vulnerability**: Weak randomness in nonces, IVs, or key generation.

**Attack**: Predict random values, break cryptography.

**Secure Random Generation**:
```python
import secrets
import os

class SecureRandomGenerator:
    """
    Generate cryptographically secure random values
    """
    
    def generate_nonce(self, length: int = 16) -> bytes:
        """
        Generate random nonce for cryptographic use
        """
        # Use secrets module (CSPRNG)
        return secrets.token_bytes(length)
    
    def generate_session_id(self) -> str:
        """
        Generate unguessable session identifier
        """
        # 32 bytes = 256 bits of entropy
        return secrets.token_urlsafe(32)
    
    def verify_entropy_source(self):
        """
        Verify system has sufficient entropy
        """
        # Check available entropy (Linux)
        try:
            with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
                entropy = int(f.read().strip())
                
            if entropy < 128:
                raise SecurityError(
                    f"Insufficient system entropy: {entropy} bits"
                )
        except FileNotFoundError:
            pass  # Not Linux
    
    @staticmethod
    def bad_random_examples():
        """
        Examples of INSECURE random generation (DO NOT USE)
        """
        import random
        import time
        
        # VULNERABLE: Predictable seed
        random.seed(int(time.time()))
        weak_random = random.randint(0, 1000000)
        
        # VULNERABLE: Not cryptographically secure
        weak_bytes = bytes(random.randint(0, 255) for _ in range(16))
        
        # VULNERABLE: Using timestamp
        weak_nonce = int(time.time()).to_bytes(8, 'big')
        
        return "These are all INSECURE - DO NOT USE"
```

## Supply Chain Vulnerabilities

### Compromised Certificate Authorities

**Incident Examples**:

**DigiNotar (2011)**:
- Dutch CA compromised by attackers
- Issued fraudulent certificates for google.com, gmail.com, etc.
- Used for surveillance in Iran
- Impact: CA removed from all trust stores, company bankrupt

**CNNIC (2015)**:
- Chinese CA issued unauthorized intermediate CA certificate
- Used to intercept HTTPS traffic
- Impact: CNNIC removed from trust stores

**Symantec (2017)**:
- Improper issuance of 30,000+ certificates
- Failed to follow industry standards
- Impact: All Symantec certificates distrusted by browsers

**Detection and Response**:
```python
from datetime import datetime, timedelta

class CACompromiseDetector:
    """
    Detect and respond to CA compromise
    """
    
    def monitor_ct_logs(self, your_domains: List[str]):
        """
        Monitor Certificate Transparency logs for unauthorized issuance
        """
        import requests
        
        for domain in your_domains:
            # Query CT logs
            response = requests.get(
                f'https://crt.sh/?q=%.{domain}&output=json'
            )
            
            certificates = response.json()
            
            # Check for unexpected issuers
            for cert in certificates:
                if not self.is_authorized_issuer(cert['issuer_name']):
                    self.alert_unauthorized_cert(
                        domain=domain,
                        issuer=cert['issuer_name'],
                        issued_at=cert['not_before'],
                        serial=cert['serial_number']
                    )
    
    def is_authorized_issuer(self, issuer: str) -> bool:
        """
        Check if CA is authorized to issue certs for your domains
        """
        authorized_cas = [
            'Let\'s Encrypt',
            'DigiCert',
            'Your Internal CA',
        ]
        
        return any(ca in issuer for ca in authorized_cas)
    
    def alert_unauthorized_cert(self, **details):
        """
        Alert on unauthorized certificate issuance
        """
        alert = {
            'severity': 'critical',
            'title': 'Unauthorized Certificate Detected',
            'details': details,
            'actions': [
                '1. Verify certificate legitimacy',
                '2. If fraudulent, report to CA',
                '3. Request revocation',
                '4. Notify browser vendors',
                '5. Implement certificate pinning',
            ]
        }
        
        self.send_alert(alert)
```

### Malicious Dependencies

**Vulnerability**: Compromised PKI libraries or dependencies.

**Event Stream Incident (2018)**:
- Popular npm package compromised
- Injected code to steal cryptocurrency wallets
- Affected thousands of applications

**Protection**:
```python
import hashlib
import json

class DependencyVerification:
    """
    Verify integrity of PKI dependencies
    """
    
    def verify_package(self, package_name: str, version: str) -> bool:
        """
        Verify package hasn't been tampered with
        """
        # Check package hash against known good values
        known_hashes = self.load_known_hashes()
        
        package_id = f"{package_name}=={version}"
        if package_id not in known_hashes:
            raise SecurityError(
                f"Unknown package version: {package_id}"
            )
        
        # Download and hash package
        package_data = self.download_package(package_name, version)
        actual_hash = hashlib.sha256(package_data).hexdigest()
        
        expected_hash = known_hashes[package_id]
        
        if actual_hash != expected_hash:
            raise SecurityError(
                f"Package hash mismatch for {package_id}. "
                f"Expected: {expected_hash}, Got: {actual_hash}. "
                f"Package may be compromised!"
            )
        
        return True
    
    def audit_dependencies(self):
        """
        Audit all cryptography-related dependencies
        """
        import pkg_resources
        
        crypto_packages = [
            'cryptography',
            'pyopenssl',
            'certifi',
            'urllib3',
            'requests',
        ]
        
        for package in crypto_packages:
            try:
                dist = pkg_resources.get_distribution(package)
                version = dist.version
                
                # Check for known vulnerabilities
                if self.has_known_vulnerabilities(package, version):
                    raise SecurityError(
                        f"{package} {version} has known vulnerabilities. "
                        f"Update immediately!"
                    )
                
                # Verify integrity
                self.verify_package(package, version)
                
            except pkg_resources.DistributionNotFound:
                continue
```

## Operational Vulnerabilities

### Certificate Expiration

**Impact**: Service outages when certificates expire unexpectedly.

**Famous Incidents**:
- Microsoft Teams (2020): Global outage due to expired certificate
- Spotify (2020): Outage from expired cert
- Ericsson (2018): Mobile network outage affecting millions

**Prevention**:
```python
from datetime import datetime, timedelta
from typing import List, Dict

class CertificateExpirationMonitor:
    """
    Monitor and alert on approaching certificate expiration
    """
    
    def __init__(self, warning_days: List[int] = [90, 60, 30, 14, 7, 3, 1]):
        self.warning_days = warning_days
    
    def check_expiration(self, cert: x509.Certificate) -> Dict:
        """
        Check certificate expiration and return status
        """
        now = datetime.now(timezone.utc)
        expires = cert.not_valid_after_utc
        days_until_expiry = (expires - now).days
        
        status = {
            'expires_at': expires,
            'days_remaining': days_until_expiry,
            'status': 'unknown',
            'action_required': False,
        }
        
        if days_until_expiry < 0:
            status['status'] = 'expired'
            status['action_required'] = True
            status['severity'] = 'critical'
        elif days_until_expiry in self.warning_days:
            status['status'] = 'expiring_soon'
            status['action_required'] = True
            status['severity'] = self.get_severity(days_until_expiry)
        else:
            status['status'] = 'valid'
        
        return status
    
    def get_severity(self, days_remaining: int) -> str:
        """
        Determine alert severity based on days remaining
        """
        if days_remaining <= 1:
            return 'critical'
        elif days_remaining <= 7:
            return 'high'
        elif days_remaining <= 30:
            return 'medium'
        else:
            return 'low'
    
    def automated_renewal(self, cert: x509.Certificate, threshold_days: int = 30):
        """
        Automatically renew certificates approaching expiration
        """
        status = self.check_expiration(cert)
        
        if status['days_remaining'] <= threshold_days:
            # Trigger automated renewal
            self.initiate_renewal(cert)
```

### Insufficient Monitoring

**Problem**: No visibility into certificate inventory and health.

**Solution**:
```python
class ComprehensiveMonitoring:
    """
    Monitor all aspects of certificate infrastructure
    """
    
    def collect_metrics(self) -> Dict:
        """
        Collect comprehensive certificate metrics
        """
        return {
            'inventory': {
                'total_certificates': self.count_all_certificates(),
                'by_environment': self.certificates_by_environment(),
                'by_issuer': self.certificates_by_issuer(),
            },
            'expiration': {
                'expiring_90_days': self.count_expiring_within(90),
                'expiring_30_days': self.count_expiring_within(30),
                'expiring_7_days': self.count_expiring_within(7),
                'expired': self.count_expired(),
            },
            'security': {
                'weak_keys': self.count_weak_keys(),
                'deprecated_algorithms': self.count_deprecated_algorithms(),
                'revoked_certificates': self.count_revoked(),
                'pinning_failures': self.count_pinning_failures(),
            },
            'operations': {
                'renewal_success_rate': self.calculate_renewal_success_rate(),
                'average_lifetime': self.calculate_average_lifetime(),
                'deployment_failures': self.count_deployment_failures(),
            },
        }
```

## Defense in Depth Strategies

### Layered Security Controls

```python
class DefenseInDepth:
    """
    Implement multiple layers of security
    """
    
    def validate_with_multiple_layers(
        self,
        cert_chain: List[bytes],
        hostname: str
    ) -> bool:
        """
        Apply multiple validation layers
        """
        # Layer 1: Standard PKI validation
        self.standard_validation(cert_chain, hostname)
        
        # Layer 2: Certificate pinning
        self.verify_pins(cert_chain)
        
        # Layer 3: Certificate Transparency verification
        self.verify_ct_logs(cert_chain)
        
        # Layer 4: Revocation checking (hard fail)
        self.check_revocation(cert_chain)
        
        # Layer 5: Additional security checks
        self.advanced_security_checks(cert_chain)
        
        return True
    
    def advanced_security_checks(self, cert_chain: List[x509.Certificate]):
        """
        Additional security validations
        """
        leaf_cert = cert_chain[0]
        
        # Check key strength
        public_key = leaf_cert.public_key()
        if public_key.key_size < 2048:
            raise SecurityError("Weak key size")
        
        # Check for deprecated algorithms
        if 'sha1' in leaf_cert.signature_algorithm_oid._name.lower():
            raise SecurityError("Deprecated signature algorithm: SHA-1")
        
        # Verify certificate is in CT logs
        try:
            sct_ext = leaf_cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
            )
            # Has SCT extension - good
        except x509.ExtensionNotFound:
            # No CT - suspicious
            raise SecurityError("Certificate not in CT logs")
        
        # Check certificate lifetime
        lifetime = (leaf_cert.not_valid_after_utc - 
                   leaf_cert.not_valid_before_utc).days
        if lifetime > 397:  # Max allowed by CA/Browser Forum
            raise SecurityError(f"Certificate lifetime too long: {lifetime} days")
```

## Further Reading

### Standards and RFCs
- RFC 5280: X.509 Certificatesand CRLs
- RFC 6960: OCSP
- RFC 8659: CAA Records
- CA/Browser Forum Baseline Requirements

### Security Resources
- OWASP Certificate and Public Key Pinning Guide
- CWE-295: Improper Certificate Validation
- Common Weakness Enumeration (CWE) PKI entries

### Research Papers
- "The Most Dangerous Code in the World" (2012)
- "Analysis of SSL Certificate Reissues" (2016)
- "Measuring and Analyzing the SSL Certificate Ecosystem" (2017)

---

**See Also**: [[Certificate Pinning]], [[Private Key Protection]], [[TLS Protocol]], [[Trust Models]]
