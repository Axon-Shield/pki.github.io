# Common Misconfigurations

## TL;DR

Certificate management failures rarely stem from complex technical issues - most outages result from straightforward misconfigurations that slip past review. This page documents the most frequent mistakes found across thousands of PKI deployments, from incorrect file permissions to wrong CN/SAN configurations, providing detection and remediation strategies for each.

**Key insight**: 80% of certificate incidents trace back to the same 20 misconfigurations.

## Overview

PKI misconfigurations persist because:
1. Certificate configuration is done infrequently (creating false confidence)
2. Testing environments don't catch production-specific issues
3. Configuration errors fail silently until certificates expire or clients reject connections
4. Documentation becomes outdated faster than certificates rotate

This page catalogs the most common mistakes, how to detect them, and how to fix them properly.

## The Top 20 Misconfigurations

### 1. Wrong Subject Alternative Name (SAN)

**The Mistake**:
```yaml
# WRONG: Using CN instead of SAN for hostname
subject:
  commonName: api.example.com  # Deprecated for hostname validation
subjectAltName: []  # Empty!

# Clients connecting to api.example.com will reject this certificate
```

**Why It Happens**:
- Confusion between CN (legacy) and SAN (modern standard)
- Certificate tools defaulting to CN-only certificates
- Copying old configurations from pre-2017 era

**Detection**:
```bash
# Check if SAN is present
openssl x509 -in server.crt -text -noout | grep -A1 "Subject Alternative Name"

# Should show:
#   X509v3 Subject Alternative Name:
#       DNS:api.example.com, DNS:www.api.example.com
```

**The Fix**:
```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

def create_csr_with_san(
    common_name: str,
    san_list: List[str]
) -> x509.CertificateSigningRequest:
    """
    Create CSR with proper SAN configuration
    """
    csr = x509.CertificateSigningRequestBuilder()
    
    # Set CN (still required in subject)
    csr = csr.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    
    # Add SAN extension (CRITICAL for hostname validation)
    san_extension = x509.SubjectAlternativeName([
        x509.DNSName(name) for name in san_list
    ])
    csr = csr.add_extension(san_extension, critical=False)
    
    # Sign CSR
    return csr.sign(private_key, hashes.SHA256())

# Correct usage:
csr = create_csr_with_san(
    common_name="api.example.com",
    san_list=[
        "api.example.com",
        "www.api.example.com",
        "api-staging.example.com"
    ]
)
```

**Validation**:
```bash
# Verify SAN matches your hostnames
openssl x509 -in server.crt -text -noout | grep -A1 "Subject Alternative Name"

# Test TLS connection
openssl s_client -connect api.example.com:443 -servername api.example.com
# Should show "Verify return code: 0 (ok)"
```

### 2. Incorrect File Permissions

**The Mistake**:
```bash
# WRONG: World-readable private key
-rw-r--r-- 1 root root  1675 Nov  9 10:00 server.key

# Any user on system can read private key!
```

**Why It Happens**:
- Copy/paste from examples without thinking about security
- Automated deployment tools with wrong umask
- Lack of post-deployment validation

**Detection**:
```bash
# Find private keys with wrong permissions
find /etc/ssl -name "*.key" -type f ! -perm 0600

# Check current permissions
ls -la /etc/ssl/private/server.key
```

**The Fix**:
```bash
# Correct permissions for private keys
chmod 600 /etc/ssl/private/server.key
chown root:root /etc/ssl/private/server.key

# Correct permissions for certificates (can be world-readable)
chmod 644 /etc/ssl/certs/server.crt
chown root:root /etc/ssl/certs/server.crt

# Set directory permissions
chmod 700 /etc/ssl/private/
chmod 755 /etc/ssl/certs/
```

**Automated Enforcement**:
```python
import os
import stat
from pathlib import Path

def enforce_certificate_permissions(cert_dir: Path, key_dir: Path):
    """
    Audit and fix certificate file permissions
    """
    issues_found = []
    
    # Check private keys
    for key_file in key_dir.glob("*.key"):
        st = key_file.stat()
        mode = st.st_mode
        
        # Private keys must be 0600 (read/write for owner only)
        if stat.S_IMODE(mode) != 0o600:
            issues_found.append({
                'file': str(key_file),
                'current': oct(stat.S_IMODE(mode)),
                'expected': '0o600',
                'severity': 'critical'
            })
            
            # Fix automatically
            key_file.chmod(0o600)
            print(f"Fixed permissions on {key_file}")
        
        # Check ownership
        if st.st_uid != 0 or st.st_gid != 0:
            issues_found.append({
                'file': str(key_file),
                'issue': 'Not owned by root',
                'severity': 'high'
            })
    
    # Check certificates (should be 0644)
    for cert_file in cert_dir.glob("*.crt"):
        st = cert_file.stat()
        mode = st.st_mode
        
        if stat.S_IMODE(mode) & 0o077 != 0o044:
            issues_found.append({
                'file': str(cert_file),
                'current': oct(stat.S_IMODE(mode)),
                'expected': '0o644',
                'severity': 'low'
            })
            
            cert_file.chmod(0o644)
    
    return issues_found
```

### 3. Hostname Mismatch

**The Mistake**:
```
Certificate issued for: prod-api-01.internal.example.com
Server accessed as:     api.example.com

Result: Certificate validation fails
```

**Why It Happens**:
- Using internal hostnames in certificates
- Not understanding load balancer DNS mapping
- Certificates issued before DNS configuration finalized

**Detection**:
```bash
# Check what hostname is in certificate
openssl x509 -in /etc/ssl/certs/server.crt -text -noout | grep -E "(Subject:|Subject Alternative Name)" -A1

# Compare with actual hostname
hostname
hostname -f

# Test from client perspective
curl -vI https://api.example.com 2>&1 | grep "certificate"
```

**The Fix**:

Option 1: Update certificate with correct hostnames
```python
def generate_csr_with_all_hostnames(service_name: str) -> str:
    """
    Generate CSR with all possible hostnames
    """
    hostnames = [
        f"{service_name}.example.com",              # Public DNS
        f"www.{service_name}.example.com",           # www subdomain
        f"{service_name}.internal.example.com",     # Internal DNS
        f"{service_name}-lb.example.com",           # Load balancer
    ]
    
    # Add IP SANs if needed for direct IP access
    ip_addresses = [
        "192.168.1.100",  # Internal IP
    ]
    
    san_entries = (
        [x509.DNSName(hostname) for hostname in hostnames] +
        [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses]
    )
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0]),
        ])
    ).add_extension(
        x509.SubjectAlternativeName(san_entries),
        critical=False
    ).sign(private_key, hashes.SHA256())
    
    return csr.public_bytes(serialization.Encoding.PEM).decode()
```

Option 2: Configure hostname resolution correctly
```nginx
# NGINX - Match certificate hostname
server {
    listen 443 ssl;
    server_name api.example.com www.api.example.com;  # Match SAN entries
    
    ssl_certificate /etc/ssl/certs/api.example.com.crt;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
}
```

### 4. Expired Intermediate Certificates

**The Mistake**:
```
Server certificate: Valid until 2026-11-09  ✓
Intermediate cert:  Valid until 2023-05-15  ✗ EXPIRED
Root certificate:   Valid until 2035-01-01  ✓

Result: Chain validation fails despite leaf certificate being valid
```

**Why It Happens**:
- Intermediate certificates have shorter validity than roots
- Automated renewal focuses on leaf certificates only
- Intermediate certificate updates require manual intervention

**Detection**:
```bash
# Check all certificates in chain
openssl s_client -connect api.example.com:443 -showcerts | \
  awk '/BEGIN CERT/,/END CERT/' | \
  awk 'BEGIN {cert=0} /BEGIN CERT/ {cert++} {print > "cert" cert ".pem"}'

# Check expiry of each certificate
for cert in cert*.pem; do
    echo "=== $cert ==="
    openssl x509 -in "$cert" -noout -subject -dates
    echo
done
```

**The Fix**:
```python
def validate_certificate_chain_expiry(
    cert_chain_path: str,
    warn_days: int = 90
) -> List[ExpiryWarning]:
    """
    Check all certificates in chain for upcoming expiry
    """
    warnings = []
    certs = load_certificate_chain(cert_chain_path)
    now = datetime.now(timezone.utc)
    
    for i, cert in enumerate(certs):
        days_until_expiry = (cert.not_valid_after_utc - now).days
        
        cert_type = "Root" if i == len(certs) - 1 else "Intermediate" if i > 0 else "Leaf"
        
        if cert.not_valid_after_utc < now:
            warnings.append(ExpiryWarning(
                position=i,
                cert_type=cert_type,
                subject=cert.subject.rfc4514_string(),
                expiry_date=cert.not_valid_after_utc,
                status="EXPIRED",
                severity="critical"
            ))
        elif days_until_expiry < warn_days:
            warnings.append(ExpiryWarning(
                position=i,
                cert_type=cert_type,
                subject=cert.subject.rfc4514_string(),
                expiry_date=cert.not_valid_after_utc,
                days_remaining=days_until_expiry,
                status="WARNING",
                severity="high" if days_until_expiry < 30 else "medium"
            ))
    
    return warnings

# Automated monitoring
def monitor_chain_expiry():
    """Monitor all certificate chains"""
    for cert_path in find_all_certificate_chains():
        warnings = validate_certificate_chain_expiry(cert_path)
        
        for warning in warnings:
            if warning.severity == "critical":
                alert_pagerduty(warning)
            elif warning.severity == "high":
                alert_email(warning)
```

### 5. Wrong Key Usage Extensions

**The Mistake**:
```
Certificate with keyUsage: digitalSignature, keyEncipherment
Used for: TLS server authentication

Should have: digitalSignature, keyEncipherment, serverAuth
```

**Why It Happens**:
- Wrong certificate profile selected during issuance
- Copy/paste from incompatible certificate example
- CA configuration error

**Detection**:
```bash
# Check key usage
openssl x509 -in server.crt -text -noout | grep -A3 "Key Usage"

# Should show for TLS server cert:
# X509v3 Key Usage: critical
#     Digital Signature, Key Encipherment
# X509v3 Extended Key Usage:
#     TLS Web Server Authentication
```

**The Fix**:
```python
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

def create_tls_server_certificate(
    csr: x509.CertificateSigningRequest,
    issuer_cert: x509.Certificate,
    issuer_key
) -> x509.Certificate:
    """
    Issue certificate with correct key usage for TLS server
    """
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        # Add Key Usage
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        # Add Extended Key Usage for TLS server
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False
        )
        .sign(issuer_key, hashes.SHA256())
    )
    
    return cert
```

### 6. Mixed Certificate Chains

**The Mistake**:
```
fullchain.pem contains:
1. Server certificate for api.example.com  ← Correct
2. Intermediate CA for DigiCert           ← WRONG CA!
3. Root CA for Let's Encrypt              ← WRONG CA!

These certificates aren't related!
```

**Why It Happens**:
- Copy/paste from different certificate deployments
- Automated scripts concatenating wrong files
- Lack of validation during deployment

**Detection**:
```python
def validate_certificate_chain_relationships(
    chain_path: str
) -> ValidationResult:
    """
    Verify each certificate is issued by the next in chain
    """
    certs = load_certificate_chain(chain_path)
    errors = []
    
    for i in range(len(certs) - 1):
        current_cert = certs[i]
        issuer_cert = certs[i + 1]
        
        # Check issuer DN matches
        if current_cert.issuer != issuer_cert.subject:
            errors.append(
                f"Certificate {i} claims issuer '{current_cert.issuer}' "
                f"but next cert has subject '{issuer_cert.subject}'"
            )
        
        # Verify signature
        try:
            issuer_cert.public_key().verify(
                current_cert.signature,
                current_cert.tbs_certificate_bytes,
                current_cert.signature_hash_algorithm
            )
        except Exception as e:
            errors.append(
                f"Certificate {i} signature verification failed: {str(e)}"
            )
    
    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors
    )
```

### 7. Reused Private Keys Across Environments

**The Mistake**:
```bash
# Production server
server.key: abc123...  (RSA 2048)

# Staging server
server.key: abc123...  (SAME KEY!)

# Development server
server.key: abc123...  (SAME KEY!)

If any environment compromised, all environments compromised!
```

**Why It Happens**:
- Copying production configs to other environments
- Lack of key rotation procedures
- "It works, don't change it" mentality

**Detection**:
```bash
# Compare key fingerprints across environments
for host in prod-api staging-api dev-api; do
    echo "=== $host ==="
    ssh $host "openssl rsa -in /etc/ssl/private/server.key -modulus -noout | openssl md5"
done

# Should show DIFFERENT hashes for each environment!
```

**The Fix**:
```python
def generate_environment_specific_keys(
    environments: List[str],
    service_name: str
) -> Dict[str, Tuple[bytes, bytes]]:
    """
    Generate unique keypairs for each environment
    """
    keypairs = {}
    
    for env in environments:
        # Generate unique keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Serialize
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        keypairs[env] = (private_pem, public_pem)
        
        print(f"Generated unique keypair for {service_name}-{env}")
    
    return keypairs

# Usage
keypairs = generate_environment_specific_keys(
    environments=['production', 'staging', 'development'],
    service_name='api'
)
```

### 8. Certificate and Key Mismatch

**The Mistake**:
```bash
# Deployed certificate is for api-old.example.com
# But private key is for api-new.example.com
# Public key in cert doesn't match private key

Result: TLS handshake fails with cryptographic error
```

**Why It Happens**:
- Renewed certificate but kept old private key
- Copied files from different systems
- Deployment script error

**Detection**:
```bash
# Check if certificate and key match
cert_modulus=$(openssl x509 -noout -modulus -in server.crt | openssl md5)
key_modulus=$(openssl rsa -noout -modulus -in server.key | openssl md5)

if [ "$cert_modulus" = "$key_modulus" ]; then
    echo "✓ Certificate and key match"
else
    echo "✗ Certificate and key DO NOT match!"
    exit 1
fi
```

**Automated Validation**:
```python
from cryptography.hazmat.primitives import serialization

def verify_certificate_key_pair(
    cert_path: str,
    key_path: str
) -> bool:
    """
    Verify certificate and private key are a matching pair
    """
    # Load certificate
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    
    # Load private key
    with open(key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    # Extract public keys
    cert_public_key = cert.public_key()
    private_public_key = private_key.public_key()
    
    # Compare public key from certificate vs public key from private key
    cert_public_bytes = cert_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_public_bytes = private_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return cert_public_bytes == private_public_bytes

# Pre-deployment validation
if not verify_certificate_key_pair('server.crt', 'server.key'):
    raise ValueError("Certificate and key don't match - aborting deployment!")
```

### 9. Weak Cryptographic Parameters

**The Mistake**:
```python
# WRONG: Using weak/deprecated algorithms
certificate:
    signature_algorithm: sha1WithRSAEncryption  # SHA-1 deprecated!
    key_size: 1024  # Too small!
    
tls_config:
    protocols: [TLSv1.0, TLSv1.1]  # Deprecated protocols!
    cipher_suites: [DES-CBC3-SHA]  # Weak cipher!
```

**Why It Happens**:
- Old configuration files copied forward
- Lack of security policy enforcement
- Compatibility concerns with legacy clients

**Detection**:
```bash
# Check certificate signature algorithm
openssl x509 -in server.crt -text -noout | grep "Signature Algorithm"

# Should show: sha256WithRSAEncryption or better
# NOT: sha1WithRSAEncryption, md5WithRSAEncryption

# Check key size
openssl x509 -in server.crt -text -noout | grep "Public-Key"

# Should show: (2048 bit) or (4096 bit) or (256 bit) for ECDSA
# NOT: (1024 bit) or smaller

# Test TLS configuration
nmap --script ssl-enum-ciphers -p 443 api.example.com
```

**The Fix**:
```python
# Enforce modern cryptographic standards
MINIMUM_KEY_SIZE_RSA = 2048
MINIMUM_KEY_SIZE_ECDSA = 256
ALLOWED_SIGNATURE_ALGORITHMS = [
    'sha256WithRSAEncryption',
    'sha384WithRSAEncryption',
    'sha512WithRSAEncryption',
    'ecdsa-with-SHA256',
    'ecdsa-with-SHA384',
]

def validate_certificate_cryptography(cert: x509.Certificate) -> List[str]:
    """
    Validate certificate uses acceptable cryptography
    """
    issues = []
    
    # Check signature algorithm
    sig_alg = cert.signature_algorithm_oid._name
    if sig_alg not in ALLOWED_SIGNATURE_ALGORITHMS:
        issues.append(
            f"Weak signature algorithm: {sig_alg}. "
            f"Use SHA-256 or stronger."
        )
    
    # Check key size
    public_key = cert.public_key()
    
    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        if key_size < MINIMUM_KEY_SIZE_RSA:
            issues.append(
                f"RSA key too small: {key_size} bits. "
                f"Minimum: {MINIMUM_KEY_SIZE_RSA} bits."
            )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_size = public_key.curve.key_size
        if key_size < MINIMUM_KEY_SIZE_ECDSA:
            issues.append(
                f"ECDSA key too small: {key_size} bits. "
                f"Minimum: {MINIMUM_KEY_SIZE_ECDSA} bits."
            )
    
    return issues
```

**Secure TLS Configuration**:
```nginx
# NGINX - Modern TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;  # Only modern protocols
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;

# Disable weak ciphers
ssl_ciphers '!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
```

### 10. Missing OCSP Stapling

**The Mistake**:
```nginx
# Basic TLS configuration - missing OCSP stapling
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    
    # Missing OCSP stapling configuration!
}

# Result: Each client makes separate OCSP request to CA
# Slow handshakes, privacy leak, CA overload
```

**Why It Happens**:
- Lack of awareness of OCSP stapling
- Default configurations don't enable it
- Complexity of configuration

**The Fix**:
```nginx
# Enable OCSP stapling
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/privkey.pem;
    
    # Enable OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Trusted certificate chain for OCSP validation
    ssl_trusted_certificate /etc/ssl/certs/chain.pem;
    
    # Resolver for OCSP requests
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
}
```

**Verification**:
```bash
# Test OCSP stapling
openssl s_client -connect api.example.com:443 -status -tlsextdebug < /dev/null 2>&1 | grep -A 17 "OCSP response"

# Should show:
# OCSP Response Status: successful (0x0)
# Response Type: Basic OCSP Response
# ...
```

### 11-20: Quick Reference

| # | Misconfiguration | Impact | Quick Fix |
|---|------------------|--------|-----------|
| 11 | Missing Certificate Chain File | Chain validation fails | Include intermediate certs in config |
| 12 | HTTP on Port 443 | TLS handshake fails | Configure SSL/TLS properly |
| 13 | Certificate in Wrong Format | Parsing errors | Convert: `openssl x509 -inform DER -outform PEM` |
| 14 | Using Expired Trust Store | Valid certs rejected | Update CA bundle |
| 15 | SNI Not Configured | First vhost served to all | Configure server_name properly |
| 16 | Certificate for Wrong Port | Hostname validation fails | Issue cert with IP SAN if needed |
| 17 | Private Key Encrypted but No Passphrase | Service won't start | Remove encryption or configure passphrase |
| 18 | Wildcard Certificate Misuse | Subdomain validation fails | Wildcard matches one level only |
| 19 | Cross-Signed Chain Confusion | Some clients fail | Provide complete chain for each path |
| 20 | Certificate Pinning Deployed Without Backup | Update locks out users | Always pin 2+ keys |

## Configuration Validation Checklist

### Pre-Deployment Checklist

```python
class CertificateConfigurationValidator:
    """
    Comprehensive pre-deployment validation
    """
    
    def validate_all(
        self,
        cert_path: str,
        key_path: str,
        chain_path: Optional[str] = None
    ) -> ValidationReport:
        """Run all validation checks"""
        
        report = ValidationReport()
        
        # 1. File existence
        report.add_check(
            "Files exist",
            self.check_files_exist(cert_path, key_path, chain_path)
        )
        
        # 2. File permissions
        report.add_check(
            "Permissions correct",
            self.check_file_permissions(cert_path, key_path)
        )
        
        # 3. Certificate validity
        report.add_check(
            "Certificate valid",
            self.check_certificate_validity(cert_path)
        )
        
        # 4. Key match
        report.add_check(
            "Certificate and key match",
            verify_certificate_key_pair(cert_path, key_path)
        )
        
        # 5. SAN present
        report.add_check(
            "SAN configured",
            self.check_san_present(cert_path)
        )
        
        # 6. Chain complete
        if chain_path:
            report.add_check(
                "Chain complete",
                self.check_chain_complete(chain_path)
            )
        
        # 7. Cryptography strength
        report.add_check(
            "Strong cryptography",
            self.check_cryptographic_strength(cert_path)
        )
        
        # 8. Key usage correct
        report.add_check(
            "Key usage appropriate",
            self.check_key_usage(cert_path)
        )
        
        # 9. No known vulnerabilities
        report.add_check(
            "No known issues",
            self.check_vulnerability_database(cert_path)
        )
        
        return report
```

### Continuous Monitoring

```yaml
# Prometheus alert rules for misconfigurations
groups:
  - name: certificate_misconfigurations
    interval: 5m
    rules:
      # Expiring certificates
      - alert: CertificateExpiringSoon
        expr: certificate_expiry_seconds < 604800  # 7 days
        labels:
          severity: critical
        annotations:
          summary: "Certificate expiring in < 7 days"
      
      # Weak cryptography
      - alert: WeakCryptography
        expr: certificate_key_size_bits < 2048
        labels:
          severity: high
        annotations:
          summary: "Certificate using weak key size"
      
      # Chain validation failures
      - alert: ChainValidationFailing
        expr: rate(certificate_chain_validation_errors[5m]) > 0
        labels:
          severity: high
        annotations:
          summary: "Certificate chain validation failing"
      
      # Missing OCSP stapling
      - alert: OCSPStaplingDisabled
        expr: ocsp_stapling_enabled == 0
        labels:
          severity: medium
        annotations:
          summary: "OCSP stapling not enabled"
```

## Configuration Templates

### NGINX - Production-Ready TLS

```nginx
# /etc/nginx/sites-available/api.example.com
server {
    listen 80;
    server_name api.example.com www.api.example.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.example.com www.api.example.com;
    
    # Certificate configuration
    ssl_certificate /etc/ssl/certs/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/api.example.com/privkey.pem;
    ssl_trusted_certificate /etc/ssl/certs/api.example.com/chain.pem;
    
    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    
    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Session configuration
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # Application configuration
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Apache - Production-Ready TLS

```apache
# /etc/apache2/sites-available/api.example.com.conf
<VirtualHost *:80>
    ServerName api.example.com
    ServerAlias www.api.example.com
    
    # Redirect to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName api.example.com
    ServerAlias www.api.example.com
    
    # Certificate configuration
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/api.example.com/cert.pem
    SSLCertificateKeyFile /etc/ssl/private/api.example.com/privkey.pem
    SSLCertificateChainFile /etc/ssl/certs/api.example.com/chain.pem
    
    # Modern TLS configuration
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    
    # OCSP stapling
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    
    # Application configuration
    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/
</VirtualHost>
```

## Debugging Tools

### Comprehensive Certificate Inspector

```bash
#!/bin/bash
# cert-inspector.sh - Comprehensive certificate analysis

CERT_FILE="$1"

if [ -z "$CERT_FILE" ] || [ ! -f "$CERT_FILE" ]; then
    echo "Usage: $0 <certificate-file>"
    exit 1
fi

echo "=================================="
echo "CERTIFICATE ANALYSIS"
echo "=================================="
echo

echo "=== Basic Information ==="
openssl x509 -in "$CERT_FILE" -noout -subject -issuer -dates
echo

echo "=== Subject Alternative Names ==="
openssl x509 -in "$CERT_FILE" -noout -text | grep -A1 "Subject Alternative Name"
echo

echo "=== Key Information ==="
openssl x509 -in "$CERT_FILE" -noout -text | grep -E "(Public-Key|Signature Algorithm)"
echo

echo "=== Key Usage ==="
openssl x509 -in "$CERT_FILE" -noout -text | grep -A2 "Key Usage"
echo

echo "=== Extended Key Usage ==="
openssl x509 -in "$CERT_FILE" -noout -text | grep -A2 "Extended Key Usage"
echo

echo "=== Authority Information Access ==="
openssl x509 -in "$CERT_FILE" -noout -text | grep -A5 "Authority Information Access"
echo

echo "=== Certificate Fingerprints ==="
echo "SHA256: $(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2)"
echo "SHA1:   $(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha1 | cut -d= -f2)"
echo

echo "=== Validity Check ==="
if openssl x509 -in "$CERT_FILE" -noout -checkend 0 > /dev/null 2>&1; then
    echo "✓ Certificate is currently valid"
    
    # Calculate days until expiry
    expiry_epoch=$(date -d "$(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2)" +%s)
    current_epoch=$(date +%s)
    days_remaining=$(( ($expiry_epoch - $current_epoch) / 86400 ))
    
    echo "  Days until expiry: $days_remaining"
    
    if [ $days_remaining -lt 30 ]; then
        echo "  ⚠ WARNING: Certificate expires in less than 30 days!"
    fi
else
    echo "✗ Certificate has EXPIRED"
fi
```

## Conclusion

Certificate misconfigurations are preventable through:

1. **Validation before deployment** - Automated checks catch 90% of issues
2. **Configuration templates** - Use proven, tested configurations
3. **Continuous monitoring** - Detect drift and changes
4. **Documentation** - Keep configuration rationale documented
5. **Regular audits** - Quarterly reviews catch accumulating problems

The key insight: most misconfigurations are straightforward mistakes that automated validation catches easily. Invest in validation tooling upfront to prevent production incidents.
