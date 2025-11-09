# Threat Models and Attack Vectors

## Overview

Public Key Infrastructure is a critical security foundation, yet it presents a rich attack surface. Understanding PKI threat models isn't about paranoia—it's about building resilient systems that fail safely when attacked. Every PKI implementation must consider not just the happy path of certificate issuance and validation, but the adversarial scenarios where attackers exploit weaknesses in cryptography, protocols, implementation, or operations.

**Core principle**: Security is achieved not by eliminating all threats, but by understanding threat models and implementing appropriate controls that make attacks impractical, detectable, or contained in their impact.

## PKI Threat Landscape

### Attacker Profiles

**Nation-state actors**:
- Capabilities: Advanced persistent threats, zero-day exploits, supply chain compromise
- Motivations: Espionage, sabotage, strategic advantage
- Targets: Certificate authorities, root key material, signing infrastructure
- Notable examples: Stuxnet (2010), DigiNotar compromise (2011)

**Organized cybercrime**:
- Capabilities: Sophisticated tooling, insider recruitment, targeted phishing
- Motivations: Financial gain, ransomware, data theft
- Targets: Private keys for impersonation, certificate authorities for fraudulent issuance
- Notable examples: Comodo CA breach attempt (2011)

**Insider threats**:
- Capabilities: Legitimate access, knowledge of internal systems, trust relationships
- Motivations: Financial, ideological, coercion, negligence
- Targets: Private keys, CA credentials, certificate issuance systems
- Risk: 30-40% of security incidents involve insider elements

**Opportunistic attackers**:
- Capabilities: Automated scanning, known exploits, social engineering
- Motivations: Any available attack surface, broad targeting
- Targets: Weak implementations, misconfigurations, expired certificates
- Volume: Highest volume but typically lower sophistication

### Attack Surface Analysis

```
┌─────────────────────────────────────────────────────────────┐
│                    PKI Attack Surface                        │
│                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌───────────────┐ │
│  │   Key Storage  │  │  CA Operations │  │  Certificate  │ │
│  │                │  │                │  │  Validation   │ │
│  │  • HSMs        │  │  • Issuance    │  │  • Trust      │ │
│  │  • Key files   │  │  • Validation  │  │  • Revocation │ │
│  │  • Memory      │  │  • Approval    │  │  • Pinning    │ │
│  └────────────────┘  └────────────────┘  └───────────────┘ │
│           │                   │                    │         │
│           └───────────────────┼────────────────────┘         │
│                               │                              │
│  ┌────────────────┐  ┌────────────────┐  ┌───────────────┐ │
│  │  Cryptographic │  │  Protocol      │  │  Operational  │ │
│  │  Primitives    │  │  Implementation│  │  Processes    │ │
│  │                │  │                │  │               │ │
│  │  • Algorithms  │  │  • TLS/SSL     │  │  • Issuance   │ │
│  │  • RNG         │  │  • ACME        │  │  • Rotation   │ │
│  │  • Side chan.  │  │  • SCEP        │  │  • Incident   │ │
│  └────────────────┘  └────────────────┘  └───────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Cryptographic Attacks

### Algorithm Weaknesses

**Collision attacks on hash functions**:

MD5 collision (2008):
```python
# Demonstrated MD5 collision allowing two certificates with same hash
# but different public keys

def md5_collision_attack_scenario():
    """
    How MD5 collisions enable certificate fraud
    """
    # Attacker creates two CSRs with carefully crafted content
    # that produces MD5 collision
    
    legitimate_csr = create_csr(
        common_name="attacker.com",
        collision_block=collision_data_1
    )
    
    fraudulent_csr = create_csr(
        common_name="bank.com",  # Target domain
        collision_block=collision_data_2
    )
    
    # Both CSRs have identical MD5 hash
    assert md5(legitimate_csr) == md5(fraudulent_csr)
    
    # Submit legitimate CSR to CA
    cert = ca.issue_certificate(legitimate_csr)
    
    # Certificate signature validates for both CSRs!
    # Attacker can now impersonate bank.com
    assert verify_signature(cert, legitimate_csr)
    assert verify_signature(cert, fraudulent_csr)
```

Defense:
- **Never use MD5 or SHA-1 for certificate signatures**
- Minimum: SHA-256
- Preferred: SHA-384 or SHA-512
- Monitor for deprecated algorithms in use

**RSA key length attacks**:

Factorization timeline:
- 512-bit RSA: Factored in 1999
- 768-bit RSA: Factored in 2009
- 1024-bit RSA: Considered breakable by well-resourced adversaries
- 2048-bit RSA: Current minimum recommendation
- 4096-bit RSA: Conservative choice for long-term security

```python
class KeyStrengthValidator:
    """
    Validate cryptographic key strength
    """
    
    MINIMUM_KEY_SIZES = {
        'RSA': 2048,
        'DSA': 2048,
        'ECDSA': 256,
        'EdDSA': 256
    }
    
    RECOMMENDED_KEY_SIZES = {
        'RSA': 3072,
        'DSA': 3072,
        'ECDSA': 384,
        'EdDSA': 448
    }
    
    def validate_key_strength(self, cert: Certificate) -> ValidationResult:
        """
        Validate certificate key meets minimum requirements
        """
        result = ValidationResult()
        
        algorithm = cert.public_key_algorithm
        key_size = cert.key_size
        
        if algorithm not in self.MINIMUM_KEY_SIZES:
            result.fail(f"Unsupported algorithm: {algorithm}")
            return result
        
        minimum = self.MINIMUM_KEY_SIZES[algorithm]
        recommended = self.RECOMMENDED_KEY_SIZES[algorithm]
        
        if key_size < minimum:
            result.fail(
                f"{algorithm} key size {key_size} below minimum {minimum}"
            )
        elif key_size < recommended:
            result.warn(
                f"{algorithm} key size {key_size} below recommended {recommended}"
            )
        else:
            result.pass_check(f"{algorithm} key size adequate: {key_size}")
        
        return result
```

### Side-Channel Attacks

**Timing attacks**:

```python
# Vulnerable: Timing leak in RSA signature verification
def vulnerable_signature_verify(signature: bytes, 
                               message: bytes,
                               public_key: RSAPublicKey) -> bool:
    """
    VULNERABLE: Early return leaks information via timing
    """
    expected = public_key.verify(signature, message)
    
    # Early return if lengths differ - timing leak!
    if len(signature) != len(expected):
        return False
    
    # Byte-by-byte comparison - timing leak!
    for i in range(len(signature)):
        if signature[i] != expected[i]:
            return False  # Early return leaks position of first difference
    
    return True

# Secure: Constant-time comparison
def secure_signature_verify(signature: bytes,
                            message: bytes, 
                            public_key: RSAPublicKey) -> bool:
    """
    SECURE: Constant-time comparison prevents timing attacks
    """
    expected = public_key.verify(signature, message)
    
    # Use constant-time comparison
    return hmac.compare_digest(signature, expected)
```

**Power analysis**:

Physical attacks on cryptographic hardware:
- **Simple Power Analysis (SPA)**: Observing power consumption during crypto operations
- **Differential Power Analysis (DPA)**: Statistical analysis of power traces
- **Correlation Power Analysis (CPA)**: Advanced statistical techniques

Defense:
```python
class SecureKeyOperations:
    """
    Guidelines for secure key operations resistant to side-channels
    """
    
    @staticmethod
    def secure_key_storage():
        """
        Recommendations for protecting keys from physical attacks
        """
        return {
            'hardware_security_modules': {
                'description': 'Tamper-resistant hardware for key storage',
                'features': [
                    'Zeroization on tampering',
                    'Shielded enclosures',
                    'Active tamper detection',
                    'Power analysis countermeasures'
                ],
                'certifications': ['FIPS 140-2 Level 3+', 'Common Criteria EAL4+']
            },
            'algorithm_hardening': {
                'blinding': 'Randomize intermediate values',
                'constant_time': 'Fixed execution time regardless of input',
                'masking': 'Split sensitive values across random shares'
            },
            'operational_security': {
                'physical_access_control': 'Restricted access to crypto hardware',
                'environmental_monitoring': 'Detect anomalous power/EM emissions',
                'audit_logging': 'Log all key access and operations'
            }
        }
```

### Quantum Computing Threats

**Post-quantum cryptography timeline**:

Current status (2025):
- **RSA/ECDSA**: Vulnerable to Shor's algorithm on quantum computers
- **Timeline**: Large-scale quantum computers 10-20 years away
- **Action required**: Begin transition planning now

NIST post-quantum standards:
```yaml
post_quantum_algorithms:
  digital_signatures:
    - name: "CRYSTALS-Dilithium"
      status: "NIST standardized (2024)"
      security_level: "High"
      performance: "Good"
      
    - name: "FALCON"
      status: "NIST standardized (2024)"
      security_level: "High"
      performance: "Excellent (compact signatures)"
      
    - name: "SPHINCS+"
      status: "NIST standardized (2024)"
      security_level: "Very High"
      performance: "Slower (stateless hash-based)"
  
  key_exchange:
    - name: "CRYSTALS-Kyber"
      status: "NIST standardized (2024)"
      security_level: "High"
      performance: "Excellent"
```

Migration strategy:
```python
class QuantumMigrationStrategy:
    """
    Phased approach to post-quantum cryptography
    """
    
    def __init__(self):
        self.phases = {
            'phase_1_inventory': {
                'timeline': '2025-2026',
                'actions': [
                    'Inventory all cryptographic systems',
                    'Identify quantum-vulnerable components',
                    'Assess criticality and data sensitivity',
                    'Calculate cryptographic shelf life'
                ]
            },
            'phase_2_hybrid': {
                'timeline': '2026-2028',
                'actions': [
                    'Deploy hybrid classical/post-quantum schemes',
                    'Update TLS to support PQ key exchange',
                    'Test PQ signature schemes in non-critical systems',
                    'Build operational expertise'
                ]
            },
            'phase_3_transition': {
                'timeline': '2028-2032',
                'actions': [
                    'Migrate critical systems to PQ crypto',
                    'Phase out classical-only systems',
                    'Re-issue certificates with PQ signatures',
                    'Update root and intermediate CAs'
                ]
            },
            'phase_4_full_pq': {
                'timeline': '2032+',
                'actions': [
                    'Complete migration to post-quantum',
                    'Decommission classical cryptography',
                    'Maintain only PQ infrastructure'
                ]
            }
        }
    
    def assess_quantum_risk(self, data_sensitivity: str,
                           retention_period: int) -> str:
        """
        Assess quantum computing risk for data
        """
        # "Harvest now, decrypt later" threat
        if data_sensitivity == 'high' and retention_period > 10:
            return 'critical'  # Immediate PQ migration needed
        elif data_sensitivity == 'high' and retention_period > 5:
            return 'high'  # PQ migration within 2 years
        elif retention_period > 15:
            return 'medium'  # PQ migration within 5 years
        else:
            return 'low'  # Standard migration timeline
```

## Certificate Authority Attacks

### CA Compromise

**Complete CA compromise scenarios**:

Attack vectors:
```python
class CACompromiseVectors:
    """
    Ways an attacker can compromise a certificate authority
    """
    
    ATTACK_VECTORS = {
        'private_key_theft': {
            'methods': [
                'Physical access to HSM',
                'Exploitation of key backup procedures',
                'Memory dumping from CA server',
                'Supply chain attack on HSM firmware',
                'Insider theft'
            ],
            'impact': 'Critical - attacker can issue fraudulent certificates',
            'detection_difficulty': 'Very High',
            'recovery': 'Revoke all issued certificates, re-key CA'
        },
        
        'credential_compromise': {
            'methods': [
                'Phishing CA operators',
                'Exploiting weak passwords',
                'Session hijacking',
                'Malware on operator workstations'
            ],
            'impact': 'High - unauthorized certificate issuance',
            'detection_difficulty': 'Medium',
            'recovery': 'Revoke fraudulent certificates, audit all issuance'
        },
        
        'system_exploitation': {
            'methods': [
                'Software vulnerabilities in CA application',
                'OS-level exploits',
                'Network-based attacks',
                'API authentication bypass'
            ],
            'impact': 'High - various depending on exploit',
            'detection_difficulty': 'Medium',
            'recovery': 'Patch vulnerability, audit system integrity'
        },
        
        'process_abuse': {
            'methods': [
                'Social engineering certificate approval',
                'Exploiting weak validation procedures',
                'Domain validation bypass',
                'Insider abuse of issuance privileges'
            ],
            'impact': 'Medium to High - limited fraudulent issuance',
            'detection_difficulty': 'Low to Medium',
            'recovery': 'Revoke fraudulent certificates, improve processes'
        }
    }
```

Real-world examples:

**DigiNotar (2011)**:
```python
class DigiNotarIncident:
    """
    Case study: DigiNotar CA compromise
    
    Timeline:
    - June 2011: Initial compromise via SQL injection
    - July 2011: Fraudulent certificates issued for *.google.com and others
    - August 2011: Detection by Iranian users
    - September 2011: DigiNotar revoked from trust stores
    - September 2011: DigiNotar declared bankrupt
    
    Impact:
    - 531 fraudulent certificates issued
    - Used for surveillance in Iran
    - Complete loss of trust in DigiNotar
    - Browser vendors removed DigiNotar root
    """
    
    lessons_learned = {
        'detection': 'Certificate Transparency would have detected this faster',
        'isolation': 'Compromise of one system led to complete CA compromise',
        'monitoring': 'Inadequate monitoring failed to detect suspicious issuance',
        'response': 'Slow incident response allowed extended compromise',
        'impact': 'Complete CA compromise requires root revocation'
    }
    
    @staticmethod
    def preventive_controls():
        return {
            'defense_in_depth': 'Multiple security layers',
            'least_privilege': 'Minimal permissions for each role',
            'monitoring': 'Real-time anomaly detection',
            'ct_logging': 'Mandatory Certificate Transparency',
            'hsm_protection': 'Hardware-protected private keys',
            'air_gap': 'Offline root CA'
        }
```

**Comodo (2011)**:
```python
class ComodoIncident:
    """
    Case study: Comodo RA compromise
    
    March 2011: Registration Authority compromised
    - Attacker obtained RA credentials
    - Issued fraudulent certificates for:
      * login.live.com (Microsoft)
      * mail.google.com (Google)
      * login.yahoo.com (Yahoo)
      * addons.mozilla.org (Mozilla)
    - Attack attributed to Iranian actor
    
    Impact:
    - Nine fraudulent certificates issued
    - Quick detection and revocation
    - No widespread exploitation detected
    """
    
    lessons_learned = {
        'ra_security': 'Registration Authorities need strong security',
        'monitoring': 'Anomalous issuance patterns should trigger alerts',
        'rapid_response': 'Quick revocation limited impact',
        'targeted_attack': 'High-profile domains were specifically targeted'
    }
```

### Fraudulent Certificate Issuance

**Domain validation bypass**:

Attack scenarios:
```python
class DomainValidationAttacks:
    """
    Attacks against domain validation in certificate issuance
    """
    
    @staticmethod
    def dns_hijacking_attack():
        """
        Attacker compromises DNS to pass validation
        """
        return {
            'attack': 'DNS Hijacking',
            'method': 'Compromise DNS provider or registrar',
            'validation_bypass': 'Control DNS records to pass DCV',
            'mitigation': [
                'DNSSEC to protect DNS integrity',
                'Multi-perspective validation',
                'CAA records to restrict CAs',
                'Monitor DNS changes'
            ]
        }
    
    @staticmethod
    def bgp_hijacking_attack():
        """
        BGP hijacking to intercept validation traffic
        """
        return {
            'attack': 'BGP Hijacking',
            'method': 'Announce false BGP routes',
            'validation_bypass': 'Intercept HTTP-01 or TLS-ALPN-01 challenges',
            'real_world': 'AWS Route53 incident (2018)',
            'mitigation': [
                'RPKI to validate BGP routes',
                'Multi-vantage-point validation',
                'DNS validation instead of HTTP',
                'Monitor BGP announcements'
            ]
        }
    
    @staticmethod
    def email_validation_attack():
        """
        Compromise email for domain validation
        """
        return {
            'attack': 'Email Account Compromise',
            'method': 'Compromise admin@ or postmaster@ email',
            'validation_bypass': 'Receive validation email',
            'mitigation': [
                'Avoid email validation for high-value domains',
                'Strong email security (2FA, etc.)',
                'CAA records to restrict CAs',
                'Monitor certificate issuance via CT logs'
            ]
        }
```

**CAA record bypass**:

DNS Certification Authority Authorization:
```python
def validate_caa_compliance(domain: str, ca_identity: str) -> bool:
    """
    Check if CA is authorized to issue for domain via CAA records
    """
    # Query CAA records
    caa_records = dns.query_caa_records(domain)
    
    if not caa_records:
        # No CAA records = any CA can issue (for now)
        return True
    
    # Check if this CA is authorized
    for record in caa_records:
        if record.tag == 'issue' or record.tag == 'issuewild':
            if record.value == ca_identity or record.value == '':
                return True
    
    # CA not authorized
    return False

# Attack: CAA records can be bypassed if not properly enforced
class CAABypassAttacks:
    """
    Ways attackers bypass CAA protections
    """
    
    attacks = {
        'dns_hijacking': 'Modify DNS to remove CAA records',
        'subdomain_takeover': 'Control subdomain without CAA record',
        'ca_non_compliance': 'CA fails to check CAA records',
        'timing_race': 'Issue during CAA record update window'
    }
```

### Man-in-the-Middle (MITM) Attacks

**TLS interception**:

Corporate MITM:
```python
class CorporateTLSInterception:
    """
    How corporate TLS inspection works (and its risks)
    """
    
    def __init__(self):
        self.corporate_ca = self.load_corporate_ca()
    
    def intercept_connection(self, original_connection):
        """
        MITM technique used by enterprise proxies
        """
        # Step 1: Terminate client TLS connection
        client_tls = self.terminate_tls(
            connection=original_connection,
            certificate=self.generate_spoofed_cert(original_connection.hostname)
        )
        
        # Step 2: Establish new connection to real server
        server_tls = self.connect_to_server(original_connection.hostname)
        
        # Step 3: Inspect and forward traffic
        while True:
            client_data = client_tls.receive()
            inspected_data = self.inspect_and_log(client_data)
            server_tls.send(inspected_data)
            
            server_response = server_tls.receive()
            inspected_response = self.inspect_and_log(server_response)
            client_tls.send(inspected_response)
    
    def generate_spoofed_cert(self, hostname: str) -> Certificate:
        """
        Generate certificate impersonating target
        """
        # Create certificate for target hostname
        # Signed by corporate CA (trusted by corporate devices)
        cert = Certificate(
            common_name=hostname,
            issuer=self.corporate_ca,
            validity=365
        )
        return self.corporate_ca.sign(cert)
    
    # Security risks:
    risks = {
        'trust_model_violation': 'Breaks end-to-end encryption',
        'key_exposure': 'Corporate CA private key is high-value target',
        'privacy_concerns': 'All TLS traffic visible to corporation',
        'certificate_pinning_breaks': 'Apps with pinning will fail',
        'vulnerability_introduction': 'Proxy bugs can create vulnerabilities'
    }
```

Defenses against unwanted MITM:
```python
class MITMDefenses:
    """
    Protections against TLS interception attacks
    """
    
    @staticmethod
    def certificate_pinning():
        """
        Pin specific certificates or public keys
        """
        return {
            'mechanism': 'Hardcode expected certificate fingerprints',
            'effectiveness': 'Prevents MITM even with trusted CA',
            'limitations': 'Requires app updates for certificate rotation',
            'use_case': 'Mobile apps, high-security applications'
        }
    
    @staticmethod
    def public_key_pinning_http():
        """
        HTTP Public Key Pinning (deprecated but instructive)
        """
        return {
            'header': 'Public-Key-Pins',
            'mechanism': 'Browser enforces pinned public keys',
            'status': 'Deprecated due to operational risks',
            'lessons': 'Pinning is powerful but operationally dangerous',
            'successor': 'Certificate Transparency + Expect-CT'
        }
    
    @staticmethod
    def certificate_transparency_monitoring():
        """
        Monitor CT logs for unexpected certificates
        """
        return {
            'mechanism': 'All public certificates logged to CT',
            'detection': 'Monitor logs for unexpected issuance',
            'effectiveness': 'Detects fraudulent issuance after-the-fact',
            'tools': ['certstream', 'facebook CT monitor', 'SSLMate']
        }
```

## Private Key Compromise

### Key Theft Scenarios

**Memory extraction**:

Heartbleed (2014):
```python
class HeartbleedVulnerability:
    """
    CVE-2014-0160: OpenSSL memory disclosure
    
    Impact: TLS private keys leaked from memory
    """
    
    def exploit_scenario(self):
        """
        How Heartbleed exposed private keys
        """
        return {
            'vulnerability': 'Buffer over-read in heartbeat extension',
            'exposed_data': [
                'Private keys',
                'Session keys',
                'User credentials',
                'Application data'
            ],
            'affected_versions': 'OpenSSL 1.0.1 through 1.0.1f',
            'detection': 'Impossible to detect if keys were stolen',
            'response': 'Assume compromise, rekey all certificates',
            'impact': '17% of internet HTTPS servers affected'
        }
    
    lessons_learned = {
        'assume_compromise': 'No way to prove keys were not stolen',
        'massive_rekeying': 'Required enterprise-wide certificate rotation',
        'memory_safety': 'Memory-safe languages prevent this class of bugs',
        'defense_in_depth': 'HSMs protect keys even if server compromised'
    }
```

**Key file exposure**:

```python
class PrivateKeyExposure:
    """
    Common ways private keys are accidentally exposed
    """
    
    exposure_vectors = {
        'source_control': {
            'scenario': 'Private key committed to Git repository',
            'detection': 'GitHub/GitLab secret scanning',
            'prevalence': 'Very common',
            'impact': 'Public exposure if public repo',
            'mitigation': [
                'Pre-commit hooks to detect secrets',
                'Never commit private keys',
                'Use secret management systems',
                'Rotate keys immediately if exposed'
            ]
        },
        
        'backups': {
            'scenario': 'Keys in unencrypted backups',
            'detection': 'Backup compromise',
            'prevalence': 'Common',
            'impact': 'Keys accessible to backup system attackers',
            'mitigation': [
                'Encrypt backups',
                'Exclude private keys from backups',
                'Store keys in HSM (not filesystem)',
                'Access control on backup systems'
            ]
        },
        
        'configuration_management': {
            'scenario': 'Keys in Ansible/Chef/Puppet',
            'detection': 'Config management system compromise',
            'prevalence': 'Common',
            'impact': 'Keys distributed to many systems',
            'mitigation': [
                'Use secret management (Vault, etc.)',
                'Encrypt secrets in config management',
                'Just-in-time key generation',
                'Limit key distribution scope'
            ]
        },
        
        'log_files': {
            'scenario': 'Keys accidentally logged',
            'detection': 'Log review',
            'prevalence': 'Occasional',
            'impact': 'Keys in centralized logging',
            'mitigation': [
                'Sanitize logs before storage',
                'Never log private keys or credentials',
                'Secure log storage',
                'Log retention policies'
            ]
        },
        
        'debugging': {
            'scenario': 'Keys in debug output or core dumps',
            'detection': 'Core dump analysis',
            'prevalence': 'Occasional',
            'impact': 'Keys exposed in crash analysis',
            'mitigation': [
                'Disable core dumps in production',
                'Scrub sensitive data from memory before freeing',
                'Secure debug output',
                'Memory encryption'
            ]
        }
    }
```

### Key Compromise Detection

**Indicators of compromise**:

```python
class KeyCompromiseDetection:
    """
    Detect potential private key compromise
    """
    
    def monitor_for_compromise_indicators(self):
        """
        Signals that might indicate key compromise
        """
        indicators = {
            'unauthorized_certificate_issuance': {
                'signal': 'Certificate issued without proper authorization',
                'detection': 'Monitor CA issuance logs',
                'severity': 'Critical',
                'action': 'Investigate immediately, potentially revoke'
            },
            
            'ct_log_anomalies': {
                'signal': 'Unexpected certificates in CT logs',
                'detection': 'Monitor CT logs for domains',
                'severity': 'High',
                'action': 'Verify legitimate issuance, revoke if fraudulent'
            },
            
            'suspicious_tls_usage': {
                'signal': 'Certificate used from unexpected locations',
                'detection': 'Monitor certificate fingerprints in network traffic',
                'severity': 'High',
                'action': 'Investigate usage patterns'
            },
            
            'failed_private_key_access': {
                'signal': 'Failed attempts to access private key storage',
                'detection': 'HSM audit logs',
                'severity': 'Medium',
                'action': 'Review access attempts, investigate if anomalous'
            },
            
            'key_file_access': {
                'signal': 'Unexpected access to private key files',
                'detection': 'File integrity monitoring',
                'severity': 'High',
                'action': 'Audit access, investigate unauthorized access'
            }
        }
        
        return indicators
    
    def automated_compromise_detection(self, cert: Certificate) -> CompromiseAssessment:
        """
        Automated assessment of potential compromise
        """
        assessment = CompromiseAssessment(certificate=cert)
        
        # Check CT logs for unexpected issuance
        ct_certs = self.query_ct_logs(cert.subject_domains)
        unexpected = [c for c in ct_certs if c not in self.expected_certificates]
        if unexpected:
            assessment.add_indicator(
                'unexpected_ct_entries',
                severity='high',
                details=unexpected
            )
        
        # Check for usage from unexpected IPs
        usage_logs = self.query_network_logs(cert.fingerprint)
        unexpected_ips = [
            log for log in usage_logs 
            if log.source_ip not in self.authorized_ips
        ]
        if unexpected_ips:
            assessment.add_indicator(
                'unexpected_usage_location',
                severity='medium',
                details=unexpected_ips
            )
        
        # Check if certificate was recently revoked
        if cert.revocation_status == 'revoked':
            assessment.add_indicator(
                'certificate_revoked',
                severity='high',
                details={'revocation_date': cert.revocation_date}
            )
        
        return assessment
```

### Key Compromise Response

**Incident response workflow**:

```python
class KeyCompromiseResponse:
    """
    Incident response procedures for key compromise
    """
    
    def execute_response(self, compromise: CompromiseIncident) -> ResponseResult:
        """
        Execute key compromise incident response
        """
        result = ResponseResult()
        
        # Phase 1: Containment (immediate)
        result.add_phase("Containment")
        
        # 1a: Revoke compromised certificate(s)
        for cert in compromise.affected_certificates:
            self.emergency_revoke_certificate(
                cert,
                reason='keyCompromise',
                revocation_date=compromise.discovery_time
            )
        
        # 1b: Block key usage
        if compromise.private_key_location:
            self.disable_key(compromise.private_key_location)
        
        # 1c: Alert monitoring systems
        self.alert_all_monitoring_systems(compromise)
        
        # Phase 2: Eradication
        result.add_phase("Eradication")
        
        # 2a: Remove compromised key material
        self.secure_delete_key_material(compromise.private_key_location)
        
        # 2b: Patch vulnerability if applicable
        if compromise.vulnerability:
            self.emergency_patch(compromise.vulnerability)
        
        # 2c: Remove attacker access
        if compromise.attacker_access:
            self.remove_attacker_access(compromise.attacker_access)
        
        # Phase 3: Recovery
        result.add_phase("Recovery")
        
        # 3a: Generate new key material
        new_keys = self.generate_new_key_pairs(
            count=len(compromise.affected_certificates)
        )
        
        # 3b: Issue replacement certificates
        replacement_certs = []
        for cert in compromise.affected_certificates:
            replacement = self.issue_replacement_certificate(
                original=cert,
                new_key=new_keys.pop()
            )
            replacement_certs.append(replacement)
        
        # 3c: Deploy replacement certificates
        for cert in replacement_certs:
            self.emergency_deploy_certificate(cert)
        
        # 3d: Verify deployments
        for cert in replacement_certs:
            verification = self.verify_certificate_deployment(cert)
            if not verification.success:
                result.add_error(f"Deployment verification failed: {cert}")
        
        # Phase 4: Post-Incident
        result.add_phase("Post-Incident")
        
        # 4a: Forensic analysis
        self.conduct_forensic_analysis(compromise)
        
        # 4b: Identify root cause
        root_cause = self.identify_root_cause(compromise)
        
        # 4c: Implement preventive controls
        self.implement_preventive_controls(root_cause)
        
        # 4d: Post-mortem
        self.schedule_post_mortem(compromise)
        
        # 4e: Update documentation
        self.update_runbooks_and_docs(compromise)
        
        return result
```

## Protocol Attacks

### TLS/SSL Vulnerabilities

**Historical protocol attacks**:

```python
class TLSProtocolAttacks:
    """
    Major TLS/SSL protocol attacks and their impact
    """
    
    ATTACKS = {
        'BEAST': {
            'year': 2011,
            'cve': 'CVE-2011-3389',
            'target': 'TLS 1.0 CBC mode',
            'impact': 'Session cookie theft',
            'mitigation': 'Disable TLS 1.0, use TLS 1.2+',
            'status': 'Mitigated'
        },
        
        'CRIME': {
            'year': 2012,
            'cve': 'CVE-2012-4929',
            'target': 'TLS compression',
            'impact': 'Session hijacking via compression side-channel',
            'mitigation': 'Disable TLS compression',
            'status': 'Mitigated'
        },
        
        'BREACH': {
            'year': 2013,
            'cve': 'CVE-2013-3587',
            'target': 'HTTP compression',
            'impact': 'Extract secrets from compressed responses',
            'mitigation': 'Disable HTTP compression for sensitive data',
            'status': 'Partial mitigation'
        },
        
        'Heartbleed': {
            'year': 2014,
            'cve': 'CVE-2014-0160',
            'target': 'OpenSSL heartbeat extension',
            'impact': 'Memory disclosure including private keys',
            'mitigation': 'Update OpenSSL, rekey all certificates',
            'status': 'Mitigated (patched)'
        },
        
        'POODLE': {
            'year': 2014,
            'cve': 'CVE-2014-3566',
            'target': 'SSL 3.0 CBC mode',
            'impact': 'Padding oracle attack',
            'mitigation': 'Disable SSL 3.0',
            'status': 'Mitigated'
        },
        
        'FREAK': {
            'year': 2015,
            'cve': 'CVE-2015-0204',
            'target': 'RSA_EXPORT cipher suites',
            'impact': 'Downgrade to 512-bit RSA',
            'mitigation': 'Disable export cipher suites',
            'status': 'Mitigated'
        },
        
        'Logjam': {
            'year': 2015,
            'cve': 'CVE-2015-4000',
            'target': 'Diffie-Hellman export cipher suites',
            'impact': 'Downgrade to weak DH parameters',
            'mitigation': 'Disable export DH, use 2048+ bit DH',
            'status': 'Mitigated'
        },
        
        'DROWN': {
            'year': 2016,
            'cve': 'CVE-2016-0800',
            'target': 'SSLv2',
            'impact': 'Decrypt TLS sessions via SSLv2',
            'mitigation': 'Disable SSLv2',
            'status': 'Mitigated'
        },
        
        'ROBOT': {
            'year': 2017,
            'cve': 'CVE-2017-13099',
            'target': 'RSA PKCS#1 v1.5',
            'impact': 'Bleichenbacher padding oracle',
            'mitigation': 'Prefer ECDHE cipher suites',
            'status': 'Partial mitigation'
        }
    }
```

**Current best practices**:

```python
class SecureTLSConfiguration:
    """
    Modern TLS configuration for security
    """
    
    @staticmethod
    def get_recommended_config():
        """
        Recommended TLS configuration (2025)
        """
        return {
            'protocols': {
                'enabled': ['TLSv1.3', 'TLSv1.2'],
                'disabled': ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'],
                'preferred': 'TLSv1.3'
            },
            
            'cipher_suites_tls13': [
                'TLS_AES_256_GCM_SHA384',
                'TLS_AES_128_GCM_SHA256',
                'TLS_CHACHA20_POLY1305_SHA256'
            ],
            
            'cipher_suites_tls12': [
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-CHACHA20-POLY1305'
            ],
            
            'key_exchange': {
                'dh_param_size': 2048,  # Minimum
                'ecdh_curves': ['X25519', 'secp384r1', 'secp256r1']
            },
            
            'features': {
                'compression': False,  # CRIME/BREACH mitigation
                'renegotiation': False,  # DoS mitigation
                'session_tickets': True,  # Performance (with rotation)
                'ocsp_stapling': True,  # Performance and privacy
                'sni': True  # Virtual hosting
            },
            
            'headers': {
                'strict_transport_security': 'max-age=31536000; includeSubDomains; preload',
                'expect_ct': 'enforce, max-age=86400'
            }
        }
```

### Certificate Validation Attacks

**Chain validation bypass**:

```python
class ChainValidationAttacks:
    """
    Attacks on certificate chain validation
    """
    
    @staticmethod
    def incomplete_chain_attack():
        """
        Server fails to send intermediate certificates
        """
        return {
            'attack': 'Missing Intermediate Certificate',
            'scenario': [
                'Server sends only leaf certificate',
                'Client cannot build chain to trusted root',
                'Some clients cache intermediates and succeed',
                'Others fail with validation error'
            ],
            'impact': 'Inconsistent validation across clients',
            'exploitation': 'Cause DoS by making service unavailable to some',
            'mitigation': [
                'Always send complete chain',
                'Automated chain validation in CI/CD',
                'Monitor for chain validation errors'
            ]
        }
    
    @staticmethod
    def untrusted_root_attack():
        """
        Certificate chain to untrusted root
        """
        return {
            'attack': 'Untrusted Root Certificate',
            'scenario': [
                'Attacker creates their own CA',
                'Issues certificate signed by their CA',
                'Presents certificate to client',
                'Client should reject (root not trusted)'
            ],
            'impact': 'Should be blocked by proper validation',
            'exploitation': 'Only works if client has misconfigured trust',
            'mitigation': [
                'Maintain proper trust store',
                'Validate chain to known roots',
                'Remove untrusted roots',
                'Monitor trust store changes'
            ]
        }
    
    @staticmethod
    def signature_verification_bypass():
        """
        Skip or weaken signature verification
        """
        return {
            'attack': 'Signature Verification Bypass',
            'scenario': [
                'Vulnerable TLS library skips signature check',
                'Or accepts weak signature algorithms',
                'Attacker presents certificate with invalid signature',
                'Client incorrectly accepts it'
            ],
            'real_world': 'Apple goto fail (2014)',
            'mitigation': [
                'Use well-tested crypto libraries',
                'Enable all validation checks',
                'Regular security updates',
                'Automated testing of validation'
            ]
        }
```

**Hostname validation bypass**:

```python
class HostnameValidationAttacks:
    """
    Attacks exploiting weak hostname validation
    """
    
    @staticmethod
    def null_byte_attack():
        """
        Null byte injection in certificate CN/SAN
        """
        return {
            'attack': 'Null Byte Injection',
            'scenario': [
                'Certificate CN: "attacker.com\\x00bank.com"',
                'Vulnerable validator stops at null byte',
                'Sees only "attacker.com"',
                'But certificate also valid for intended victim'
            ],
            'real_world': 'Found in multiple TLS libraries (2009-2015)',
            'mitigation': [
                'Properly parse X.509 names',
                'Reject certificates with null bytes',
                'Use SAN instead of CN',
                'Modern libraries have fixed this'
            ]
        }
    
    @staticmethod
    def wildcard_abuse():
        """
        Overly broad wildcard matching
        """
        return {
            'attack': 'Wildcard Abuse',
            'scenario': [
                'Certificate for *.example.com',
                'Should match sub.example.com',
                'Should NOT match sub.domain.example.com',
                'Vulnerable validators allow multi-level'
            ],
            'mitigation': [
                'Wildcards only match single label',
                'Use multiple specific SANs instead',
                'Avoid wildcards for sensitive domains'
            ]
        }
    
    @staticmethod
    def homograph_attack():
        """
        Unicode homograph domains
        """
        return {
            'attack': 'IDN Homograph',
            'scenario': [
                'Register domain with lookalike characters',
                'еxample.com (Cyrillic е) vs example.com (Latin e)',
                'Obtain legitimate certificate',
                'Users cannot distinguish domains'
            ],
            'mitigation': [
                'Browser IDN display policies',
                'Restrict mixed-script domains',
                'Certificate Transparency monitoring',
                'User education'
            ]
        }
```

## Operational Security Failures

### Configuration Errors

**Common misconfigurations**:

```python
class CommonPKIMisconfigurations:
    """
    Dangerous but common PKI misconfigurations
    """
    
    MISCONFIGURATIONS = {
        'weak_private_key_permissions': {
            'issue': 'Private key file readable by all users',
            'command': 'ls -l /etc/ssl/private/server.key',
            'bad': '-rw-r--r-- 1 root root 1675 server.key',
            'good': '-rw------- 1 root root 1675 server.key',
            'risk': 'Any user can steal private key',
            'fix': 'chmod 600 /etc/ssl/private/server.key'
        },
        
        'private_key_in_public_location': {
            'issue': 'Private key in web-accessible directory',
            'bad': '/var/www/html/certs/private.key',
            'risk': 'Private key downloadable via HTTP',
            'fix': 'Move to /etc/ssl/private/, block web access'
        },
        
        'certificate_key_mismatch': {
            'issue': 'Certificate does not match private key',
            'detection': 'TLS handshake fails with "wrong signature" error',
            'risk': 'Service outage',
            'fix': 'Verify cert/key match before deployment'
        },
        
        'missing_intermediate_certificates': {
            'issue': 'Server sends only leaf certificate',
            'detection': 'Some clients fail to validate chain',
            'risk': 'Intermittent connection failures',
            'fix': 'Include all intermediate certificates in chain'
        },
        
        'expired_certificate': {
            'issue': 'Certificate past validity period',
            'detection': 'All clients reject connection',
            'risk': 'Complete service outage',
            'fix': 'Renew certificate before expiry'
        },
        
        'wrong_hostname': {
            'issue': 'Certificate does not include server hostname',
            'detection': 'Hostname validation errors',
            'risk': 'Clients cannot connect',
            'fix': 'Include all hostnames in certificate SANs'
        },
        
        'weak_cipher_suites': {
            'issue': 'Weak or export cipher suites enabled',
            'bad': 'SSLCipherSuite ALL:!EXPORT:!DES:!MD5',
            'risk': 'Vulnerable to downgrade attacks',
            'fix': 'Use only modern, strong cipher suites'
        },
        
        'ssl_version_2_or_3_enabled': {
            'issue': 'SSLv2 or SSLv3 still enabled',
            'detection': 'SSLyze, testssl.sh',
            'risk': 'Vulnerable to DROWN, POODLE',
            'fix': 'Disable all SSL versions, use TLS 1.2+'
        }
    }
```

### Supply Chain Attacks

**Compromised cryptographic libraries**:

```python
class SupplyChainThreats:
    """
    Supply chain attack vectors in PKI
    """
    
    @staticmethod
    def compromised_crypto_library():
        """
        Backdoored cryptographic implementation
        """
        return {
            'attack': 'Compromised Crypto Library',
            'scenario': [
                'Attacker compromises crypto library source/binary',
                'Backdoor weakens key generation',
                'Or leaks key material',
                'Or bypasses validation'
            ],
            'real_world': 'Juniper ScreenOS backdoor (2015)',
            'impact': 'Widespread compromise of systems using library',
            'detection': [
                'Code review of critical libraries',
                'Binary integrity verification',
                'Behavioral monitoring',
                'Key quality testing'
            ],
            'mitigation': [
                'Use well-audited libraries',
                'Verify signatures on dependencies',
                'Pin specific versions',
                'Test key randomness',
                'Defense in depth'
            ]
        }
    
    @staticmethod
    def malicious_hsm_firmware():
        """
        Compromised HSM firmware
        """
        return {
            'attack': 'HSM Firmware Backdoor',
            'scenario': [
                'Attacker compromises HSM vendor',
                'Malicious firmware update distributed',
                'Firmware extracts key material',
                'Or weakens key generation'
            ],
            'impact': 'Complete compromise of key protection',
            'detection': 'Very difficult - requires firmware analysis',
            'mitigation': [
                'HSM from trusted vendors with FIPS validation',
                'Firmware signature verification',
                'Multiple vendors in critical infrastructure',
                'Air-gapped key generation'
            ]
        }
    
    @staticmethod
    def compromised_ca_software():
        """
        Backdoor in CA management software
        """
        return {
            'attack': 'CA Software Compromise',
            'scenario': [
                'CA management software compromised',
                'Backdoor enables unauthorized issuance',
                'Or logs key material',
                'Or bypasses approval workflows'
            ],
            'impact': 'Unauthorized certificate issuance',
            'mitigation': [
                'Vendor security assessment',
                'Code audits for critical software',
                'Anomaly detection on issuance',
                'Multi-party approval processes'
            ]
        }
```

## Defense in Depth

### Layered Security Controls

```python
class PKISecurityLayers:
    """
    Defense in depth for PKI infrastructure
    """
    
    def __init__(self):
        self.layers = {
            'physical': {
                'controls': [
                    'Secure data center for CA infrastructure',
                    'HSM in tamper-resistant enclosure',
                    'Access control to server rooms',
                    'Environmental monitoring',
                    'Offline root CA in vault'
                ],
                'threat_mitigation': [
                    'Physical theft',
                    'Unauthorized access',
                    'Environmental attacks'
                ]
            },
            
            'network': {
                'controls': [
                    'Network segmentation (CA in isolated VLAN)',
                    'Firewall rules restricting CA access',
                    'IDS/IPS monitoring',
                    'TLS for all communications',
                    'VPN for remote access'
                ],
                'threat_mitigation': [
                    'Network-based attacks',
                    'MITM attacks',
                    'Unauthorized access',
                    'Lateral movement'
                ]
            },
            
            'system': {
                'controls': [
                    'Hardened OS configuration',
                    'Minimal installed software',
                    'Regular patching',
                    'Host-based firewall',
                    'Antivirus/EDR',
                    'File integrity monitoring'
                ],
                'threat_mitigation': [
                    'OS vulnerabilities',
                    'Malware',
                    'Unauthorized changes'
                ]
            },
            
            'application': {
                'controls': [
                    'Secure CA software configuration',
                    'Input validation',
                    'Output encoding',
                    'Error handling',
                    'Secure session management',
                    'API authentication'
                ],
                'threat_mitigation': [
                    'Application vulnerabilities',
                    'Injection attacks',
                    'Authentication bypass'
                ]
            },
            
            'cryptographic': {
                'controls': [
                    'Keys stored in FIPS 140-2 Level 3+ HSM',
                    'Strong key generation',
                    'Approved algorithms only',
                    'Regular key rotation',
                    'Encrypted key backups'
                ],
                'threat_mitigation': [
                    'Key theft',
                    'Weak cryptography',
                    'Algorithm breaks'
                ]
            },
            
            'operational': {
                'controls': [
                    'Separation of duties',
                    'Multi-party approval for sensitive operations',
                    'Comprehensive audit logging',
                    'Regular security assessments',
                    'Incident response procedures',
                    'Background checks for operators'
                ],
                'threat_mitigation': [
                    'Insider threats',
                    'Operational errors',
                    'Unauthorized activities'
                ]
            },
            
            'monitoring': {
                'controls': [
                    'Certificate Transparency monitoring',
                    'CA audit log monitoring',
                    'Anomaly detection',
                    'Security information and event management (SIEM)',
                    'Regular security audits'
                ],
                'threat_mitigation': [
                    'Undetected compromises',
                    'Fraudulent issuance',
                    'Anomalous behavior'
                ]
            }
        }
```

## Conclusion

PKI security requires a comprehensive threat model that spans cryptographic attacks, infrastructure compromise, protocol vulnerabilities, and operational failures. No single control provides complete security; instead, defense in depth creates overlapping layers that make attacks impractical or at least detectable.

The most critical principles:

1. **Assume breach**: Design systems to limit impact when (not if) compromise occurs
2. **Defense in depth**: Multiple independent security layers
3. **Monitoring and detection**: You can't respond to what you don't detect
4. **Cryptographic agility**: Ability to migrate away from broken algorithms
5. **Operational security**: Technical controls are worthless with weak processes

Understanding these threat models enables building PKI infrastructure that is resilient against real-world attacks, responds effectively when compromised, and evolves as the threat landscape changes.
