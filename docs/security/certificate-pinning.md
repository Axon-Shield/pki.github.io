# Certificate Pinning

**Category**: Security  
**Complexity**: Advanced  
**Prerequisites**: [Certificate Anatomy](../foundations/certificate-anatomy.md), [Chain Of Trust](../foundations/trust-models.md), [Tls Protocol](../standards/tls-protocol.md)  
**Related**: [Common Vulnerabilities](common-vulnerabilities.md), [Private Key Protection](private-key-protection.md), [Trust Models](../foundations/trust-models.md)

---

## Overview

Certificate pinning is a security technique where applications explicitly trust specific certificates or public keys rather than relying solely on the system's trust store. This hardens security by preventing man-in-the-middle (MITM) attacks even when an attacker has compromised a Certificate Authority or installed rogue root certificates on the device.

### Why Pin Certificates?

**Traditional TLS validation weaknesses**:

- Any CA in the trust store can issue certificates for any domain
- ~100+ root CAs trusted by default on most systems
- Compromise of any single CA threatens all connections
- Government-backed CAs may issue certificates for surveillance
- Rogue certificates have been issued (DigiNotar 2011, CNNIC 2015)

**Pinning provides defense-in-depth**:
```
Normal TLS:
  App → System Trust Store (100+ CAs) → Accept any valid certificate

With Pinning:
  App → Built-in pins → Only accept specific certificates/keys
```

## Pinning Strategies

### 1. Certificate Pinning

Pin the entire certificate (including validity dates and signature).

**Advantages**:

- Simple to implement
- Exact match required
- No ambiguity

**Disadvantages**:

- Requires app update when certificate expires
- Inflexible for certificate rotation
- High operational burden

**Implementation**:
```python
import hashlib
import ssl
from typing import Set

class CertificatePinner:
    """
    Pin entire certificates by their SHA-256 hash
    """
    
    def __init__(self, pinned_certs: Set[str]):
        """
        Args:
            pinned_certs: Set of SHA-256 hashes of DER-encoded certificates
        """
        self.pinned_certs = pinned_certs
    
    def verify_certificate(self, cert_der: bytes) -> bool:
        """
        Verify certificate matches one of the pins
        """
        cert_hash = hashlib.sha256(cert_der).hexdigest()
        
        if cert_hash not in self.pinned_certs:
            raise SecurityError(
                f"Certificate hash {cert_hash} not in pinned set. "
                f"Expected one of: {self.pinned_certs}"
            )
        
        return True

# Usage in application
API_CERT_PINS = {
    # Production certificate (expires 2025-12-31)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    # Backup certificate (expires 2026-06-30)
    "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
}

pinner = CertificatePinner(API_CERT_PINS)
```

### 2. Public Key Pinning (RECOMMENDED)

Pin the public key component only, ignoring certificate metadata.

**Advantages**:

- Survives certificate renewal (same key pair)
- More flexible for operations
- Recommended by OWASP
- Can pin intermediate or root CA keys

**Disadvantages**:

- Slightly more complex to extract public key
- Must still rotate when keys change

**Implementation**:
```python
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class PublicKeyPinner:
    """
    Pin Subject Public Key Info (SPKI) using SHA-256
    """
    
    def __init__(self, pinned_spki_hashes: Set[str]):
        """
        Args:
            pinned_spki_hashes: Set of base64-encoded SHA-256 hashes of SPKI
        """
        self.pinned_spki_hashes = pinned_spki_hashes
    
    def extract_spki_hash(self, cert_der: bytes) -> str:
        """
        Extract and hash the Subject Public Key Info from certificate
        """
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        # Get public key
        public_key = cert.public_key()
        
        # Serialize to SubjectPublicKeyInfo format
        spki_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Hash and base64 encode
        spki_hash = hashlib.sha256(spki_der).digest()
        return base64.b64encode(spki_hash).decode('ascii')
    
    def verify_certificate(self, cert_der: bytes) -> bool:
        """
        Verify certificate's public key matches one of the pins
        """
        spki_hash = self.extract_spki_hash(cert_der)
        
        if spki_hash not in self.pinned_spki_hashes:
            raise SecurityError(
                f"Public key hash {spki_hash} not in pinned set. "
                f"This could indicate a MITM attack or certificate change."
            )
        
        return True

# Usage - pins that survive certificate renewal
API_SPKI_PINS = {
    # Primary key (used across multiple certificate renewals)
    "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=",
    # Backup key (for emergency rotation)
    "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
    # CA public key (pin the issuer for additional security)
    "hI0z9TjTa9Xq+PnBW4J9vKvp+Pq8dqLRFzXsLxJwXqI=",
}

pinner = PublicKeyPinner(API_SPKI_PINS)
```

### 3. Certificate Authority Pinning

Pin the intermediate or root CA certificate/key.

**Advantages**:

- No updates needed for individual certificate rotation
- Reasonable security improvement
- Lower operational burden

**Disadvantages**:

- Less protection than endpoint pinning
- Still vulnerable if CA is compromised
- Doesn't protect against CA mis-issuance

**Use case**: Balance between security and operational flexibility.

```python
class CAPinner:
    """
    Pin Certificate Authority public keys
    """
    
    def __init__(self, ca_spki_hashes: Set[str]):
        self.ca_spki_hashes = ca_spki_hashes
    
    def verify_chain(self, cert_chain: List[bytes]) -> bool:
        """
        Verify at least one certificate in chain has pinned key
        
        Args:
            cert_chain: List of DER-encoded certificates from leaf to root
        """
        pinner = PublicKeyPinner(self.ca_spki_hashes)
        
        # Check each certificate in chain
        for cert_der in cert_chain:
            try:
                spki_hash = pinner.extract_spki_hash(cert_der)
                if spki_hash in self.ca_spki_hashes:
                    return True
            except Exception:
                continue
        
        raise SecurityError(
            "No certificate in chain matches pinned CA keys. "
            "Chain may be compromised or using unexpected CA."
        )

# Pin your organization's CA
INTERNAL_CA_PINS = {
    # Internal Root CA
    "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=",
    # Internal Intermediate CA
    "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
}
```

### 4. Multi-Pin Strategy (BEST PRACTICE)

Combine multiple pins for defense-in-depth and operational flexibility.

**Pin multiple points in the trust chain**:
```python
class MultiPinValidator:
    """
    Validate certificate chain against multiple pin types
    """
    
    def __init__(self, config: PinningConfig):
        self.config = config
    
    def validate_chain(self, cert_chain: List[x509.Certificate]) -> bool:
        """
        Validate using multiple pinning strategies
        """
        results = {
            'leaf_pin': False,
            'intermediate_pin': False,
            'root_pin': False,
        }
        
        # Extract leaf, intermediate, and root
        leaf_cert = cert_chain[0]
        intermediate_certs = cert_chain[1:-1]
        root_cert = cert_chain[-1] if len(cert_chain) > 1 else None
        
        # Check leaf certificate pin
        if self.config.leaf_pins:
            leaf_spki = self._extract_spki_hash(leaf_cert)
            results['leaf_pin'] = leaf_spki in self.config.leaf_pins
        
        # Check intermediate certificate pins
        if self.config.intermediate_pins and intermediate_certs:
            for cert in intermediate_certs:
                inter_spki = self._extract_spki_hash(cert)
                if inter_spki in self.config.intermediate_pins:
                    results['intermediate_pin'] = True
                    break
        
        # Check root certificate pin
        if self.config.root_pins and root_cert:
            root_spki = self._extract_spki_hash(root_cert)
            results['root_pin'] = root_spki in self.config.root_pins
        
        # Apply validation policy
        return self._apply_policy(results)
    
    def _apply_policy(self, results: dict) -> bool:
        """
        Apply pinning policy (e.g., require leaf OR intermediate pin)
        """
        if self.config.policy == 'strict':
            # Require leaf pin AND (intermediate OR root) pin
            return results['leaf_pin'] and (
                results['intermediate_pin'] or results['root_pin']
            )
        elif self.config.policy == 'balanced':
            # Require any two pins to match
            return sum(results.values()) >= 2
        elif self.config.policy == 'flexible':
            # Require at least one pin to match
            return any(results.values())
        
        raise ValueError(f"Unknown policy: {self.config.policy}")

# Configuration example
config = PinningConfig(
    leaf_pins={
        "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=",  # Primary
        "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",  # Backup
    },
    intermediate_pins={
        "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",  # Your CA
    },
    root_pins={
        "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=",  # Your Root CA
    },
    policy='balanced'  # Any two pins must match
)
```

## Platform-Specific Implementation

### iOS (Swift)

**Using `NSPinnedDomains` in `Info.plist`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSPinnedDomains</key>
        <dict>
            <key>api.example.com</key>
            <dict>
                <key>NSIncludesSubdomains</key>
                <true/>
                <key>NSPinnedLeafIdentities</key>
                <array>
                    <dict>
                        <key>SPKI-SHA256-BASE64</key>
                        <string>X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=</string>
                    </dict>
                    <dict>
                        <key>SPKI-SHA256-BASE64</key>
                        <string>58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=</string>
                    </dict>
                </array>
                <key>NSPinnedCAIdentities</key>
                <array>
                    <dict>
                        <key>SPKI-SHA256-BASE64</key>
                        <string>YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</string>
                    </dict>
                </array>
            </dict>
        </dict>
    </dict>
</dict>
</plist>
```

**Manual implementation with `URLSession`**:
```swift
import Foundation
import Security

class CertificatePinner: NSObject, URLSessionDelegate {
    // SHA-256 hashes of pinned public keys (base64 encoded)
    private let pinnedKeys: Set<String> = [
        "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=",
        "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
    ]
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Only handle server trust challenges
        guard challenge.protectionSpace.authenticationMethod == 
              NSURLAuthenticationMethodServerTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Validate pin
        if validatePins(serverTrust: serverTrust) {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            // Pin validation failed - reject connection
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    private func validatePins(serverTrust: SecTrust) -> Bool {
        // Get certificate chain
        let certificateCount = SecTrustGetCertificateCount(serverTrust)
        
        // Check each certificate in chain
        for index in 0..<certificateCount {
            guard let certificate = SecTrustGetCertificateAtIndex(serverTrust, index) else {
                continue
            }
            
            // Extract public key
            guard let publicKey = SecCertificateCopyKey(certificate) else {
                continue
            }
            
            // Get public key data
            guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                continue
            }
            
            // Hash the public key
            let publicKeyHash = sha256(data: publicKeyData)
            let publicKeyHashBase64 = publicKeyHash.base64EncodedString()
            
            // Check if this key is pinned
            if pinnedKeys.contains(publicKeyHashBase64) {
                return true
            }
        }
        
        return false
    }
    
    private func sha256(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
}

// Usage
let pinner = CertificatePinner()
let sessionConfig = URLSessionConfiguration.default
let session = URLSession(
    configuration: sessionConfig,
    delegate: pinner,
    delegateQueue: nil
)
```

### Android (Kotlin)

**Declarative pinning with Network Security Configuration**:
```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Pin specific domain -->
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <!-- Primary key -->
            <pin digest="SHA-256">X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=</pin>
            <!-- Backup key -->
            <pin digest="SHA-256">58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=</pin>
            <!-- CA key for flexibility -->
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
</application>
```

**Programmatic pinning with OkHttp**:
```kotlin
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

class SecureApiClient {
    private val certificatePinner = CertificatePinner.Builder()
        .add(
            "api.example.com",
            "sha256/X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=",  // Primary
            "sha256/58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",  // Backup
            "sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="   // CA
        )
        .build()
    
    private val client = OkHttpClient.Builder()
        .certificatePinner(certificatePinner)
        .build()
    
    fun makeSecureRequest(url: String): String {
        val request = Request.Builder()
            .url(url)
            .build()
        
        return try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw IOException("Unexpected response: $response")
                }
                response.body?.string() ?: ""
            }
        } catch (e: SSLPeerUnverifiedException) {
            // Certificate pinning failure
            Log.e("SecureApi", "Certificate pinning failed", e)
            throw SecurityException("Certificate validation failed - possible MITM attack")
        }
    }
}
```

### Web Browsers (HTTP Public Key Pinning - DEPRECATED)

**WARNING**: HPKP is deprecated and removed from modern browsers due to operational risks.

```http
# DO NOT USE - Shown for historical context only
Public-Key-Pins: 
    pin-sha256="X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE="; 
    pin-sha256="58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU="; 
    max-age=5184000; 
    includeSubDomains
```

**Why HPKP was deprecated**:

- Pin misconfiguration could permanently break websites
- No safe recovery mechanism if all pinned keys lost
- Limited adoption due to risk
- Better alternatives (Certificate Transparency, Expect-CT)

**Modern alternative - Certificate Transparency**:
```http
Expect-CT: max-age=86400, enforce, report-uri="https://example.com/ct-report"
```

### Python (requests library)

```python
import requests
import ssl
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

class PinnedHTTPAdapter(HTTPAdapter):
    """
    HTTP adapter that validates certificate pins
    """
    
    def __init__(self, pinned_spki_hashes, *args, **kwargs):
        self.pinned_spki_hashes = pinned_spki_hashes
        super().__init__(*args, **kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        # Create SSL context with custom verification
        context = create_urllib3_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Store original verify function
        original_verify = context.check_hostname
        
        # Wrap with pin verification
        def verify_with_pins(cert, hostname):
            # First do normal verification
            if not original_verify(cert, hostname):
                return False
            
            # Then verify pins
            return self._verify_pins(cert)
        
        context.check_hostname = verify_with_pins
        kwargs['ssl_context'] = context
        
        return super().init_poolmanager(*args, **kwargs)
    
    def _verify_pins(self, cert):
        """
        Verify certificate's SPKI hash against pins
        """
        # Extract SPKI and hash it
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        
        cert_obj = x509.load_der_x509_certificate(cert, default_backend())
        public_key = cert_obj.public_key()
        
        spki_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        spki_hash = hashlib.sha256(spki_der).digest()
        spki_hash_b64 = base64.b64encode(spki_hash).decode('ascii')
        
        if spki_hash_b64 not in self.pinned_spki_hashes:
            raise ssl.SSLError(
                f"Certificate pin validation failed. "
                f"Expected one of {self.pinned_spki_hashes}, "
                f"got {spki_hash_b64}"
            )
        
        return True

# Usage
pinned_hashes = {
    "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=",
    "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
}

session = requests.Session()
session.mount('https://', PinnedHTTPAdapter(pinned_hashes))

# Make pinned requests
response = session.get('https://api.example.com/data')
```

## Certificate Rotation with Pinning

### The Fundamental Challenge

Certificate pinning creates an operational challenge: how do you rotate certificates without breaking deployed applications?

**The problem**:
```
Day 0:  Deploy app with pinned certificate (expires in 1 year)
Day 365: Certificate expires
Day 366: All apps stop working until users update

Result: Service outage for users who haven't updated
```

### Strategy 1: Multiple Pins (Recommended)

Always pin at least 2 keys: current and future.

```python
class RotationFriendlyPinner:
    """
    Pinner designed for graceful rotation
    """
    
    def __init__(self):
        # Always maintain current + next key
        self.pins = {
            'current': "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=",
            'next': "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
        }
    
    def validate(self, spki_hash: str) -> bool:
        """Accept any pinned key"""
        return spki_hash in self.pins.values()

# Rotation process:
# 1. Deploy app with pins: [current, next]
# 2. When ready to rotate:
#    a. Issue new certificate using 'next' key
#    b. Generate new 'next+1' key
#    c. Deploy app update with pins: [next, next+1]
#    d. Old apps still work (they accept 'next' key)
# 3. After sufficient adoption, old key can be retired
```

**Rotation timeline**:
```
Month 0:  App v1.0 released
          Pins: [Key-A, Key-B]
          Server uses: Key-A

Month 11: App v1.1 released  
          Pins: [Key-B, Key-C]
          Server uses: Key-A (still works for v1.0 and v1.1)

Month 12: Sufficient adoption of v1.1 (e.g., 80%)
          Server rotates to: Key-B
          v1.0 and v1.1 both work

Month 23: App v1.2 released
          Pins: [Key-C, Key-D]
          Server uses: Key-B

Month 24: High adoption of v1.2
          Server rotates to: Key-C
          v1.0 stops working (acceptable - 1 year old)
          v1.1 and v1.2 work
```

### Strategy 2: Pin CA Instead of Leaf

Pin the CA certificate, avoiding need to update pins for each rotation.

```python
# Pin your organization's CA
CA_PINS = {
    "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",  # Internal CA
}

# Leaf certificates can rotate freely as long as issued by pinned CA
# Trade-off: Less security than leaf pinning
```

### Strategy 3: Dynamic Pin Updates

Update pins dynamically via secure channel.

**WARNING**: This approach has security implications.

```python
class DynamicPinner:
    """
    Update pins from server (use with extreme caution)
    """
    
    def __init__(self, bootstrap_pins: Set[str]):
        self.pins = bootstrap_pins
        self.pin_update_url = "https://api.example.com/.well-known/pin-updates"
    
    async def update_pins(self):
        """
        Fetch new pins from server
        
        CRITICAL: This request must itself be pinned to bootstrap pins
        """
        # Use bootstrap pins for this request
        async with PinnedSession(self.pins) as session:
            response = await session.get(self.pin_update_url)
            
            # Response must be signed by trusted key
            pin_update = await self.verify_signature(response)
            
            # Validate new pins
            if self.validate_pin_update(pin_update):
                self.pins.update(pin_update['new_pins'])
                
                # Persist to local storage
                await self.save_pins()
    
    def validate_pin_update(self, update: dict) -> bool:
        """
        Validate pin update for security
        """
        # Must always include at least one current pin
        if not any(pin in self.pins for pin in update['new_pins']):
            raise SecurityError(
                "Pin update must include at least one current pin"
            )
        
        # Must not remove all pins
        if len(update['new_pins']) == 0:
            raise SecurityError("Cannot remove all pins")
        
        # Signature must be valid
        if not update['signature_valid']:
            raise SecurityError("Invalid signature on pin update")
        
        return True
```

**Risks of dynamic updates**:

- If update mechanism is compromised, attacker can inject pins
- Creates additional attack surface
- Defeats purpose of pinning if not carefully implemented
- Only use if combined with:

  - Digital signatures on updates
  - Never removing all existing pins
  - Rate limiting and anomaly detection

### Strategy 4: Expiration-Aware Pinning

Build expiration awareness into the app.

```python
from datetime import datetime, timedelta

class ExpirationAwarePinner:
    """
    Gracefully handle pin expiration
    """
    
    def __init__(self):
        self.pins = {
            "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=": {
                'expires': datetime(2025, 12, 31),
                'status': 'active',
            },
            "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=": {
                'expires': datetime(2026, 6, 30),
                'status': 'future',
            },
        }
    
    def validate(self, spki_hash: str) -> bool:
        """
        Validate pin with expiration awareness
        """
        if spki_hash not in self.pins:
            return False
        
        pin_info = self.pins[spki_hash]
        
        # Check expiration
        if datetime.now() > pin_info['expires']:
            # Pin has expired
            if self.should_enforce_after_expiration():
                # Strict mode - reject
                return False
            else:
                # Grace period - accept but warn
                self.log_warning(
                    f"Using expired pin {spki_hash}. "
                    f"Expired: {pin_info['expires']}"
                )
                return True
        
        return True
    
    def should_enforce_after_expiration(self) -> bool:
        """
        Decide whether to enforce pinning after expiration
        """
        # Check if app is outdated
        app_age = datetime.now() - self.app_install_date
        
        if app_age > timedelta(days=180):
            # Old app - don't enforce (avoid breaking old clients)
            return False
        else:
            # Recent app - enforce
            return True
```

## Operational Considerations

### Generating Pins

**Extract SPKI hash from certificate file**:
```bash
#!/bin/bash
# Extract and hash Subject Public Key Info

# For a certificate file
openssl x509 -in cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform DER | \
    openssl dgst -sha256 -binary | \
    base64

# For a website's certificate
openssl s_client -connect api.example.com:443 -servername api.example.com < /dev/null 2>/dev/null | \
    openssl x509 -pubkey -noout | \
    openssl pkey -pubin -outform DER | \
    openssl dgst -sha256 -binary | \
    base64

# For entire certificate chain
echo | openssl s_client -connect api.example.com:443 -showcerts 2>/dev/null | \
    awk '/BEGIN CERT/,/END CERT/ {print}' | \
    while read -r cert; do
        echo "$cert" | openssl x509 -pubkey -noout | \
            openssl pkey -pubin -outform DER | \
            openssl dgst -sha256 -binary | \
            base64
    done
```

**Generate backup pins before deploying**:
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
import base64

def generate_backup_key_pin() -> tuple[str, bytes]:
    """
    Generate a backup key pair and return the pin
    
    Returns:
        (pin_hash, private_key_pem)
    """
    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Extract public key
    public_key = private_key.public_key()
    
    # Serialize to SPKI format
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Hash and encode
    spki_hash = hashlib.sha256(spki_der).digest()
    pin = base64.b64encode(spki_hash).decode('ascii')
    
    # Export private key for safekeeping
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'strong-password')
    )
    
    return pin, private_key_pem

# Generate backup key BEFORE deploying app
backup_pin, backup_key = generate_backup_key_pin()
print(f"Backup pin: {backup_pin}")
print("Store backup key in HSM or secure key vault")
```

### Testing Pinning

**Test harness for pin validation**:
```python
import pytest
from unittest.mock import Mock, patch

class TestCertificatePinning:
    """
    Test suite for certificate pinning
    """
    
    def test_valid_pin_accepted(self):
        """Valid pin should be accepted"""
        pinner = PublicKeyPinner({"X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE="})
        
        # Mock valid certificate with matching pin
        valid_cert = self.create_test_cert_with_pin(
            "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE="
        )
        
        assert pinner.verify_certificate(valid_cert) == True
    
    def test_invalid_pin_rejected(self):
        """Invalid pin should be rejected"""
        pinner = PublicKeyPinner({"X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE="})
        
        # Mock certificate with different pin
        invalid_cert = self.create_test_cert_with_pin(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        )
        
        with pytest.raises(SecurityError):
            pinner.verify_certificate(invalid_cert)
    
    def test_multiple_pins_any_valid(self):
        """If multiple pins configured, any valid pin should work"""
        pins = {
            "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE=",
            "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
        }
        pinner = PublicKeyPinner(pins)
        
        # Test with second pin
        cert = self.create_test_cert_with_pin(
            "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU="
        )
        
        assert pinner.verify_certificate(cert) == True
    
    def test_expired_pin_handling(self):
        """Test behavior when pin has expired"""
        pinner = ExpirationAwarePinner()
        
        # Mock expired pin
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = datetime(2026, 1, 1)
            
            cert = self.create_test_cert_with_pin(
                "X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE="
            )
            
            # Should log warning but accept in grace period
            assert pinner.validate(cert) == True
    
    def test_mitm_certificate_rejected(self):
        """Certificate from rogue CA should be rejected despite valid chain"""
        pinner = PublicKeyPinner({"X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE="})
        
        # Mock certificate with valid signature but wrong pin
        mitm_cert = self.create_mitm_cert()
        
        with pytest.raises(SecurityError) as exc:
            pinner.verify_certificate(mitm_cert)
        
        assert "possible MITM attack" in str(exc.value).lower()
```

**Integration testing with production endpoints**:
```bash
#!/bin/bash
# Test pinning against live endpoints

set -e

API_HOST="api.example.com"
EXPECTED_PIN="X3pGTSOuJeEVw989IJ/cEtXUEmy52zs1lkJZdZNg5iE="

echo "Testing certificate pinning for $API_HOST..."

# Get actual pin
ACTUAL_PIN=$(echo | openssl s_client -connect $API_HOST:443 -servername $API_HOST < /dev/null 2>/dev/null | \
    openssl x509 -pubkey -noout | \
    openssl pkey -pubin -outform DER | \
    openssl dgst -sha256 -binary | \
    base64)

echo "Expected pin: $EXPECTED_PIN"
echo "Actual pin:   $ACTUAL_PIN"

if [ "$ACTUAL_PIN" = "$EXPECTED_PIN" ]; then
    echo "✓ Pin matches"
    exit 0
else
    echo "✗ Pin mismatch - pinning will fail in production!"
    exit 1
fi
```

### Monitoring and Alerting

**Pin validation metrics**:
```python
from prometheus_client import Counter, Histogram

# Metrics
pin_validation_total = Counter(
    'cert_pin_validation_total',
    'Total certificate pin validations',
    ['result', 'domain']
)

pin_validation_duration = Histogram(
    'cert_pin_validation_duration_seconds',
    'Time spent validating pins',
    ['domain']
)

class MonitoredPinner:
    """
    Pinner with observability
    """
    
    def __init__(self, pins: Set[str], domain: str):
        self.pinner = PublicKeyPinner(pins)
        self.domain = domain
    
    def verify_certificate(self, cert_der: bytes) -> bool:
        """
        Verify with metrics
        """
        with pin_validation_duration.labels(domain=self.domain).time():
            try:
                result = self.pinner.verify_certificate(cert_der)
                pin_validation_total.labels(
                    result='success',
                    domain=self.domain
                ).inc()
                return result
            except SecurityError as e:
                pin_validation_total.labels(
                    result='failure',
                    domain=self.domain
                ).inc()
                
                # Log detailed error
                logger.error(
                    "Certificate pin validation failed",
                    extra={
                        'domain': self.domain,
                        'error': str(e),
                        'cert_hash': self.pinner.extract_spki_hash(cert_der),
                        'expected_pins': list(self.pinner.pinned_spki_hashes),
                    }
                )
                raise
```

**Alert on pin mismatches**:
```yaml
# Prometheus alerting rule
groups:
  - name: certificate_pinning
    rules:
      - alert: CertificatePinFailure
        expr: |
          rate(cert_pin_validation_total{result="failure"}[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Certificate pin validation failures detected"
          description: |
            Pin validation failing for {{ $labels.domain }}.
            Rate: {{ $value | humanize }}
            This could indicate:
            - Certificate rotation without pin update
            - MITM attack in progress
            - Misconfigured pinning
            
      - alert: CertificatePinNearExpiry
        expr: |
          cert_pin_expiry_days < 30
        labels:
          severity: warning
        annotations:
          summary: "Pinned certificate expiring soon"
          description: |
            Pinned certificate for {{ $labels.domain }} expires in {{ $value }} days.
            Action required:
            1. Generate new key pair
            2. Update app with new pin
            3. Deploy updated app
            4. Rotate certificate after sufficient adoption
```

### Incident Response

**Pin validation failure runbook**:

```markdown
# Incident: Certificate Pin Validation Failures

## Symptoms
- Apps unable to connect to API
- "Certificate validation failed" errors
- Spike in pin validation failures

## Triage Steps

### 1. Verify Scope
```bash
# Check error rate by domain
curl '[Prometheus:9090 - Query](http://prometheus:9090/api/v1/query?query=rate(cert_pin_validation_total{result="failure"}[5m]))'
```

### 2. Check Certificate Status
```bash
# Verify current certificate matches expected pin
./scripts/check-pins.sh api.example.com
```

### 3. Determine Root Cause

**Scenario A: Legitimate Certificate Rotation**
- Certificate was rotated but app pins not updated
- **Impact**: All app versions with old pins broken
- **Resolution**: Rollback certificate OR emergency app update

**Scenario B: MITM Attack**
- Unexpected certificate with different pin
- **Impact**: Varies by attack scope
- **Resolution**: Investigate, do not weaken pinning

**Scenario C: Pin Misconfiguration**
- Wrong pins deployed in app update
- **Impact**: New app version broken
- **Resolution**: Emergency app update with correct pins

### 4. Remediation Actions

**If legitimate rotation (Scenario A)**:
```bash
# Option 1: Rollback certificate (fastest)
kubectl rollout undo deployment/api-server

# Option 2: Emergency app update (if rollback not possible)
# 1. Build app with updated pins
# 2. Fast-track through app stores
# 3. Force update if critical

# Option 3: Temporarily disable pinning (LAST RESORT)
# Only if user impact severe and no other option
```

**If MITM attack suspected (Scenario B)**:
```bash
# DO NOT disable pinning
# Investigate:
# - Check certificate chain
# - Verify DNS not hijacked
# - Check for rogue CA certificates on devices
# - Review network logs
```

## Prevention

1. **Always maintain backup pins** in deployed apps
2. **Test pins before certificate rotation**
3. **Gradual rollout** of certificate changes
4. **Monitor pin validation metrics** continuously
5. **Document rotation procedures**
```

## Security Considerations

### Threats Mitigated by Pinning

**Compromised Certificate Authority**:
```
Without pinning:
  Attacker compromises CA → Issues rogue cert → MITM attack succeeds

With pinning:
  Attacker compromises CA → Issues rogue cert → App rejects cert (wrong pin)
```

**Rogue Root Certificate Installation**:
```
Without pinning:
  Malware installs root CA → Issues cert for your domain → Intercepts traffic

With pinning:
  Malware installs root CA → Issues cert → App rejects (not pinned)
```

**Government/Corporate Network Interception**:
```
Without pinning:
  Corporate proxy uses trusted CA → Intercepts HTTPS → User unaware

With pinning:
  Corporate proxy certificate rejected → Connection fails → User alerted
```

### Threats NOT Mitigated

**Pinning does NOT protect against**:

- Application-level attacks (SQL injection, XSS, etc.)
- Compromised application code
- Stolen API keys or credentials
- Attacks before SSL/TLS handshake
- Physical device compromise (attacker can modify app)

### Operational Risks

**Risk 1: Pin Lockout**
```
Scenario: All pinned keys lost/compromised, no backup
Impact: Application permanently broken until update deployed
Mitigation: Always maintain backup pins, test rotation procedures
```

**Risk 2: Delayed Updates**
```
Scenario: Users don't update apps, pins expire
Impact: Old app versions stop working
Mitigation: Server-side grace period, push notifications, forced updates
```

**Risk 3: Development Complications**
```
Scenario: Developers use different certificates (dev, staging, prod)
Impact: Pinning breaks in non-production environments
Mitigation: Environment-specific pins, build-time configuration
```

### Best Practices Summary

**DO**:

- ✅ Pin public keys (SPKI), not full certificates
- ✅ Maintain multiple pins (current + backup)
- ✅ Pin both leaf and intermediate/root certificates
- ✅ Test pinning thoroughly before production
- ✅ Monitor pin validation metrics
- ✅ Document rotation procedures
- ✅ Use expiration awareness in apps
- ✅ Generate backup keys before deployment

**DON'T**:

- ❌ Pin only one certificate
- ❌ Use HPKP (deprecated)
- ❌ Deploy without backup pins
- ❌ Rotate certificates without updating pins
- ❌ Use dynamic pin updates without signatures
- ❌ Ignore pin validation failures
- ❌ Disable pinning in production (except absolute emergency)

## Real-World Examples

### Case Study 1: Twitter (2012)

**Challenge**: Protect against compromised CAs after DigiNotar incident

**Solution**:

- Implemented certificate pinning in Twitter iOS app
- Pinned both leaf certificates and CA keys
- Maintained multiple pins for rotation flexibility

**Outcome**:

- Successfully detected and blocked MITM attempts
- Set industry example for mobile app security

### Case Study 2: Google Chrome

**Implementation**: Chrome pins Google domains
```cpp
// Chromium source code (simplified)
static const char* kGooglePins[] = {
  "sha256/4BjDjn8v2lWeUFQnqSs0BgbIcrU9LosQWGDWzQ=",
  "sha256/GUAL5bejH7czkXcAeJ0vCiRxwMnVBsDlBMBsFtfLF8A=",
  // ... multiple backup pins
};
```

**Results**:

- Protected hundreds of millions of users
- Detected multiple MITM attempts
- Influenced industry to adopt pinning

### Case Study 3: Banking App Implementation

**Requirements**:

- Protect customer financial data
- Meet PCI-DSS requirements
- Support certificate rotation

**Architecture**:
```
Mobile App Pinning Strategy:
├── Primary API pin (current certificate)
├── Backup API pin (prepared for rotation)
├── CA pin (intermediate CA)
└── Root CA pin (ultimate fallback)

Rotation Process:
├── 90 days before expiry: Generate new key pair
├── 60 days before: Deploy app update with new backup pin
├── 30 days before: Monitor app adoption
├── Rotation day: Switch to new certificate
└── 90 days after: Remove old pin from next app version
```

**Results**:

- Zero outages during multiple rotations
- Detected 3 MITM attempts in corporate environments
- Achieved PCI-DSS compliance

## Tools and Libraries

### iOS
- **Built-in**: `NSPinnedDomains` (iOS 14+)
- **TrustKit**: Full-featured pinning framework
- **Alamofire**: Network library with pinning support

### Android
- **Built-in**: Network Security Configuration (API 24+)
- **OkHttp**: `CertificatePinner` class
- **Conscrypt**: Advanced SSL provider

### Web
- **Certificate Transparency**: Modern alternative to HPKP
- **Expect-CT**: Enforce CT logging
- **React Native**: `react-native-ssl-pinning`

### Backend
- **Python**: `requests` with custom adapter
- **Node.js**: `tls.connect()` with checkServerIdentity
- **Go**: `tls.Config` with `VerifyPeerCertificate`

## Further Reading

### Standards
- RFC 7469: Public Key Pinning Extension for HTTP (HPKP - deprecated)
- RFC 6797: HTTP Strict Transport Security (HSTS)
- RFC 6962: Certificate Transparency

### Documentation
- OWASP Certificate Pinning Cheat Sheet
- Apple App Transport Security documentation
- Android Network Security Configuration guide

### Research Papers
- "The Risks of SSL Inspection" (2016)
- "Certificate Pinning in Practice" (2014)
- "Analysis of the HTTPS Certificate Ecosystem" (2013)

---

**See Also**: [Common Vulnerabilities](common-vulnerabilities.md), [Trust Models](../foundations/trust-models.md), [Tls Protocol](../standards/tls-protocol.md), [Private Key Protection](private-key-protection.md)
