# ACME Protocol Implementation

## TL;DR

ACME (Automated Certificate Management Environment) is the protocol that revolutionized PKI by enabling fully automated certificate issuance and renewal without human intervention. Implementing an ACME server involves building a complete certificate authority with account management, order processing, challenge validation (DNS-01, HTTP-01, TLS-ALPN-01), certificate issuance, and renewal workflows. The reference implementation (Boulder, used by Let's Encrypt) demonstrates production-grade architecture with multi-tier validation, rate limiting, database design for high availability, monitoring, and security controls. Organizations implement ACME servers for private PKI, regulatory compliance requiring private CAs, custom validation logic, specialized certificate types, and air-gapped environments. The protocol's elegant design separates concerns (account ↔ order ↔ authorization ↔ challenge), uses cryptographic account binding, and supports automated domain validation at scale.

**Key Insight**: ACME succeeds because it inverts traditional PKI assumptions—instead of building for human-in-the-loop manual processes with automation as an afterthought, it assumes fully automated machine-driven workflows with human intervention as the exception. This fundamental design choice enables modern cloud-native architectures and short-lived certificate strategies.

---

## Overview

ACME (RFC 8555) defines a protocol between certificate applicants and certificate authorities that enables fully automated certificate lifecycle management. The protocol uses HTTPS + JSON and cryptographic signatures for all operations.

**Core ACME Concepts**:
1. **Account** - Identity used across all ACME operations, bound to public key
2. **Order** - Request for certificate covering specific identifiers
3. **Authorization** - Proof of control required for each identifier
4. **Challenge** - Method used to prove control (DNS, HTTP, TLS-ALPN)
5. **Certificate** - Final artifact delivered after successful validation

**Protocol Flow**:
```
Client                                                    Server
  |                                                          |
  |--- Create Account (with public key) ------------------->|
  |<-- Account URL + status --------------------------------|
  |                                                          |
  |--- Create Order (with identifiers) -------------------->|
  |<-- Order URL + authorization URLs ----------------------|
  |                                                          |
  |--- Fetch Authorization (for each identifier) ---------->|
  |<-- Challenge options (DNS-01, HTTP-01, TLS-ALPN-01) ---|
  |                                                          |
  |--- Complete Challenge (place validation token) -------->|
  |<-- Challenge accepted ----------------------------------|
  |                                                          |
  |--- Notify CA (challenge ready) ----------------------->|
  |<-- Server validates asynchronously --------------------|
  |                                                          |
  |--- Poll Authorization (check status) ----------------->|
  |<-- Status: valid ----------------------------------------|
  |                                                          |
  |--- Finalize Order (submit CSR) ----------------------->|
  |<-- Order status: processing -----------------------------|
  |                                                          |
  |--- Poll Order (wait for certificate) ----------------->|
  |<-- Certificate URL -------------------------------------|
  |                                                          |
  |--- Download Certificate -------------------------------->|
  |<-- Certificate chain ------------------------------------|
```

---

## Server Architecture

### Component Overview

Production ACME servers consist of multiple specialized components:

```
                    ┌─────────────────┐
                    │   Load Balancer │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐    ┌────▼────┐   ┌────▼────┐
         │  ACME   │    │  ACME   │   │  ACME   │
         │  API    │    │  API    │   │  API    │
         │ Server  │    │ Server  │   │ Server  │
         └────┬────┘    └────┬────┘   └────┬────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │   Message Queue  │
                    │   (RabbitMQ)    │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐    ┌────▼────┐   ┌────▼────┐
         │Challenge│    │Challenge│   │Challenge│
         │Validator│    │Validator│   │Validator│
         └────┬────┘    └────┬────┘   └────┬────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │   PostgreSQL    │
                    │   (Primary +    │
                    │    Replicas)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   CA Signer     │
                    │   (with HSM)    │
                    └─────────────────┘
```

**Components**:
1. **API Server** - Handles ACME requests, enforces rate limits, manages sessions
2. **Validator** - Performs challenge validation asynchronously
3. **Signer** - Interfaces with HSM for certificate signing
4. **Database** - Stores accounts, orders, authorizations, certificates
5. **Message Queue** - Decouples API from validation for scalability
6. **Monitoring** - Tracks metrics, alerts, audit logs

### Database Schema

Core tables for ACME server:

```sql
-- Accounts table
CREATE TABLE accounts (
    id BIGSERIAL PRIMARY KEY,
    key_id TEXT NOT NULL UNIQUE,  -- JWK thumbprint
    jwk JSONB NOT NULL,            -- Account public key
    contact TEXT[],                -- Email addresses
    status VARCHAR(20) NOT NULL,   -- valid, deactivated, revoked
    terms_agreed BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_status CHECK (status IN ('valid', 'deactivated', 'revoked'))
);

CREATE INDEX idx_accounts_key_id ON accounts(key_id);
CREATE INDEX idx_accounts_status ON accounts(status);

-- Orders table
CREATE TABLE orders (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts(id),
    status VARCHAR(20) NOT NULL,   -- pending, ready, processing, valid, invalid
    expires TIMESTAMP NOT NULL,
    identifiers JSONB NOT NULL,    -- Array of {type, value}
    not_before TIMESTAMP,
    not_after TIMESTAMP,
    error JSONB,
    certificate_serial TEXT,       -- Once issued
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_status CHECK (status IN ('pending', 'ready', 'processing', 'valid', 'invalid'))
);

CREATE INDEX idx_orders_account ON orders(account_id);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_expires ON orders(expires);

-- Authorizations table
CREATE TABLE authorizations (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts(id),
    identifier_type VARCHAR(10) NOT NULL,  -- dns, ip
    identifier_value TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,           -- pending, valid, invalid, deactivated, expired, revoked
    expires TIMESTAMP NOT NULL,
    wildcard BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    validated_at TIMESTAMP,
    CONSTRAINT valid_status CHECK (status IN ('pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked'))
);

CREATE INDEX idx_authz_account ON authorizations(account_id);
CREATE INDEX idx_authz_identifier ON authorizations(identifier_type, identifier_value);
CREATE INDEX idx_authz_status ON authorizations(status);
CREATE UNIQUE INDEX idx_authz_unique ON authorizations(account_id, identifier_type, identifier_value, wildcard)
    WHERE status IN ('pending', 'valid');

-- Challenges table
CREATE TABLE challenges (
    id BIGSERIAL PRIMARY KEY,
    authorization_id BIGINT NOT NULL REFERENCES authorizations(id),
    type VARCHAR(20) NOT NULL,     -- http-01, dns-01, tls-alpn-01
    status VARCHAR(20) NOT NULL,    -- pending, processing, valid, invalid
    token TEXT NOT NULL,
    validated TIMESTAMP,
    error JSONB,
    validation_record JSONB,       -- Store validation details
    CONSTRAINT valid_type CHECK (type IN ('http-01', 'dns-01', 'tls-alpn-01')),
    CONSTRAINT valid_status CHECK (status IN ('pending', 'processing', 'valid', 'invalid'))
);

CREATE INDEX idx_challenges_authz ON challenges(authorization_id);
CREATE INDEX idx_challenges_status ON challenges(status);
CREATE INDEX idx_challenges_type ON challenges(type);

-- Order-Authorization junction
CREATE TABLE order_authorizations (
    order_id BIGINT NOT NULL REFERENCES orders(id),
    authorization_id BIGINT NOT NULL REFERENCES authorizations(id),
    PRIMARY KEY (order_id, authorization_id)
);

-- Certificates table
CREATE TABLE certificates (
    serial TEXT PRIMARY KEY,
    der BYTEA NOT NULL,             -- Certificate in DER format
    issued_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires TIMESTAMP NOT NULL,
    account_id BIGINT NOT NULL REFERENCES accounts(id),
    order_id BIGINT REFERENCES orders(id),
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP,
    revocation_reason INT
);

CREATE INDEX idx_certificates_account ON certificates(account_id);
CREATE INDEX idx_certificates_expires ON certificates(expires);
CREATE INDEX idx_certificates_revoked ON certificates(revoked);

-- Rate limiting table
CREATE TABLE rate_limits (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT REFERENCES accounts(id),
    ip_address INET,
    limit_name VARCHAR(50) NOT NULL,
    count INT NOT NULL DEFAULT 1,
    window_start TIMESTAMP NOT NULL,
    window_end TIMESTAMP NOT NULL
);

CREATE INDEX idx_rate_limits_account ON rate_limits(account_id, limit_name, window_end);
CREATE INDEX idx_rate_limits_ip ON rate_limits(ip_address, limit_name, window_end);
```

---

## Account Management

### Account Creation

ACME accounts are bound to public keys, not usernames/passwords:

```python
from josepy import jwk
from acme import messages, client
import json

class ACMEAccountManager:
    """Handle ACME account operations"""
    
    def create_account(self, jwk_key, contact_emails, terms_agreed):
        """Create new ACME account"""
        
        # Calculate key ID (JWK thumbprint)
        key_id = self.calculate_key_id(jwk_key)
        
        # Check for existing account
        existing = self.db.execute(
            "SELECT id FROM accounts WHERE key_id = %s",
            (key_id,)
        ).fetchone()
        
        if existing:
            raise ConflictError(f"Account already exists: {key_id}")
        
        # Verify terms agreed
        if not terms_agreed:
            raise ValueError("Must agree to terms of service")
        
        # Insert account
        account_id = self.db.execute(
            """
            INSERT INTO accounts (key_id, jwk, contact, status, terms_agreed)
            VALUES (%s, %s, %s, 'valid', TRUE)
            RETURNING id
            """,
            (key_id, json.dumps(jwk_key.to_json()), contact_emails)
        ).fetchone()[0]
        
        self.db.commit()
        
        # Generate account URL
        account_url = f"{self.base_url}/acme/acct/{account_id}"
        
        self.audit_log.log_account_created(account_id, key_id, contact_emails)
        
        return {
            'id': account_id,
            'key': jwk_key,
            'contact': contact_emails,
            'status': 'valid',
            'orders': f"{account_url}/orders"
        }, account_url
    
    def calculate_key_id(self, jwk_key):
        """Calculate JWK thumbprint for account identification"""
        import hashlib
        import base64
        
        # Get canonical JWK representation
        canonical = jwk_key.thumbprint()
        
        # SHA-256 hash
        digest = hashlib.sha256(canonical).digest()
        
        # Base64url encode
        key_id = base64.urlsafe_b64encode(digest).decode().rstrip('=')
        
        return key_id
```

### Account Key Rollover

Allowing account key changes while maintaining account history:

```python
def rollover_account_key(self, account_id, old_jwk, new_jwk, signed_request):
    """Roll over account key to new key"""
    
    # Verify request signed by old key
    if not self.verify_signature(signed_request, old_jwk):
        raise UnauthorizedError("Invalid signature with old key")
    
    # Verify inner request signed by new key
    inner = json.loads(signed_request['payload'])
    if not self.verify_signature(inner, new_jwk):
        raise UnauthorizedError("Invalid signature with new key")
    
    # Calculate new key ID
    new_key_id = self.calculate_key_id(new_jwk)
    
    # Check new key not already in use
    existing = self.db.execute(
        "SELECT id FROM accounts WHERE key_id = %s",
        (new_key_id,)
    ).fetchone()
    
    if existing:
        raise ConflictError("New key already associated with account")
    
    # Update account
    self.db.execute(
        """
        UPDATE accounts 
        SET key_id = %s, jwk = %s
        WHERE id = %s
        """,
        (new_key_id, json.dumps(new_jwk.to_json()), account_id)
    )
    
    self.db.commit()
    self.audit_log.log_key_rollover(account_id, old_jwk, new_jwk)
    
    return {'status': 'valid', 'key': new_jwk}
```

---

## Order Processing

### Creating Orders

```python
class ACMEOrderProcessor:
    """Process ACME orders"""
    
    def create_order(self, account_id, identifiers, not_before=None, not_after=None):
        """Create new certificate order"""
        
        # Validate identifiers
        for identifier in identifiers:
            if identifier['type'] not in ['dns', 'ip']:
                raise ValueError(f"Unsupported identifier type: {identifier['type']}")
            
            # Validate DNS name format
            if identifier['type'] == 'dns':
                if not self.is_valid_domain(identifier['value']):
                    raise ValueError(f"Invalid domain: {identifier['value']}")
        
        # Check for rate limits
        self.check_rate_limits(account_id, 'orders_per_account')
        
        # Set expiry (7 days standard)
        expires = datetime.utcnow() + timedelta(days=7)
        
        # Create order
        order_id = self.db.execute(
            """
            INSERT INTO orders (account_id, status, expires, identifiers, not_before, not_after)
            VALUES (%s, 'pending', %s, %s, %s, %s)
            RETURNING id
            """,
            (account_id, expires, json.dumps(identifiers), not_before, not_after)
        ).fetchone()[0]
        
        # Create authorizations for each unique identifier
        authz_ids = []
        for identifier in identifiers:
            authz_id = self.create_authorization(
                account_id,
                identifier['type'],
                identifier['value']
            )
            authz_ids.append(authz_id)
            
            # Link to order
            self.db.execute(
                "INSERT INTO order_authorizations (order_id, authorization_id) VALUES (%s, %s)",
                (order_id, authz_id)
            )
        
        self.db.commit()
        
        # Generate order URL
        order_url = f"{self.base_url}/acme/order/{order_id}"
        
        return {
            'status': 'pending',
            'expires': expires.isoformat(),
            'identifiers': identifiers,
            'authorizations': [
                f"{self.base_url}/acme/authz/{authz_id}"
                for authz_id in authz_ids
            ],
            'finalize': f"{order_url}/finalize"
        }, order_url
    
    def create_authorization(self, account_id, identifier_type, identifier_value):
        """Create authorization with challenges"""
        
        # Check for existing valid authorization
        existing = self.db.execute(
            """
            SELECT id FROM authorizations
            WHERE account_id = %s 
              AND identifier_type = %s 
              AND identifier_value = %s
              AND status = 'valid'
              AND expires > NOW()
            """,
            (account_id, identifier_type, identifier_value)
        ).fetchone()
        
        if existing:
            return existing[0]
        
        # Create new authorization
        expires = datetime.utcnow() + timedelta(days=7)
        
        authz_id = self.db.execute(
            """
            INSERT INTO authorizations (account_id, identifier_type, identifier_value, status, expires)
            VALUES (%s, %s, %s, 'pending', %s)
            RETURNING id
            """,
            (account_id, identifier_type, identifier_value, expires)
        ).fetchone()[0]
        
        # Create challenges
        self.create_challenges_for_authorization(authz_id, identifier_type)
        
        return authz_id
    
    def create_challenges_for_authorization(self, authz_id, identifier_type):
        """Create appropriate challenges for identifier type"""
        
        import secrets
        
        # Generate random token
        token = secrets.token_urlsafe(32)
        
        if identifier_type == 'dns':
            # DNS identifiers get all challenge types
            challenge_types = ['http-01', 'dns-01', 'tls-alpn-01']
        elif identifier_type == 'ip':
            # IP identifiers only get http-01 and tls-alpn-01
            challenge_types = ['http-01', 'tls-alpn-01']
        
        for challenge_type in challenge_types:
            self.db.execute(
                """
                INSERT INTO challenges (authorization_id, type, status, token)
                VALUES (%s, %s, 'pending', %s)
                """,
                (authz_id, challenge_type, token)
            )
```

### Finalizing Orders

```python
def finalize_order(self, order_id, account_id, csr_der):
    """Finalize order by submitting CSR"""
    
    # Load order
    order = self.db.execute(
        "SELECT * FROM orders WHERE id = %s AND account_id = %s",
        (order_id, account_id)
    ).fetchone()
    
    if not order:
        raise NotFoundError("Order not found")
    
    if order['status'] != 'ready':
        raise OrderNotReadyError(f"Order status is {order['status']}, must be 'ready'")
    
    # Parse CSR
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    
    csr = x509.load_der_x509_csr(csr_der, default_backend())
    
    # Verify CSR identifiers match order
    csr_names = self.extract_identifiers_from_csr(csr)
    order_names = set(
        identifier['value']
        for identifier in json.loads(order['identifiers'])
    )
    
    if csr_names != order_names:
        raise ValueError("CSR identifiers don't match order")
    
    # Update order status
    self.db.execute(
        "UPDATE orders SET status = 'processing' WHERE id = %s",
        (order_id,)
    )
    self.db.commit()
    
    # Queue certificate generation
    self.queue_certificate_generation(order_id, csr_der)
    
    return {'status': 'processing'}

def generate_certificate(self, order_id, csr_der):
    """Generate and sign certificate"""
    
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from datetime import datetime, timedelta
    
    # Load order
    order = self.db.execute("SELECT * FROM orders WHERE id = %s", (order_id,)).fetchone()
    
    # Parse CSR
    csr = x509.load_der_x509_csr(csr_der, default_backend())
    
    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(self.issuer_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    
    # Set validity
    not_before = order.get('not_before') or datetime.utcnow()
    not_after = order.get('not_after') or (datetime.utcnow() + timedelta(days=90))
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    
    # Copy extensions from CSR
    for extension in csr.extensions:
        builder = builder.add_extension(
            extension.value,
            critical=extension.critical
        )
    
    # Add required extensions
    builder = self.add_required_extensions(builder)
    
    # Sign certificate
    certificate = builder.sign(
        private_key=self.issuer_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    # Store certificate
    serial = format(certificate.serial_number, 'x')
    self.db.execute(
        """
        INSERT INTO certificates (serial, der, expires, account_id, order_id)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (serial, certificate.public_bytes(serialization.Encoding.DER),
         not_after, order['account_id'], order_id)
    )
    
    # Update order
    self.db.execute(
        """
        UPDATE orders 
        SET status = 'valid', certificate_serial = %s 
        WHERE id = %s
        """,
        (serial, order_id)
    )
    
    self.db.commit()
    
    return certificate
```

---

## Challenge Validation

### DNS-01 Challenge

The most secure and versatile validation method:

```python
import dns.resolver
import hashlib
import base64

class DNS01Validator:
    """Validate DNS-01 challenges"""
    
    def validate(self, challenge, authorization, account_jwk):
        """Perform DNS-01 validation"""
        
        domain = authorization['identifier_value']
        token = challenge['token']
        
        # Calculate expected TXT record value
        expected_value = self.calculate_key_authorization(token, account_jwk)
        
        # Hash the key authorization
        digest = hashlib.sha256(expected_value.encode()).digest()
        expected_record = base64.urlsafe_b64encode(digest).decode().rstrip('=')
        
        # Query DNS
        record_name = f"_acme-challenge.{domain}"
        
        try:
            # Query multiple nameservers for redundancy
            nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            found = False
            
            for nameserver in nameservers:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [nameserver]
                resolver.timeout = 5
                resolver.lifetime = 5
                
                try:
                    answers = resolver.resolve(record_name, 'TXT')
                    
                    for rdata in answers:
                        txt_value = rdata.strings[0].decode()
                        
                        if txt_value == expected_record:
                            found = True
                            break
                    
                    if found:
                        break
                        
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
            
            if not found:
                return False, f"Expected TXT record '{expected_record}' not found at {record_name}"
            
            # Store validation record
            validation_record = {
                'nameservers_queried': nameservers,
                'record_name': record_name,
                'expected_value': expected_record,
                'validated_at': datetime.utcnow().isoformat()
            }
            
            return True, validation_record
            
        except dns.exception.Timeout:
            return False, f"DNS query timeout for {record_name}"
        
        except Exception as e:
            return False, f"DNS validation error: {str(e)}"
    
    def calculate_key_authorization(self, token, account_jwk):
        """Calculate key authorization for challenge"""
        
        # JWK thumbprint
        thumbprint = account_jwk.thumbprint()
        
        # key_authorization = token || '.' || base64url(thumbprint)
        key_auth = f"{token}.{base64.urlsafe_b64encode(thumbprint).decode().rstrip('=')}"
        
        return key_auth
```

### HTTP-01 Challenge

For validation via web server:

```python
import requests

class HTTP01Validator:
    """Validate HTTP-01 challenges"""
    
    def validate(self, challenge, authorization, account_jwk):
        """Perform HTTP-01 validation"""
        
        domain = authorization['identifier_value']
        token = challenge['token']
        
        # Calculate expected response
        expected_response = self.calculate_key_authorization(token, account_jwk)
        
        # Build validation URL
        url = f"http://{domain}/.well-known/acme-challenge/{token}"
        
        try:
            # Fetch with redirects allowed (up to 10)
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={'User-Agent': 'ACME-Server/1.0'}
            )
            
            if response.status_code != 200:
                return False, f"HTTP {response.status_code} when fetching {url}"
            
            # Verify content type
            content_type = response.headers.get('Content-Type', '')
            if not content_type.startswith('text/plain') and not content_type.startswith('application/octet-stream'):
                return False, f"Invalid content type: {content_type}"
            
            # Check response body
            body = response.text.strip()
            
            if body != expected_response:
                return False, f"Response mismatch. Expected: {expected_response}, Got: {body}"
            
            # Validation successful
            validation_record = {
                'url': url,
                'status_code': response.status_code,
                'expected_response': expected_response,
                'validated_at': datetime.utcnow().isoformat(),
                'redirect_chain': [resp.url for resp in response.history] + [response.url]
            }
            
            return True, validation_record
            
        except requests.Timeout:
            return False, f"Timeout fetching {url}"
        
        except requests.ConnectionError as e:
            return False, f"Connection error: {str(e)}"
        
        except Exception as e:
            return False, f"Validation error: {str(e)}"
```

### TLS-ALPN-01 Challenge

For systems that can only serve HTTPS:

```python
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import hashes

class TLSALPN01Validator:
    """Validate TLS-ALPN-01 challenges"""
    
    ACME_TLS_1_PROTOCOL = 'acme-tls/1'
    
    def validate(self, challenge, authorization, account_jwk):
        """Perform TLS-ALPN-01 validation"""
        
        domain = authorization['identifier_value']
        token = challenge['token']
        
        # Calculate expected value
        key_auth = self.calculate_key_authorization(token, account_jwk)
        key_auth_hash = hashlib.sha256(key_auth.encode()).digest()
        
        try:
            # Create SSL context with ALPN
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols([self.ACME_TLS_1_PROTOCOL])
            
            # Connect
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    
                    # Verify ALPN protocol
                    selected_protocol = ssock.selected_alpn_protocol()
                    if selected_protocol != self.ACME_TLS_1_PROTOCOL:
                        return False, f"Wrong ALPN protocol: {selected_protocol}"
                    
                    # Get certificate
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Verify certificate contains ACME extension
                    try:
                        acme_ext = cert.extensions.get_extension_for_oid(
                            x509.ObjectIdentifier('1.3.6.1.5.5.7.1.31')  # id-pe-acmeIdentifier
                        )
                        
                        # Extension value should be SHA-256 hash of key authorization
                        if acme_ext.value.value != key_auth_hash:
                            return False, "ACME extension value mismatch"
                        
                    except x509.ExtensionNotFound:
                        return False, "ACME extension not found in certificate"
                    
                    # Verify SAN matches domain
                    try:
                        san_ext = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        
                        san_names = [name.value for name in san_ext.value]
                        if domain not in san_names:
                            return False, f"Domain {domain} not in certificate SANs"
                            
                    except x509.ExtensionNotFound:
                        return False, "No SAN extension in certificate"
                    
                    # Validation successful
                    validation_record = {
                        'domain': domain,
                        'alpn_protocol': selected_protocol,
                        'certificate_fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
                        'validated_at': datetime.utcnow().isoformat()
                    }
                    
                    return True, validation_record
        
        except socket.timeout:
            return False, f"Connection timeout to {domain}:443"
        
        except ssl.SSLError as e:
            return False, f"SSL error: {str(e)}"
        
        except Exception as e:
            return False, f"Validation error: {str(e)}"
```

### Validation Worker

Asynchronous validation processing:

```python
import pika
import json

class ValidationWorker:
    """Process challenge validations asynchronously"""
    
    def __init__(self, rabbitmq_url, db_connection):
        self.db = db_connection
        self.validators = {
            'dns-01': DNS01Validator(),
            'http-01': HTTP01Validator(),
            'tls-alpn-01': TLSALPN01Validator()
        }
        
        # Setup RabbitMQ
        params = pika.URLParameters(rabbitmq_url)
        self.connection = pika.BlockingConnection(params)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue='challenge_validations', durable=True)
    
    def start(self):
        """Start consuming validation requests"""
        
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(
            queue='challenge_validations',
            on_message_callback=self.handle_validation
        )
        
        print('Validation worker started...')
        self.channel.start_consuming()
    
    def handle_validation(self, ch, method, properties, body):
        """Process single validation request"""
        
        try:
            request = json.loads(body)
            
            challenge_id = request['challenge_id']
            authz_id = request['authorization_id']
            account_jwk = request['account_jwk']
            
            # Load challenge and authorization
            challenge = self.load_challenge(challenge_id)
            authorization = self.load_authorization(authz_id)
            
            # Update status to processing
            self.update_challenge_status(challenge_id, 'processing')
            
            # Perform validation
            validator = self.validators[challenge['type']]
            success, result = validator.validate(challenge, authorization, account_jwk)
            
            if success:
                # Mark challenge as valid
                self.update_challenge_status(
                    challenge_id,
                    'valid',
                    validation_record=result
                )
                
                # Check if all challenges for authorization are valid
                if self.all_challenges_valid(authz_id):
                    self.update_authorization_status(authz_id, 'valid')
                    
                    # Check if all authorizations for orders are valid
                    self.check_order_readiness(authz_id)
            else:
                # Mark challenge as invalid
                self.update_challenge_status(
                    challenge_id,
                    'invalid',
                    error=result
                )
            
            # Acknowledge message
            ch.basic_ack(delivery_tag=method.delivery_tag)
            
        except Exception as e:
            print(f"Validation error: {e}")
            # Requeue for retry
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
    
    def check_order_readiness(self, authz_id):
        """Check if any orders are now ready for finalization"""
        
        # Find orders using this authorization
        orders = self.db.execute(
            """
            SELECT DISTINCT o.id
            FROM orders o
            JOIN order_authorizations oa ON o.id = oa.order_id
            WHERE oa.authorization_id = %s AND o.status = 'pending'
            """,
            (authz_id,)
        ).fetchall()
        
        for order_row in orders:
            order_id = order_row[0]
            
            # Check if all authorizations are valid
            all_valid = self.db.execute(
                """
                SELECT COUNT(*) = COUNT(CASE WHEN a.status = 'valid' THEN 1 END)
                FROM order_authorizations oa
                JOIN authorizations a ON oa.authorization_id = a.id
                WHERE oa.order_id = %s
                """,
                (order_id,)
            ).fetchone()[0]
            
            if all_valid:
                self.db.execute(
                    "UPDATE orders SET status = 'ready' WHERE id = %s",
                    (order_id,)
                )
                self.db.commit()
```

---

## Rate Limiting

### Rate Limit Implementation

```python
from datetime import datetime, timedelta

class RateLimiter:
    """Enforce ACME rate limits"""
    
    def __init__(self, db):
        self.db = db
        self.limits = {
            'new_accounts_per_ip': {'limit': 10, 'window': timedelta(hours=3)},
            'orders_per_account': {'limit': 300, 'window': timedelta(hours=3)},
            'certificates_per_domain': {'limit': 50, 'window': timedelta(days=7)},
            'failed_validations': {'limit': 5, 'window': timedelta(hours=1)},
            'new_orders_per_ip': {'limit': 20, 'window': timedelta(minutes=10)}
        }
    
    def check_limit(self, limit_name, identifier_value, identifier_type='account_id'):
        """Check if rate limit exceeded"""
        
        config = self.limits[limit_name]
        window_start = datetime.utcnow() - config['window']
        
        # Clean old entries
        self.db.execute(
            "DELETE FROM rate_limits WHERE window_end < NOW()"
        )
        
        # Count current usage
        if identifier_type == 'account_id':
            current_count = self.db.execute(
                """
                SELECT COALESCE(SUM(count), 0)
                FROM rate_limits
                WHERE account_id = %s 
                  AND limit_name = %s
                  AND window_start >= %s
                """,
                (identifier_value, limit_name, window_start)
            ).fetchone()[0]
        else:  # IP address
            current_count = self.db.execute(
                """
                SELECT COALESCE(SUM(count), 0)
                FROM rate_limits
                WHERE ip_address = %s 
                  AND limit_name = %s
                  AND window_start >= %s
                """,
                (identifier_value, limit_name, window_start)
            ).fetchone()[0]
        
        if current_count >= config['limit']:
            retry_after = self.calculate_retry_after(
                identifier_value,
                identifier_type,
                limit_name
            )
            raise RateLimitExceededError(
                f"Rate limit exceeded for {limit_name}",
                retry_after=retry_after
            )
        
        # Increment counter
        self.increment_counter(identifier_value, identifier_type, limit_name, config['window'])
    
    def increment_counter(self, identifier_value, identifier_type, limit_name, window):
        """Increment rate limit counter"""
        
        window_end = datetime.utcnow() + window
        
        if identifier_type == 'account_id':
            self.db.execute(
                """
                INSERT INTO rate_limits (account_id, limit_name, count, window_start, window_end)
                VALUES (%s, %s, 1, NOW(), %s)
                """,
                (identifier_value, limit_name, window_end)
            )
        else:
            self.db.execute(
                """
                INSERT INTO rate_limits (ip_address, limit_name, count, window_start, window_end)
                VALUES (%s, %s, 1, NOW(), %s)
                """,
                (identifier_value, limit_name, window_end)
            )
        
        self.db.commit()
    
    def calculate_retry_after(self, identifier_value, identifier_type, limit_name):
        """Calculate when limit will reset"""
        
        if identifier_type == 'account_id':
            oldest = self.db.execute(
                """
                SELECT MIN(window_end)
                FROM rate_limits
                WHERE account_id = %s AND limit_name = %s
                """,
                (identifier_value, limit_name)
            ).fetchone()[0]
        else:
            oldest = self.db.execute(
                """
                SELECT MIN(window_end)
                FROM rate_limits
                WHERE ip_address = %s AND limit_name = %s
                """,
                (identifier_value, limit_name)
            ).fetchone()[0]
        
        if oldest:
            return int((oldest - datetime.utcnow()).total_seconds())
        return 60
```

---

## High Availability Deployment

### Multi-Region Architecture

```yaml
# kubernetes/acme-server-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: acme-api-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: acme-api
  template:
    metadata:
      labels:
        app: acme-api
    spec:
      containers:
      - name: acme-api
        image: acme-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: acme-secrets
              key: database-url
        - name: RABBITMQ_URL
          valueFrom:
            secretKeyRef:
              name: acme-secrets
              key: rabbitmq-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: acme-api-service
spec:
  selector:
    app: acme-api
  ports:
  - protocol: TCP
    port: 443
    targetPort: 8080
  type: LoadBalancer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: acme-validator
spec:
  replicas: 5
  selector:
    matchLabels:
      app: acme-validator
  template:
    metadata:
      labels:
        app: acme-validator
    spec:
      containers:
      - name: validator
        image: acme-validator:latest
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: acme-secrets
              key: database-url
        - name: RABBITMQ_URL
          valueFrom:
            secretKeyRef:
              name: acme-secrets
              key: rabbitmq-url
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
```

### Database Replication

```sql
-- PostgreSQL streaming replication setup

-- On primary:
-- postgresql.conf
wal_level = replica
max_wal_senders = 3
max_replication_slots = 3
synchronous_commit = on
synchronous_standby_names = 'standby1'

-- pg_hba.conf
host replication replicator standby1_ip/32 md5
host replication replicator standby2_ip/32 md5

-- Create replication user
CREATE USER replicator REPLICATION LOGIN ENCRYPTED PASSWORD 'secure_password';

-- On replicas:
-- recovery.conf
standby_mode = on
primary_conninfo = 'host=primary_ip port=5432 user=replicator password=secure_password'
trigger_file = '/tmp/postgresql.trigger'
```

---

## Monitoring and Observability

### Metrics Collection

```python
from prometheus_client import Counter, Histogram, Gauge
import time

# Define metrics
orders_created = Counter('acme_orders_created_total', 'Total orders created')
certificates_issued = Counter('acme_certificates_issued_total', 'Total certificates issued')
validations_attempted = Counter('acme_validations_attempted_total', 'Total validation attempts', ['type', 'result'])
validation_duration = Histogram('acme_validation_duration_seconds', 'Validation duration', ['type'])
active_orders = Gauge('acme_active_orders', 'Currently active orders')
rate_limit_hits = Counter('acme_rate_limit_hits_total', 'Rate limit exceeded', ['limit_name'])

class InstrumentedACMEServer:
    """ACME server with Prometheus metrics"""
    
    def create_order(self, account_id, identifiers):
        """Create order with metrics"""
        
        orders_created.inc()
        active_orders.inc()
        
        try:
            order = super().create_order(account_id, identifiers)
            return order
        except RateLimitExceededError as e:
            rate_limit_hits.labels(limit_name='orders_per_account').inc()
            raise
    
    def validate_challenge(self, challenge_id):
        """Validate with timing metrics"""
        
        challenge = self.load_challenge(challenge_id)
        challenge_type = challenge['type']
        
        start = time.time()
        
        try:
            result = super().validate_challenge(challenge_id)
            
            duration = time.time() - start
            validation_duration.labels(type=challenge_type).observe(duration)
            
            if result:
                validations_attempted.labels(type=challenge_type, result='success').inc()
            else:
                validations_attempted.labels(type=challenge_type, result='failure').inc()
            
            return result
            
        except Exception as e:
            validations_attempted.labels(type=challenge_type, result='error').inc()
            raise
    
    def issue_certificate(self, order_id):
        """Issue certificate with metrics"""
        
        cert = super().issue_certificate(order_id)
        certificates_issued.inc()
        active_orders.dec()
        return cert
```

### Logging

```python
import logging
import json

class StructuredLogger:
    """JSON structured logging for ACME server"""
    
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_order_created(self, order_id, account_id, identifiers):
        self.logger.info('order_created', extra={
            'order_id': order_id,
            'account_id': account_id,
            'identifier_count': len(identifiers),
            'identifiers': identifiers
        })
    
    def log_validation_attempt(self, challenge_id, challenge_type, domain, result):
        self.logger.info('validation_attempted', extra={
            'challenge_id': challenge_id,
            'challenge_type': challenge_type,
            'domain': domain,
            'result': result
        })
    
    def log_certificate_issued(self, order_id, serial, common_name):
        self.logger.info('certificate_issued', extra={
            'order_id': order_id,
            'serial': serial,
            'common_name': common_name
        })
    
    def log_rate_limit_exceeded(self, account_id, limit_name, ip_address):
        self.logger.warning('rate_limit_exceeded', extra={
            'account_id': account_id,
            'limit_name': limit_name,
            'ip_address': ip_address
        })

class JsonFormatter(logging.Formatter):
    """Format logs as JSON"""
    
    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'message': record.getMessage(),
            'logger': record.name
        }
        
        # Add extra fields
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
        
        return json.dumps(log_data)
```

---

## Security Considerations

### Account Security
- Account keys should be at least 2048-bit RSA or 256-bit ECDSA
- Implement account key rollover to allow key rotation
- Rate limit account creation per IP to prevent abuse
- Log all account operations for audit

### Validation Security
- Perform validation from multiple vantage points
- Implement validation timeout (maximum 60 seconds)
- Store validation records for compliance
- Use DNS resolvers that support DNSSEC when possible

### Certificate Security
- Never issue certificates longer than 398 days
- Enforce key size minimums (2048-bit RSA, 256-bit ECDSA)
- Check Certificate Transparency logs
- Implement CAA checking
- Use OCSP Must-Staple extension

### Infrastructure Security
- HSM for CA signing keys
- Database encryption at rest
- TLS 1.3 for all communications
- Regular security audits and penetration testing
- Separate validation network from API network

---

## Common Pitfalls

### Validation Race Conditions
**Problem**: Client removes challenge response before all validators check  
**Solution**: Multiple validators with staggered timing, validation record storage

### Database Hotspots
**Problem**: Single order table becomes bottleneck at scale  
**Solution**: Partition by time range, archive completed orders, use read replicas

### Challenge Token Reuse
**Problem**: Using same token for multiple challenges enables attacks  
**Solution**: Generate unique token per challenge, expire after use

### Missing CAA Checks
**Problem**: Issuing certificates for domains with CAA records forbidding issuance  
**Solution**: Check CAA records before every issuance, respect iodef reporting

### Insufficient Rate Limiting
**Problem**: Single account can overwhelm validation infrastructure  
**Solution**: Multiple rate limit tiers, exponential backoff, IP-based limits

---

## Real-World Examples

### Let's Encrypt (Boulder)
The largest ACME CA, issuing 3+ million certificates daily:
- Go-based implementation for performance
- Multi-region deployment with anycast
- Comprehensive rate limiting (50 orders/account/hour, 300 pending/account)
- Multiple validation perspectives (4+ geographically distributed validators)
- Integration with Certificate Transparency
- Publicly audited code: https://github.com/letsencrypt/boulder

**Lessons**: Horizontal scaling critical, validation must be geographically diverse, rate limiting essential, observability non-negotiable.

### Sectigo (SCM)
Enterprise ACME CA with private deployments:
- Customizable validation workflows for internal networks
- Integration with enterprise directory services (LDAP, AD)
- Custom challenge types for air-gapped environments
- Policy-driven issuance with approval gates
- Support for client certificates and code signing

**Lessons**: ACME protocol extensible for enterprise needs, internal validation methods necessary, policy layer enables governance.

### HashiCorp Vault PKI
ACME implementation for internal certificates:
- Integrated with Vault's authentication methods
- Dynamic certificate lifetimes based on requester
- Automated renewal via Vault agents
- Multi-tenancy with namespace isolation
- Audit logging through Vault audit devices

**Lessons**: ACME works for private PKI, integration with existing auth simplifies adoption, short lifetimes reduce operational burden.

---

## Further Reading

### Standards and RFCs
- RFC 8555: ACME Protocol
- RFC 8657: CAA Record Extensions for ACME
- RFC 8737: ACME TLS ALPN Challenge Extension
- RFC 8738: ACME IP Identifier Validation Extension
- Let's Encrypt Integration Guide: https://letsencrypt.org/docs/integration-guide/

### Related Pages
- [Certificate Issuance Workflows](./certificate-issuance-workflows.md) - Complete workflow patterns
- [ACME Protocol](./acme-protocol.md) - ACME standard deep dive  
- [Certificate Lifecycle Management](./certificate-lifecycle-management.md) - Lifecycle automation
- [CA Architecture](./ca-architecture.md) - CA design principles
- [HSM Integration](./hsm-integration.md) - Hardware security for CA keys

### Implementation Resources
- Boulder (Let's Encrypt): https://github.com/letsencrypt/boulder
- Certbot (ACME client): https://github.com/certbot/certbot
- acme.sh (Bash ACME client): https://github.com/acmesh-official/acme.sh
- Pebble (Test ACME server): https://github.com/letsencrypt/pebble
- ACME Protocol Specification: https://tools.ietf.org/html/rfc8555

---

**Last Updated**: 2025-11-09  
**Maintenance Notes**: Monitor for ACME protocol updates (new challenge types, extensions), update Boulder implementation examples, add emerging validation methods, track Let's Encrypt operational metrics