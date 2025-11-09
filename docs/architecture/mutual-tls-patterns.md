# Mutual TLS Patterns

## Overview

Mutual TLS (mTLS) extends traditional TLS by requiring both client and server to present certificates, enabling strong bidirectional authentication. While server-only TLS proves the server's identity to clients, mTLS proves both parties' identities to each other—critical for service-to-service communication, API security, and zero-trust architectures.

**Core principle**: mTLS transforms authentication from "prove you know a password" to "prove you possess a private key." This cryptographic proof is stronger, more auditable, and enables fine-grained authorization based on certificate attributes.

## Why Mutual TLS

Traditional authentication (passwords, API keys, bearer tokens) has fundamental weaknesses:
- Credentials can be stolen and replayed
- No cryptographic proof of identity
- Difficult to rotate securely
- Poor auditability

mTLS provides:
- Strong cryptographic authentication
- Non-repudiation (private key possession)
- Certificate attributes for authorization
- Automatic rotation capabilities
- Comprehensive audit trails

## mTLS Handshake

The mTLS handshake extends standard TLS:

```
Client                                Server
  │                                     │
  │──────── ClientHello ───────────────>│
  │                                     │
  │<────── ServerHello ─────────────────│
  │<────── Certificate ─────────────────│ (Server cert)
  │<── CertificateRequest ──────────────│ (Request client cert)
  │<────── ServerHelloDone ─────────────│
  │                                     │
  │──────── Certificate ────────────────>│ (Client cert)
  │──────── ClientKeyExchange ──────────>│
  │──────── CertificateVerify ──────────>│ (Prove possession)
  │──────── ChangeCipherSpec ───────────>│
  │──────── Finished ───────────────────>│
  │                                     │
  │<────── ChangeCipherSpec ────────────│
  │<────── Finished ────────────────────│
  │                                     │
  │═══════ Encrypted Data ═════════════>│
  │<══════ Encrypted Data ══════════════│
```

Both parties verify certificates against trusted CAs, check revocation status, and validate certificate attributes before allowing communication.

## Implementation Patterns

### API Gateway mTLS

API gateway enforcing client certificate authentication:

```python
# API Gateway with mTLS enforcement
from flask import Flask, request
import ssl

app = Flask(__name__)

# Configure TLS context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain('server.crt', 'server.key')
context.load_verify_locations('client-ca.crt')
context.verify_mode = ssl.CERT_REQUIRED  # Require client cert

@app.route('/api/payment')
def payment_api():
    # Extract client certificate
    client_cert = request.environ.get('peercert')
    
    # Extract identity from certificate
    client_cn = dict(x[0] for x in client_cert['subject'])['commonName']
    client_org = dict(x[0] for x in client_cert['subject'])['organizationName']
    
    # Authorization based on certificate
    if client_org != 'TrustedPartner':
        return {'error': 'Unauthorized organization'}, 403
    
    # Process request
    return {'status': 'Payment processed', 'client': client_cn}

if __name__ == '__main__':
    app.run(ssl_context=context, host='0.0.0.0', port=443)

### Database mTLS

PostgreSQL with client certificate authentication:

```sql
-- postgresql.conf
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_ca_file = 'client-ca.crt'

-- pg_hba.conf
# Require client certificates for connections
hostssl all all 0.0.0.0/0 cert clientcert=verify-full

-- Map certificate CN to database user
# pg_ident.conf
mymap   /^(.*)@example\.com$   \1
```

Client connection:
```python
import psycopg2

conn = psycopg2.connect(
    host='db.example.com',
    port=5432,
    database='production',
    sslmode='verify-full',
    sslcert='client.crt',
    sslkey='client.key',
    sslrootcert='server-ca.crt'
)
```

### Microservices mTLS

Service-to-service with certificate-based auth:

```python
import requests

# Client making request
response = requests.get(
    'https://payment-service.internal/process',
    cert=('client.crt', 'client.key'),  # Client certificate
    verify='server-ca.crt'   # Verify server
)

# Server validating client
from flask import Flask, request

@app.route('/process')
def process_payment():
    # Extract client certificate
    client_cert = request.environ['peercert']
    service_name = extract_cn(client_cert)
    
    # Policy check
    if service_name not in ['order-service', 'billing-service']:
        return {'error': 'Unauthorized service'}, 403
    
    return {'status': 'processed'}
```

## Certificate-Based Authorization

Extract attributes from certificates for fine-grained access control:

```python
class CertificateAuthorization:
    """
    Authorization based on certificate attributes
    """
    
    def authorize_request(self, cert, resource, action):
        """
        Determine if certificate holder can perform action
        """
        # Extract attributes
        subject = cert['subject']
        ou = self.get_field(subject, 'OU')
        cn = self.get_field(subject, 'CN')
        
        # Extract custom extensions
        extensions = self.parse_extensions(cert)
        team = extensions.get('team')
        role = extensions.get('role')
        
        # Policy evaluation
        if resource == '/admin' and role != 'admin':
            return False
        
        if resource.startswith('/api/payments'):
            if team not in ['payments', 'billing']:
                return False
        
        return True
```

## Best Practices

**Certificate management**:
- Short-lived certificates (hours to days)
- Automatic rotation
- Revocation checking (OCSP)
- Proper certificate validation

**Security**:
- Verify certificate chain to trusted root
- Check certificate hasn't expired
- Validate hostname matches certificate
- Check revocation status
- Enforce minimum TLS version (1.2+)

**Performance**:
- Cache session tickets for performance
- Use OCSP stapling
- Connection pooling with certificate reuse
- Monitor handshake latency

## Common Patterns

**Partner API access**: External partners authenticate with certificates, enabling B2B integrations without shared secrets.

**Internal service mesh**: All services use mTLS for communication, with automatic certificate issuance and rotation via service mesh.

**Device authentication**: IoT devices use client certificates for authentication, enabling per-device identity and access control.

**Database access**: Applications use certificates for database authentication, removing password management burden.

## Troubleshooting

Common mTLS issues:

**Handshake failures**: Usually certificate validation errors. Check certificate chain, expiry, and trust store.

**Performance problems**: mTLS adds overhead. Use session resumption and connection pooling.

**Certificate rotation**: Ensure zero-downtime rotation with overlapping validity periods.

## Conclusion

Mutual TLS provides strong, bidirectional authentication using certificates. By requiring both parties to prove identity cryptographically, mTLS enables fine-grained access control based on certificate attributes and eliminates many password-related vulnerabilities.

For modern microservices and zero-trust architectures, mTLS is becoming the default rather than the exception—especially with service meshes automating certificate management.
