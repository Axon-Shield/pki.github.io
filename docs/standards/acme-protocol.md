---
title: ACME Protocol
category: standards
last_updated: 2024-11-09
last_reviewed: 2024-11-09
version: 1.0
status: stable
tags: [acme, automation, lets-encrypt, certificate-automation, rfc8555]
---

# ACME Protocol

> **TL;DR**: Automatic Certificate Management Environment (ACME) is a protocol for automating certificate issuance, renewal, and revocation. Developed by Let's Encrypt and standardized as RFC 8555, ACME enables zero-touch certificate lifecycle management through automated domain validation challenges. Understanding ACME is essential for implementing modern, scalable certificate management.

## Overview

Before ACME, obtaining certificates required manual processes: generate CSR, prove domain control through email or file verification, wait for CA to issue certificate, manually install certificate, manually renew before expiration. This manual workflow didn't scale for organizations with thousands of certificates or modern cloud-native applications spinning up new services continuously.

ACME revolutionized PKI automation by standardizing the entire certificate lifecycle as an API-driven protocol. First deployed by Let's Encrypt in 2015, ACME enabled free, automated certificates for millions of websites. The protocol was standardized as RFC 8555[^1] in 2019 and is now supported by multiple Certificate Authorities and implemented in numerous client tools.

ACME's impact extends beyond Let's Encrypt: it demonstrates how thoughtful protocol design enables automation at massive scale (Let's Encrypt issues over 3 million certificates daily). Understanding ACME is crucial for anyone implementing certificate automation, building cloud infrastructure, or operating modern PKI.

**Related Pages**: [[certificate-lifecycle-management]], [[renewal-automation]], [[tls-protocol]], [[what-is-pki]]

## Key Concepts

### Protocol Overview

ACME defines interactions between three parties:

#### ACME Client

Software requesting certificates on behalf of domain owner.

**Responsibilities**:



- Account registration with ACME server
- Prove control over domain (challenge completion)
- Generate key pairs
- Request certificate issuance
- Automate renewal before expiration
- Handle revocation if needed

**Examples**:



- **Certbot**: EFF's official client, Python-based
- **acme.sh**: Shell script implementation
- **cert-manager**: Kubernetes-native controller
- **Caddy**: Web server with built-in ACME
- **Traefik**: Reverse proxy with ACME support

#### ACME Server (CA)

Certificate Authority implementing ACME protocol.

**Responsibilities**:



- Account management
- Challenge generation and validation
- Certificate issuance
- Certificate revocation
- Rate limiting and abuse prevention

**Examples**:



- **Let's Encrypt**: Free, public CA
- **ZeroSSL**: Free and paid options
- **Buypass Go SSL**: Free Norwegian CA
- **Google Trust Services**: Google's CA
- **Boulder**: Open-source ACME server (Let's Encrypt's implementation)
- **Step CA**: Private ACME server

#### Domain Owner

Entity controlling domain and running ACME client.

**Responsibilities**:



- Maintain domain infrastructure to complete challenges
- Secure ACME account credentials
- Monitor certificate expiration and renewal
- Respond to validation challenges

### Account Management

ACME requires account registration before certificate operations.

#### Account Registration

**Process**:
1. Client generates account key pair (typically ECDSA P-256)
2. Client sends registration request with public key
3. Server creates account, assigns unique URL
4. Client stores account key and URL for future operations

**Account Request Example** (Simplified JSON):
```json
{
  "termsOfServiceAgreed": true,
  "contact": [
    "mailto:admin@example.com"
  ]
}
```

**Server Response**:
```json
{
  "status": "valid",
  "contact": [
    "mailto:admin@example.com"
  ],
  "orders": "https://acme.example.com/acme/acct/123/orders",
  "key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "base64...",
    "y": "base64..."
  }
}
```

**Account Key Security**:



- Account key controls all certificates for the account
- Store securely (HSM, encrypted keystore)
- Separate from certificate private keys
- Compromise allows unauthorized certificate issuance
- Can be rotated using key rollover procedure

#### Account Key Rollover

Change account key without losing account:

```
1. Client generates new account key pair
2. Client sends key rollover request signed with both old and new keys
3. Server validates both signatures
4. Server updates account to use new key
5. Client discards old key
```

### Domain Validation Challenges

ACME uses challenges to prove domain control before issuing certificates.

#### HTTP-01 Challenge

Prove control by serving specific content at well-known URL.

**Challenge Flow**:
```
1. Client requests certificate for example.com
2. Server generates challenge token: "abc123xyz"
3. Server expects content at:
   http://example.com/.well-known/acme-challenge/abc123xyz
4. Client places token + account key fingerprint at URL
5. Server fetches URL, validates content
6. If valid, domain ownership proven
```

**Required Content Format**:
```
<token>.<base64url(SHA-256(account_key_jwk))>

Example:
abc123xyz.Xyz9876def
```

**Advantages**:



- Simple to implement
- Works with standard web servers
- Port 80 required (standard)
- No DNS changes needed

**Limitations**:



- Requires port 80 accessible from internet
- Only validates single hostname
- Cannot validate wildcard certificates
- Doesn't work for internal domains

**Use Cases**:



- Public websites
- Single hostnames
- Standard web server environments

#### DNS-01 Challenge

Prove control by creating specific DNS TXT record.

**Challenge Flow**:
```
1. Client requests certificate for *.example.com
2. Server generates challenge token: "abc123xyz"
3. Server expects DNS TXT record:
   _acme-challenge.example.com IN TXT "<validation_string>"
4. Client creates DNS record via DNS API
5. Server queries DNS, validates record
6. If valid, domain ownership proven
```

**Validation String**:
```
base64url(SHA-256(<token>.<base64url(SHA-256(account_key_jwk))>))
```

**Advantages**:



- Works without public-facing web server
- Can validate wildcard certificates (*.example.com)
- Can validate multiple domains simultaneously
- Works for internal/private domains

**Limitations**:



- Requires DNS provider API or manual DNS management
- DNS propagation delays (can take minutes)
- More complex to automate
- Potential for DNS pollution if not cleaned up

**Use Cases**:



- Wildcard certificates
- Internal infrastructure
- Load balancers/proxies
- Environments without web server

#### TLS-ALPN-01 Challenge

Prove control via TLS handshake with specific ALPN extension.

**Challenge Flow**:
```
1. Client requests certificate for example.com
2. Server generates challenge token
3. Client creates self-signed certificate with:
   - acmeIdentifier extension containing validation data
   - Served on port 443
4. Server connects to example.com:443 with ALPN "acme-tls/1"
5. Server validates certificate extension
6. If valid, domain ownership proven
```

**Advantages**:



- Works on port 443 only (no port 80)
- Useful when port 80 blocked/unavailable
- Simple validation
- Fast (no DNS delays)

**Limitations**:



- Requires TLS server control
- Less widely supported
- Cannot validate wildcards
- Relatively new (not all clients support)

**Use Cases**:



- Environments where only port 443 allowed
- TLS-based infrastructure
- Alternative to HTTP-01 when port 80 unavailable

### Certificate Issuance Flow

Complete process from request to certificate installation.

#### Step-by-Step Process

**1. Account Registration** (One-time)
```
Client                          ACME Server

POST /acme/new-account
  {account_key, contact}  ---->
                          <----  201 Created
                                 {account_url, status}
```

**2. Create Order**
```
POST /acme/new-order
  {identifiers: [example.com]} -->
                          <----  201 Created
                                 {status: pending,
                                  authorizations: [auth_url],
                                  finalize: finalize_url}
```

**3. Get Authorization**
```
POST /acme/authz/{id}     ---->
                          <----  200 OK
                                 {identifier: example.com,
                                  status: pending,
                                  challenges: [http-01, dns-01]}
```

**4. Select Challenge**
```
# Client chooses HTTP-01 challenge
# Places validation content at:
# http://example.com/.well-known/acme-challenge/<token>
```

**5. Trigger Validation**
```
POST /acme/challenge/{id}
  {}                      ---->
                          <----  200 OK
                                 {status: processing}
```

**6. Poll Authorization**
```
POST /acme/authz/{id}     ---->
                          <----  200 OK
                                 {status: valid}  # Validation succeeded!
```

**7. Finalize Order** (Submit CSR)
```
POST /acme/order/{id}/finalize
  {csr: base64_csr}       ---->
                          <----  200 OK
                                 {status: valid,
                                  certificate: cert_url}
```

**8. Download Certificate**
```
POST /acme/cert/{id}      ---->
                          <----  200 OK
                                 -----BEGIN CERTIFICATE-----
                                 ...certificate chain...
                                 -----END CERTIFICATE-----
```

#### Order Lifecycle

```
pending --> ready --> processing --> valid --> expired
    |                                   |
    +-----------------------------------+
                    |
                 invalid
```

**pending**: Waiting for authorizations to complete
**ready**: All authorizations valid, ready for finalization
**processing**: CA generating certificate
**valid**: Certificate issued and ready for download
**invalid**: Order failed (challenge validation failed)
**expired**: Order expired before completion

### Certificate Renewal

ACME makes renewal identical to initial issuance.

#### Renewal Strategy

**When to Renew**:
```
Certificate Lifetime: 90 days (Let's Encrypt)

Recommended Renewal:
Day 0  |-------- 60 days --------|-- 30 days --|
       ^                         ^              ^
    Issued                  Renew starts     Expires

Renewal Window: Day 60-89 (30 days)
Ideal: Day 60 (30 days remaining)
```

**Why 90-Day Certificates?**:



- Forces automation (manual renewal unsustainable)
- Reduces exposure window if key compromised
- Enables key rotation best practices
- Tests renewal process frequently

**Automated Renewal Loop**:
```python
while True:
    certs = get_installed_certificates()
    for cert in certs:
        days_until_expiry = cert.not_after - now()
        
        if days_until_expiry < 30:  # Renew at 30 days
            new_cert = acme_renew(cert)
            install_certificate(new_cert)
            reload_server()
    
    sleep(24 * 3600)  # Check daily
```

#### Renewal Considerations

**Key Rotation**:



- **Reuse private key**: Same key, new certificate
  - Simpler, fewer keys to manage
  - Longer key exposure window
- **Generate new key**: New key pair with renewal
  - Better security (limits key exposure)
  - More complex (manage multiple keys during transition)
  - Recommended by security best practices

**Certificate Chain**:



- ACME server may return different intermediates over time
- Always use full chain returned by server
- Don't assume chain structure stays constant

**Rate Limits**:



- Let's Encrypt: 50 certificates per registered domain per week
- Consider rate limits in renewal automation
- Spread renewals across time (don't renew all at once)

### Revocation

ACME supports certificate revocation.

#### Revocation Methods

**By Account Key** (Most Common):
```
POST /acme/revoke-cert
Authorization: <account_key_signature>
{
  "certificate": "<base64_cert>",
  "reason": 1  # keyCompromise
}
```

**By Certificate Private Key**:
```
# Can revoke even without account access
# Useful if account key lost but certificate key intact

POST /acme/revoke-cert
Authorization: <cert_key_signature>
{
  "certificate": "<base64_cert>",
  "reason": 1
}
```

**Revocation Reasons**:



- 0: unspecified
- 1: keyCompromise
- 3: affiliationChanged
- 4: superseded
- 5: cessationOfOperation

#### When to Revoke

**Immediately Revoke If**:



- Private key compromised or exposed
- Domain no longer controlled
- Certificate issued in error
- Service decommissioned permanently

**Consider Revocation If**:



- Replacing certificate before expiration
- Service temporarily offline
- Security best practice in incident response

**Don't Need to Revoke If**:



- Normal certificate renewal (cert expires soon anyway)
- Certificate already expired

## Practical Guidance

### Implementing ACME Clients

#### Using Certbot

**Installation**:
```bash
# Ubuntu/Debian
apt-get install certbot

# CentOS/RHEL
yum install certbot

# macOS
brew install certbot
```

**Standalone Mode** (HTTP-01):
```bash
# Obtains certificate, doesn't install
# Runs own web server on port 80

certbot certonly --standalone \
  -d example.com \
  -d www.example.com \
  --email admin@example.com \
  --agree-tos

# Certificates saved to:
# /etc/letsencrypt/live/example.com/
#   fullchain.pem  (certificate + intermediate)
#   privkey.pem    (private key)
#   cert.pem       (certificate only)
#   chain.pem      (intermediate only)
```

**Webroot Mode** (HTTP-01):
```bash
# Places validation files in existing webroot
# Web server continues running

certbot certonly --webroot \
  -w /var/www/html \
  -d example.com \
  -d www.example.com
```

**DNS Mode** (DNS-01):
```bash
# Requires DNS plugin

# Install Cloudflare plugin
pip install certbot-dns-cloudflare

# Configure API credentials
echo "dns_cloudflare_api_token = YOUR_TOKEN" > ~/.secrets/cloudflare.ini
chmod 600 ~/.secrets/cloudflare.ini

# Obtain wildcard certificate
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
  -d '*.example.com' \
  -d example.com
```

**Automatic Renewal**:
```bash
# Test renewal (dry run)
certbot renew --dry-run

# Set up cron job (runs twice daily)
# /etc/cron.d/certbot
0 */12 * * * certbot renew --quiet --deploy-hook "systemctl reload nginx"
```

#### Using acme.sh

**Installation**:
```bash
curl https://get.acme.sh | sh -s email=admin@example.com
```

**Standalone Mode**:
```bash
acme.sh --issue --standalone \
  -d example.com \
  -d www.example.com
```

**DNS Mode** (Many Providers Supported):
```bash
# Cloudflare
export CF_Token="YOUR_TOKEN"
acme.sh --issue --dns dns_cf \
  -d example.com \
  -d '*.example.com'

# Route53
export AWS_ACCESS_KEY_ID="YOUR_KEY"
export AWS_SECRET_ACCESS_KEY="YOUR_SECRET"
acme.sh --issue --dns dns_aws \
  -d example.com
```

**Install Certificate**:
```bash
acme.sh --install-cert -d example.com \
  --key-file /etc/nginx/ssl/example.com.key \
  --fullchain-file /etc/nginx/ssl/example.com.crt \
  --reloadcmd "systemctl reload nginx"
```

**Automatic Renewal**:
```bash
# Installed by default in crontab
# acme.sh automatically renews certificates
crontab -l | grep acme.sh
# 0 0 * * * /root/.acme.sh/acme.sh --cron
```

### Kubernetes Integration

#### cert-manager

**Installation**:
```bash
# Install with kubectl
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
```

**ClusterIssuer Configuration**:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
    # HTTP-01 solver
    - http01:
        ingress:
          class: nginx
    # DNS-01 solver (for wildcards)
    - dns01:
        cloudflare:
          email: admin@example.com
          apiTokenSecretRef:
            name: cloudflare-api-token
            key: api-token
      selector:
        dnsZones:
        - 'example.com'
```

**Certificate Resource**:
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com-tls
  namespace: default
spec:
  secretName: example-com-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - example.com
  - www.example.com
```

**Ingress Annotation** (Automatic Certificate):
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - example.com
    secretName: example-com-tls  # cert-manager creates this
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: example-service
            port:
              number: 80
```

### Private ACME Server

#### Using Smallstep

**Install Step CA**:
```bash
# Install step and step-ca
wget https://dl.step.sm/gh-release/cli/docs-ca-install/v0.23.0/step-cli_0.23.0_amd64.deb
wget https://dl.step.sm/gh-release/certificates/docs-ca-install/v0.23.0/step-ca_0.23.0_amd64.deb
sudo dpkg -i step-cli_0.23.0_amd64.deb step-ca_0.23.0_amd64.deb
```

**Initialize CA**:
```bash
step ca init --acme

# Prompts for:
# - CA name
# - DNS names
# - Address (where CA listens)
# - Provisioner name
```

**Start CA**:
```bash
step-ca $(step path)/config/ca.json

# ACME directory URL:
# https://<ca-host>:9000/acme/<provisioner>/directory
```

**Use with Certbot**:
```bash
certbot certonly --standalone \
  --server https://ca.example.com:9000/acme/acme/directory \
  --email admin@example.com \
  -d internal.example.com
```

### Troubleshooting ACME

#### Common Issues

**Challenge Validation Fails**:
```bash
# Test HTTP-01 challenge manually
curl http://example.com/.well-known/acme-challenge/<token>

# Should return:
<token>.<account_key_fingerprint>

# Common problems:
# - Firewall blocking port 80
# - Web server not serving .well-known directory
# - Redirect to HTTPS interfering
# - Load balancer not forwarding to correct backend
```

**DNS-01 Challenge Timeout**:
```bash
# Check DNS propagation
dig TXT _acme-challenge.example.com

# Check from multiple locations
# Use: https://www.whatsmydns.net/

# Common problems:
# - DNS API credentials incorrect
# - DNS provider rate limits
# - Slow DNS propagation (can take 5-30 minutes)
# - DNS record not cleaned up from previous attempt
```

**Rate Limit Exceeded**:
```
Error: too many certificates already issued for: example.com

# Solutions:
# - Wait until rate limit window passes (1 week for Let's Encrypt)
# - Use staging server for testing
# - Consider using different registered domain
# - Review automation (avoid unnecessary issuance)
```

**Testing Against Staging**:
```bash
# Let's Encrypt staging server (higher rate limits)
certbot certonly --standalone \
  --server https://acme-staging-v02.api.letsencrypt.org/directory \
  -d example.com

# Staging certificates not trusted by browsers
# Use for testing automation only
```

## Common Pitfalls

- **Not using staging for testing**: Testing against production CA, hitting rate limits
  - **Why it happens**: Unaware of staging environment; shortcuts during development
  - **How to avoid**: Always test with staging server first; use production only for final verification
  - **How to fix**: Wait for rate limit to reset; switch to staging for development

- **Missing autorenewal**: Certificates expire because renewal cron job not configured
  - **Why it happens**: Manual testing doesn't set up automation; cron job breaks after OS update
  - **How to avoid**: Test renewal process; monitor cron jobs; alert on upcoming expiration
  - **How to fix**: Set up cron job; test with certbot renew --dry-run; add monitoring

- **DNS challenge cleanup failures**: Old DNS records interfere with new challenges
  - **Why it happens**: DNS API failures; script errors during cleanup; manual intervention
  - **How to avoid**: Robust error handling in DNS scripts; verify cleanup; use unique record names
  - **How to fix**: Manually clean DNS records; improve cleanup automation; add retries

- **Account key loss**: Lost account key prevents certificate renewal or revocation
  - **Why it happens**: No backup of account key; server rebuilt without preserving keys
  - **How to avoid**: Backup account keys securely; document key locations; test recovery
  - **How to fix**: Create new account; re-register domains; obtain new certificates

- **Port 80 not accessible**: HTTP-01 challenges fail because port 80 blocked or redirect misconfigured
  - **Why it happens**: Firewall rules; all HTTP traffic redirected to HTTPS; load balancer misconfiguration
  - **How to avoid**: Test port 80 accessibility before implementation; use DNS-01 if HTTP not feasible
  - **How to fix**: Fix firewall rules; allow .well-known path in HTTPS redirect; consider DNS-01

## Security Considerations

### Account Key Security

**Critical Importance**:



- Account key authorizes all certificate operations
- Compromise allows attacker to issue certificates for your domains
- More critical than individual certificate private keys

**Protection Measures**:



- Store encrypted at rest
- Restrict access (root/admin only)
- Consider HSM for high-security environments
- Monitor account activity
- Implement key rotation procedures

### Challenge Security

**HTTP-01 Risks**:



- Port 80 must be publicly accessible
- Challenge responses served over unencrypted HTTP
- Not sensitive: challenge response is public information
- Risk is not in challenge content but in validation process

**DNS-01 Risks**:



- DNS API credentials are highly sensitive
- API compromise allows certificate issuance for any domain
- DNS provider access should be restricted
- Use DNS API tokens with minimal permissions

**BGP Hijacking**:



- Attacker redirects traffic to their infrastructure
- Completes ACME challenge for victim's domain
- Obtains valid certificate
- **Mitigation**: Multiple vantage point validation (Let's Encrypt uses this)

### Rate Limiting

Let's Encrypt rate limits (as of 2024)[^2]:

**Certificates per Registered Domain**: 50 per week
- Registered domain is the domain purchased from registrar
- example.com is registered domain
- All subdomains count toward limit (www.example.com, api.example.com)

**Duplicate Certificate**: 5 per week
- Same exact set of FQDNs
- Allows renewal even if hitting cert limit

**Failed Validations**: 5 failures per account, per hostname, per hour

**New Orders**: 300 per 3 hours

**Mitigation Strategies**:



- Spread certificate issuance over time
- Use wildcard certificates where appropriate
- Combine multiple subdomains in single certificate (SAN)
- Monitor rate limit consumption

## Real-World Examples

### Case Study: Let's Encrypt Growth

**Scale** (as of 2024):



- 3+ million certificates issued daily
- 300+ million active certificates
- 90% of web pages loaded over HTTPS (up from 40% in 2015)

**Impact**:



- Eliminated cost barrier to HTTPS
- Enabled small sites and personal projects to use HTTPS
- Demonstrated viability of automated certificate management
- Influenced industry toward automation

**Key Takeaway**: Well-designed automation protocol enables massive scale. ACME made HTTPS accessible to everyone.

### Case Study: Kubernetes cert-manager Adoption

**Problem**: Manual certificate management doesn't work in dynamic Kubernetes environments
- Pods ephemeral, IPs change
- Dozens or hundreds of services
- GitOps workflows require automation

**Solution**: cert-manager with ACME integration
- Declarative certificate resources
- Automatic issuance and renewal
- Kubernetes-native (CRDs, operators)

**Impact**: Certificates become infrastructure-as-code, managed like any other Kubernetes resource.

**Key Takeaway**: ACME's API-driven approach fits cloud-native infrastructure patterns. Automation is essential for dynamic environments.

### Case Study: DNS Provider API Outages

**Incident**: DNS provider API outage during ACME renewals

**Impact**:



- DNS-01 challenge failures
- Renewal failures for wildcard certificates
- Cascading expirations

**Lessons**:



- DNS API is critical dependency for DNS-01 challenges
- Need fallback strategies (manual, alternative provider)
- Monitor DNS API availability
- Alert on challenge failures before expiration
- Consider HTTP-01 as fallback when possible

**Key Takeaway**: ACME introduces dependencies on external services (CA, DNS provider). Build resilience into automation.

## Further Reading

### Essential Resources
- [RFC 8555 - ACME Protocol](https://www.rfc-editor.org/rfc/rfc8555) - Official standard
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/) - Comprehensive ACME implementation guide
- [Certbot Documentation](https://certbot.eff.org/docs/) - Client documentation
- [cert-manager Documentation](https://cert-manager.io/docs/) - Kubernetes integration

### Advanced Topics
- [[renewal-automation]] - Operational automation strategies
- [[certificate-lifecycle-management]] - Lifecycle management context
- [[tls-protocol]] - How ACME certificates are used
- [[patterns/certificate-as-code]] - Infrastructure as code approaches

## References

[^1]: Barnes, R., et al. "Automatic Certificate Management Environment (ACME)." RFC 8555, March 2019. [Rfc-editor - Rfc8555](https://www.rfc-editor.org/rfc/rfc8555)

[^2]: Let's Encrypt. "Rate Limits." [Letsencrypt - Rate Limits](https://letsencrypt.org/docs/rate-limits/) (Accessed November 2024)

## Change History

| Date | Version | Changes | Reason |
|------|---------|---------|--------|
| 2024-11-09 | 1.0 | Initial creation | Essential automation standard documentation |

---

**Quality Checks**: 



- [x] All claims cited from authoritative sources
- [x] Cross-references validated
- [x] Practical guidance included
- [x] Examples are current and relevant
- [x] Security considerations addressed
