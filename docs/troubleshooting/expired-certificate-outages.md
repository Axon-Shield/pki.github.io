# Expired Certificate Outages

## TL;DR

Certificate expiry outages are preventable disasters that occur when certificates exceed their validity period. Despite being entirely predictable (every certificate has a known expiration date), they remain one of the most common causes of production incidents. This page covers emergency response procedures, root cause analysis, and prevention strategies to eliminate expiry-related outages.

**Emergency first step**: Identify expired certificates, issue emergency replacements, and deploy immediately. Prevention requires monitoring, automation, and organizational accountability.

## Overview

Certificate expiry is unique among infrastructure failures: it's completely predictable yet continues to cause major outages across the industry. High-profile incidents include LinkedIn (2023), Microsoft Teams (2023), Spotify (2022), and Ericsson's cellular network outage (2018) affecting millions of users.

The paradox: organizations know exactly when certificates will expire, yet still experience outages. This stems from organizational failures, not technical limitations.

## Anatomy of an Expiry Outage

### Timeline of a Typical Incident

**T-90 days**: Certificate approaches expiration
- Monitoring alerts generated (if monitoring exists)
- Alerts potentially ignored, filtered, or routed incorrectly
- No action taken

**T-30 days**: Escalation threshold
- Higher-severity alerts should trigger
- Ownership unclear: who is responsible for renewal?
- Competing priorities delay action

**T-7 days**: Critical threshold
- Emergency procedures should activate
- Change freeze policies may block deployment
- Testing requirements conflict with urgency

**T-0 (Expiry)**: Certificate expires
- TLS handshakes begin failing
- Clients reject connections
- Service becomes unavailable
- War room activated

**T+0 to T+4 hours**: Emergency response
- Identify expired certificate (harder than expected)
- Issue emergency certificate
- Navigate change control processes
- Deploy across all affected systems
- Validate restoration

### Why Expiry Outages Happen

**Organizational failures**:

- **No ownership**: "Someone else's job" mentality
- **Alert fatigue**: Too many low-priority alerts drown critical ones
- **Process gaps**: Manual renewal processes don't scale
- **Change control conflicts**: Security policies block emergency deployments
- **Knowledge silos**: Only one person knows how to renew specific certificates

**Technical failures**:

- **Discovery gaps**: Unknown certificates that can't be renewed
- **Deployment complexity**: Renewal requires coordinating dozens of systems
- **Testing requirements**: Can't validate renewals without production-like environment
- **Automation failures**: Automated renewal fails silently weeks before expiry

**Communication failures**:

- **Stakeholder notifications**: Service owners unaware of expiring certificates
- **Cross-team dependencies**: Certificate used by multiple teams
- **Vendor coordination**: Third-party systems need advance notice
- **Documentation gaps**: Renewal procedures outdated or incomplete

## Emergency Response Procedures

### Phase 1: Immediate Triage (0-15 minutes)

**Step 1: Confirm certificate expiry**
```bash
# Quick verification of expired certificate
echo | openssl s_client -connect api.example.com:443 -servername api.example.com 2>/dev/null | openssl x509 -noout -dates

# Output shows:
# notBefore=Jan  1 00:00:00 2024 GMT
# notAfter=Nov  8 23:59:59 2025 GMT  # If this is in the past, certificate expired

# Check current time vs expiry
current_time=$(date -u +%s)
cert_expiry=$(date -d "Nov 8 23:59:59 2025" +%s)
if [ $current_time -gt $cert_expiry ]; then
    echo "EXPIRED: Certificate expired $((($current_time - $cert_expiry) / 86400)) days ago"
fi
```

**Step 2: Assess blast radius**
```python
def assess_outage_scope(expired_cert_fingerprint: str) -> OutageScope:
    """
    Determine which services are affected by expired certificate
    """
    scope = OutageScope()
    
    # Query inventory for all locations using this certificate
    locations = certificate_inventory.find_by_fingerprint(
        expired_cert_fingerprint
    )
    
    for location in locations:
        # Check if service is down
        health_status = check_service_health(location.hostname, location.port)
        
        if health_status.down:
            scope.affected_services.append({
                'hostname': location.hostname,
                'port': location.port,
                'service_name': location.service_name,
                'criticality': location.criticality,
                'last_working': health_status.last_successful_check
            })
    
    # Estimate business impact
    scope.affected_users = sum(s['user_count'] for s in scope.affected_services)
    scope.revenue_impact_per_hour = sum(
        s['revenue_per_hour'] for s in scope.affected_services
    )
    
    return scope
```

**Step 3: Activate incident response**
```yaml
incident_response:
  severity: P1  # Certificate expiry affecting production is always P1
  
  immediate_actions:
    - page: platform-sre-oncall
    - page: security-oncall
    - notify: service-owner
    - create: incident-channel  # #incident-cert-expiry-2025-11-09
    
  communication_plan:
    internal:
      - post_to: #incidents
      - notify: engineering-leadership
      - update: status_page
    
    external:
      - update: customer_status_page
      - notify: enterprise_customers  # If contractual SLA breach
      
  roles:
    incident_commander: platform-sre-oncall
    technical_lead: pki-team-lead
    communications: customer-support-lead
```

### Phase 2: Emergency Certificate Issuance (15-45 minutes)

**Option A: Standard CA (fastest for known certificates)**
```bash
# Generate CSR from existing private key (if available)
openssl req -new \
    -key /backup/api.example.com.key \
    -out emergency-renewal.csr \
    -subj "/CN=api.example.com" \
    -addext "subjectAltName=DNS:api.example.com,DNS:www.api.example.com"

# Submit to CA (automated ACME if available)
certbot certonly \
    --manual \
    --preferred-challenges dns \
    --domain api.example.com \
    --domain www.api.example.com \
    --csr emergency-renewal.csr

# Or manual submission to enterprise CA
curl -X POST https://ca.corp.example.com/issue \
    -H "Authorization: Bearer $EMERGENCY_TOKEN" \
    -F "csr=@emergency-renewal.csr" \
    -F "profile=tls-server-emergency" \
    -F "validity_days=90" \
    -o new-cert.pem
```

**Option B: Generate new keypair (if private key unavailable)**
```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

def generate_emergency_certificate(
    common_name: str,
    san_list: List[str],
    validity_days: int = 90
) -> Tuple[bytes, bytes]:
    """
    Generate emergency self-signed certificate or CSR
    Use only as last resort when CA unavailable
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Use 2048 for speed in emergency
    )
    
    # Build CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Emergency"),
        ])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(name) for name in san_list
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Serialize private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Emergency: no passphrase
    )
    
    # Serialize CSR
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    
    return private_key_pem, csr_pem

# Usage in emergency
private_key, csr = generate_emergency_certificate(
    common_name="api.example.com",
    san_list=["api.example.com", "www.api.example.com"]
)

# Save for emergency CA submission
with open("/tmp/emergency.key", "wb") as f:
    f.write(private_key)
with open("/tmp/emergency.csr", "wb") as f:
    f.write(csr)
```

**Option C: Temporary self-signed certificate (absolute last resort)**
```bash
# ONLY use if:
# 1. CA completely unavailable
# 2. Clients can temporarily accept self-signed
# 3. Will replace with CA-signed within 24 hours

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout emergency-selfsigned.key \
    -out emergency-selfsigned.crt \
    -days 7 \
    -subj "/CN=api.example.com/O=Emergency Temporary" \
    -addext "subjectAltName=DNS:api.example.com"

# WARNING: Clients will reject unless configured to trust
# Document this as technical debt requiring immediate fix
```

### Phase 3: Emergency Deployment (45-90 minutes)

**Deployment strategies by risk level**:

**High-risk (revenue-critical services)**:
```bash
#!/bin/bash
# emergency-cert-deploy.sh - Coordinated deployment for critical services

set -euo pipefail

CERT_FILE="/emergency/new-cert.pem"
KEY_FILE="/emergency/new-cert.key"
CHAIN_FILE="/emergency/ca-chain.pem"

# Validation before deployment
echo "=== Pre-deployment validation ==="
openssl x509 -in "$CERT_FILE" -noout -subject -dates -fingerprint

# Verify certificate and key match
cert_modulus=$(openssl x509 -noout -modulus -in "$CERT_FILE" | openssl md5)
key_modulus=$(openssl rsa -noout -modulus -in "$KEY_FILE" | openssl md5)

if [ "$cert_modulus" != "$key_modulus" ]; then
    echo "ERROR: Certificate and key don't match!"
    exit 1
fi

# Verify certificate not expired
if ! openssl x509 -checkend 0 -noout -in "$CERT_FILE"; then
    echo "ERROR: New certificate is already expired!"
    exit 1
fi

# Backup existing certificates
echo "=== Backing up existing certificates ==="
BACKUP_DIR="/backup/certs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

for target in "${DEPLOYMENT_TARGETS[@]}"; do
    ssh "$target" "cp /etc/ssl/certs/server.crt $BACKUP_DIR/server.crt.$target"
    ssh "$target" "cp /etc/ssl/private/server.key $BACKUP_DIR/server.key.$target"
done

# Deploy to canary first
echo "=== Deploying to canary ==="
CANARY="${DEPLOYMENT_TARGETS[0]}"

scp "$CERT_FILE" "$CANARY:/etc/ssl/certs/server.crt"
scp "$KEY_FILE" "$CANARY:/etc/ssl/private/server.key"
scp "$CHAIN_FILE" "$CANARY:/etc/ssl/certs/ca-chain.pem"

# Reload service on canary
ssh "$CANARY" "systemctl reload nginx"

# Wait and verify canary
echo "=== Verifying canary ==="
sleep 10

if ! curl -vI "https://$CANARY" 2>&1 | grep -q "SSL certificate verify ok"; then
    echo "ERROR: Canary verification failed!"
    # Rollback canary
    ssh "$CANARY" "cp $BACKUP_DIR/server.crt.$CANARY /etc/ssl/certs/server.crt"
    ssh "$CANARY" "cp $BACKUP_DIR/server.key.$CANARY /etc/ssl/private/server.key"
    ssh "$CANARY" "systemctl reload nginx"
    exit 1
fi

echo "=== Canary successful, deploying to fleet ==="

# Deploy to remaining targets in parallel
for target in "${DEPLOYMENT_TARGETS[@]:1}"; do
    (
        scp "$CERT_FILE" "$target:/etc/ssl/certs/server.crt"
        scp "$KEY_FILE" "$target:/etc/ssl/private/server.key"
        scp "$CHAIN_FILE" "$target:/etc/ssl/certs/ca-chain.pem"
        ssh "$target" "systemctl reload nginx"
        
        # Verify each target
        if curl -vI "https://$target" 2>&1 | grep -q "SSL certificate verify ok"; then
            echo "✓ $target deployed successfully"
        else
            echo "✗ $target verification failed"
        fi
    ) &
done

wait

echo "=== Deployment complete ==="
```

**Medium-risk (internal services)**:
```python
import asyncio
import aiohttp
from typing import List, Dict

async def deploy_certificate_parallel(
    targets: List[Dict],
    cert_path: str,
    key_path: str
) -> Dict[str, bool]:
    """
    Deploy certificate to multiple targets in parallel
    """
    results = {}
    
    async def deploy_to_target(target: Dict) -> bool:
        """Deploy to single target"""
        try:
            # Copy certificate files
            await run_ssh_command(
                target['hostname'],
                f"cat > /tmp/new-cert.pem",
                stdin=open(cert_path, 'rb')
            )
            
            await run_ssh_command(
                target['hostname'],
                f"cat > /tmp/new-key.pem",
                stdin=open(key_path, 'rb')
            )
            
            # Install certificates
            await run_ssh_command(
                target['hostname'],
                "sudo cp /tmp/new-cert.pem /etc/ssl/certs/server.crt && "
                "sudo cp /tmp/new-key.pem /etc/ssl/private/server.key && "
                "sudo systemctl reload nginx"
            )
            
            # Verify
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{target['hostname']}/health",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    return response.status == 200
                    
        except Exception as e:
            logger.error(f"Deployment to {target['hostname']} failed: {e}")
            return False
    
    # Deploy in parallel
    tasks = [deploy_to_target(target) for target in targets]
    results_list = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Map results
    for target, result in zip(targets, results_list):
        results[target['hostname']] = (
            result if isinstance(result, bool) else False
        )
    
    return results
```

### Phase 4: Verification and Monitoring (90-120 minutes)

**Comprehensive verification checklist**:

```python
class EmergencyDeploymentVerification:
    """
    Verify emergency certificate deployment was successful
    """
    
    def verify_all(self, deployment: EmergencyDeployment) -> VerificationReport:
        """
        Run all verification checks
        """
        report = VerificationReport()
        
        # 1. Certificate validity
        report.add_check(
            "Certificate Validity",
            self.verify_certificate_valid(deployment.cert_path)
        )
        
        # 2. Certificate matches private key
        report.add_check(
            "Key Match",
            self.verify_key_match(deployment.cert_path, deployment.key_path)
        )
        
        # 3. Trust chain complete
        report.add_check(
            "Trust Chain",
            self.verify_trust_chain(deployment.cert_path, deployment.chain_path)
        )
        
        # 4. All targets serving new certificate
        report.add_check(
            "Deployment Coverage",
            self.verify_all_targets_updated(deployment.targets)
        )
        
        # 5. TLS handshake successful
        report.add_check(
            "TLS Handshake",
            self.verify_tls_handshake(deployment.targets)
        )
        
        # 6. No certificate warnings
        report.add_check(
            "No Warnings",
            self.verify_no_warnings(deployment.targets)
        )
        
        # 7. Application health restored
        report.add_check(
            "Application Health",
            self.verify_application_health(deployment.targets)
        )
        
        # 8. Error rates normalized
        report.add_check(
            "Error Rates",
            self.verify_error_rates_normal(deployment.service_name)
        )
        
        return report
    
    def verify_certificate_valid(self, cert_path: str) -> CheckResult:
        """Verify certificate is currently valid"""
        cert = load_certificate(cert_path)
        now = datetime.now(timezone.utc)
        
        if now < cert.not_before:
            return CheckResult(
                passed=False,
                message=f"Certificate not yet valid (starts {cert.not_before})"
            )
        
        if now > cert.not_after:
            return CheckResult(
                passed=False,
                message=f"Certificate expired at {cert.not_after}"
            )
        
        days_until_expiry = (cert.not_after - now).days
        
        return CheckResult(
            passed=True,
            message=f"Certificate valid for {days_until_expiry} more days",
            details={'expires': cert.not_after.isoformat()}
        )
    
    def verify_all_targets_updated(
        self,
        targets: List[str]
    ) -> CheckResult:
        """Verify all targets serving new certificate"""
        new_fingerprint = self.get_certificate_fingerprint(self.cert_path)
        
        mismatches = []
        for target in targets:
            live_fingerprint = self.get_live_certificate_fingerprint(target)
            
            if live_fingerprint != new_fingerprint:
                mismatches.append({
                    'target': target,
                    'expected': new_fingerprint,
                    'actual': live_fingerprint
                })
        
        if mismatches:
            return CheckResult(
                passed=False,
                message=f"{len(mismatches)} targets not serving new certificate",
                details={'mismatches': mismatches}
            )
        
        return CheckResult(
            passed=True,
            message=f"All {len(targets)} targets serving new certificate"
        )
```

**Post-deployment monitoring**:
```yaml
monitoring_checklist:
  immediate:
    - metric: tls_handshake_success_rate
      threshold: "> 99.9%"
      duration: 15_minutes
      
    - metric: http_error_rate_5xx
      threshold: "< 0.1%"
      duration: 15_minutes
      
    - metric: certificate_expiry_seconds
      threshold: "> 7_days"
      alert_if_below: true
  
  sustained:
    - metric: application_request_latency_p99
      threshold: "< baseline + 10%"
      duration: 1_hour
      
    - metric: customer_reported_issues
      threshold: "< 5"
      duration: 4_hours
      
    - metric: ssl_verification_errors
      threshold: "0"
      duration: 4_hours
```

### Phase 5: Communication and Documentation

**Incident timeline documentation**:
```markdown
# Incident Report: Certificate Expiry - api.example.com

## Timeline (All times UTC)

**2025-11-09 14:23** - Certificate expired
**2025-11-09 14:31** - First customer reports received
**2025-11-09 14:35** - Monitoring alerts triggered (8 min delay)
**2025-11-09 14:42** - Incident declared, war room activated
**2025-11-09 14:50** - Expired certificate identified
**2025-11-09 15:05** - Emergency CSR generated and submitted
**2025-11-09 15:23** - New certificate issued by CA
**2025-11-09 15:35** - Certificate deployed to canary
**2025-11-09 15:42** - Canary validated, fleet deployment started
**2025-11-09 16:08** - All targets updated and verified
**2025-11-09 16:30** - Service fully restored, incident closed
**2025-11-09 18:00** - Post-mortem scheduled

## Impact

- **Duration**: 1 hour 45 minutes (14:23 - 16:08 UTC)
- **Affected Services**: api.example.com (REST API)
- **User Impact**: ~15,000 API requests failed
- **Revenue Impact**: Estimated $45,000 (based on transaction volume)
- **Customer Reports**: 37 support tickets

## Root Cause

Certificate api.example.com expired on 2025-11-09 14:23 UTC.

**Contributing factors**:
1. Automated renewal failed 45 days prior (logs show CA rate limit)
2. Backup manual process not executed
3. Monitoring alerts were routed to unmaintained email alias
4. Certificate not included in weekly expiry reports (discovery gap)

## Resolution

Emergency certificate issued and deployed across all 23 API gateway instances.

## Follow-up Actions

| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| Add cert to discovery inventory | PKI Team | 2025-11-11 | Done |
| Fix monitoring alert routing | SRE Team | 2025-11-12 | In Progress |
| Implement auto-renewal retry logic | Platform Team | 2025-11-20 | Planned |
| Audit all certificates for discovery gaps | Security Team | 2025-11-30 | Planned |
```

## Root Cause Analysis

### The Five Whys

**Problem**: Production certificate expired causing outage

**Why 1**: Why did the certificate expire?
- Renewal process was not executed

**Why 2**: Why was renewal not executed?
- Automated renewal failed 45 days earlier

**Why 3**: Why did automated renewal fail?
- CA rate limit exceeded due to retry loop bug

**Why 4**: Why didn't backup manual process trigger?
- Manual process depends on email alerts to unmaintained alias

**Why 5**: Why were alerts going to unmaintained alias?
- Team reorganization changed ownership, documentation not updated

**Root cause**: Organizational failure to maintain alert routing and backup processes, compounded by insufficient monitoring of automation health.

### Common Root Causes

**Technical**:
```python
@dataclass
class TechnicalRootCause:
    """Common technical causes of expiry outages"""
    
    # Automation failures
    automation_failure = "ACME client stopped working, fails silently"
    rate_limiting = "Hit CA rate limits, renewal blocked"
    credential_expiry = "API credentials for CA expired"
    
    # Discovery failures
    unknown_certificate = "Certificate not in inventory system"
    shadow_it = "Certificate created outside standard process"
    forgotten_certificate = "Certificate on decommissioned-but-running system"
    
    # Deployment failures
    deployment_complexity = "Renewal requires coordinating 50+ systems"
    change_freeze = "Change control policy blocked deployment"
    testing_requirements = "No test environment to validate renewal"
```

**Organizational**:
```python
@dataclass
class OrganizationalRootCause:
    """Common organizational causes"""
    
    # Ownership failures
    unclear_ownership = "No one knows who owns this certificate"
    team_turnover = "Person who knew how to renew left company"
    cross_team_dependencies = "Certificate used by 3 teams, coordination failed"
    
    # Process failures
    manual_processes = "Renewal requires manual steps that were skipped"
    competing_priorities = "Renewal deprioritized for feature work"
    alert_fatigue = "Too many false positives, real alert ignored"
    
    # Communication failures
    notification_gaps = "Stakeholders not notified of upcoming expiry"
    documentation_rot = "Runbook outdated, incorrect procedures"
    knowledge_silos = "Only one person knows renewal procedure"
```

## Prevention Strategies

### Layer 1: Monitoring and Alerting

**Multi-tier alert strategy**:
```yaml
alert_tiers:
  # Tier 1: Early warning (90 days)
  early_warning:
    trigger: 90_days_before_expiry
    severity: info
    action: create_renewal_ticket
    recipients:
      - certificate_owner
      - pki_team
    
  # Tier 2: Action required (60 days)
  action_required:
    trigger: 60_days_before_expiry
    severity: warning
    action: escalate_to_manager
    recipients:
      - certificate_owner
      - owner_manager
      - pki_team
    frequency: weekly
    
  # Tier 3: Urgent (30 days)
  urgent:
    trigger: 30_days_before_expiry
    severity: high
    action: page_oncall
    recipients:
      - certificate_owner
      - owner_manager
      - director_infrastructure
      - pki_team
    frequency: daily
    
  # Tier 4: Critical (14 days)
  critical:
    trigger: 14_days_before_expiry
    severity: critical
    action: emergency_process
    recipients:
      - all_engineering
      - vp_engineering
      - cto
    frequency: every_6_hours
    
  # Tier 5: Emergency (7 days)
  emergency:
    trigger: 7_days_before_expiry
    severity: p1
    action: immediate_renewal_required
    recipients:
      - incident_response_team
      - executive_team
    frequency: every_hour
```

**Alert validation**:
```python
class AlertValidation:
    """
    Ensure alerts are actually working
    """
    
    def validate_alert_pipeline(self):
        """
        Test alert delivery end-to-end
        """
        # Create test certificate expiring in 89 days
        test_cert = self.create_test_certificate(days_valid=89)
        
        # Register in monitoring
        self.register_certificate(test_cert)
        
        # Wait for 90-day alert
        alert_received = self.wait_for_alert(
            cert_id=test_cert.id,
            threshold="90_days",
            timeout=timedelta(hours=2)
        )
        
        if not alert_received:
            raise AlertPipelineFailure(
                "90-day alert not received within 2 hours"
            )
        
        # Validate alert content
        assert alert_received.severity == "info"
        assert alert_received.contains_renewal_instructions
        assert test_cert.owner in alert_received.recipients
        
        # Cleanup test certificate
        self.remove_certificate(test_cert)
```

### Layer 2: Automation

**Automated renewal with retry logic**:
```python
class ResilientRenewalSystem:
    """
    Certificate renewal with comprehensive error handling
    """
    
    def __init__(self):
        self.max_retries = 5
        self.retry_delays = [300, 900, 3600, 14400, 86400]  # 5m, 15m, 1h, 4h, 24h
        self.notification_system = NotificationSystem()
    
    async def renew_certificate(
        self,
        cert: Certificate
    ) -> RenewalResult:
        """
        Attempt certificate renewal with retry logic
        """
        attempt = 0
        last_error = None
        
        while attempt < self.max_retries:
            try:
                # Check if already renewed
                if self.recently_renewed(cert):
                    return RenewalResult(
                        success=True,
                        message="Certificate already renewed"
                    )
                
                # Pre-flight checks
                self.validate_renewal_prerequisites(cert)
                
                # Attempt renewal
                new_cert = await self.request_new_certificate(cert)
                
                # Validate new certificate
                self.validate_new_certificate(new_cert, cert)
                
                # Stage for deployment
                await self.stage_certificate(new_cert)
                
                # Success
                await self.notification_system.notify_success(cert, new_cert)
                
                return RenewalResult(
                    success=True,
                    certificate=new_cert,
                    attempt=attempt + 1
                )
                
            except RateLimitError as e:
                # Rate limited by CA
                last_error = e
                await self.notification_system.notify_rate_limit(
                    cert, attempt, self.retry_delays[attempt]
                )
                
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delays[attempt])
                    attempt += 1
                else:
                    break
                    
            except CAUnavailableError as e:
                # CA temporarily down
                last_error = e
                await self.notification_system.notify_ca_unavailable(
                    cert, attempt
                )
                
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delays[attempt])
                    attempt += 1
                else:
                    break
                    
            except ValidationError as e:
                # Validation failed (likely configuration issue)
                last_error = e
                await self.notification_system.notify_validation_failure(
                    cert, str(e)
                )
                # Don't retry validation errors
                break
                
            except Exception as e:
                # Unexpected error
                last_error = e
                await self.notification_system.notify_unexpected_error(
                    cert, str(e)
                )
                
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delays[attempt])
                    attempt += 1
                else:
                    break
        
        # All retries exhausted
        await self.notification_system.notify_renewal_failure(
            cert, last_error, attempt + 1
        )
        
        # Escalate to human
        await self.create_urgent_ticket(cert, last_error)
        
        return RenewalResult(
            success=False,
            error=last_error,
            attempts=attempt + 1
        )
```

### Layer 3: Organizational Controls

**Ownership assignment**:
```yaml
certificate_ownership:
  assignment_rules:
    # Automatic assignment based on certificate attributes
    - condition: subject_cn.endswith('.api.example.com')
      owner_team: platform-api-team
      backup_owner: platform-sre
      
    - condition: subject_cn.endswith('.internal.example.com')
      owner_team: infrastructure-team
      backup_owner: security-team
      
    - condition: usage == 'code_signing'
      owner_team: security-team
      backup_owner: release-engineering
  
  ownership_validation:
    frequency: quarterly
    process:
      - export_all_certificates_with_owners
      - send_to_each_team_lead
      - require_acknowledgment_within_14_days
      - escalate_unacknowledged_to_director
  
  handoff_process:
    when_person_leaves:
      - identify_owned_certificates
      - reassign_to_team
      - update_documentation
      - test_renewal_procedures
      - confirm_new_owner_trained
```

**Change control exemptions**:
```yaml
emergency_exemptions:
  certificate_expiry:
    automatic_approval:
      conditions:
        - certificate_expires_within: 7_days
        - service_criticality: high_or_critical
        - certificate_type: production
      
      requirements:
        - notify: change_advisory_board
        - document: emergency_justification
        - require: post_incident_review
      
      deployment_restrictions:
        - must_use: canary_deployment
        - must_verify: before_full_rollout
        - must_monitor: for_4_hours_minimum
      
    expedited_approval:
      conditions:
        - certificate_expires_within: 30_days
        - normal_change_window_conflict: true
      
      process:
        - submit: expedited_change_request
        - approval_required_within: 4_hours
        - approved_by: service_owner_and_security_lead
```

### Layer 4: Testing and Validation

**Chaos engineering for certificate expiry**:
```python
class CertificateExpiryGameDay:
    """
    Practice certificate expiry scenarios
    """
    
    def run_game_day(self):
        """
        Execute game day exercise
        """
        # Select non-critical test service
        test_service = self.select_test_service(
            criticality="low",
            has_redundancy=True
        )
        
        # Replace certificate with one expiring in 1 hour
        original_cert = test_service.get_certificate()
        expiring_cert = self.create_short_lived_certificate(
            template=original_cert,
            validity=timedelta(hours=1)
        )
        
        # Deploy expiring certificate
        test_service.deploy_certificate(expiring_cert)
        
        print(f"""
        === Certificate Expiry Game Day ===
        
        Service: {test_service.name}
        Expires: {expiring_cert.not_after}
        Time until expiry: 1 hour
        
        Objectives:
        1. Detect expiring certificate via monitoring
        2. Generate emergency renewal
        3. Deploy renewed certificate
        4. Restore service to normal
        
        Success criteria:
        - Detection within 5 minutes of alert threshold
        - Renewal completed before expiry
        - Service experiences < 1 minute downtime
        
        Starting game day timer...
        """)
        
        # Monitor team response
        response_metrics = self.monitor_team_response(
            test_service,
            expiring_cert,
            timeout=timedelta(hours=2)
        )
        
        # Generate report
        self.generate_game_day_report(response_metrics)
        
        # Restore original certificate
        test_service.deploy_certificate(original_cert)
```

## Lessons from Major Incidents

### Case Study: LinkedIn (2023)

**What happened**:

- Certificate expired during business hours
- Global outage affecting millions of users
- Duration: Several hours

**Contributing factors**:

- Automated renewal process had undiscovered bug
- Backup manual process not executed
- Monitoring alerts didn't escalate appropriately

**Lessons learned**:
1. Test automated renewal regularly in production-like environment
2. Require manual validation that automated renewal succeeded
3. Implement escalation for failures in automated processes

### Case Study: Ericsson (2018)

**What happened**:

- Software certificate expired in mobile network equipment
- Affected 32 million mobile subscribers across UK and Japan
- Duration: 12+ hours

**Contributing factors**:

- Certificate embedded in software
- No monitoring for embedded certificate expiry
- Global deployment meant rolling back affected millions

**Lessons learned**:
1. Inventory ALL certificates, including embedded in software/firmware
2. Monitor certificate expiry in deployed code, not just infrastructure
3. Test certificate rotation in production-representative environment

### Case Study: Microsoft Teams (2023)

**What happened**:

- Authentication certificate expired
- Users unable to access Teams
- Duration: ~4 hours

**Contributing factors**:

- Certificate in authentication flow
- Complex deployment requiring coordination across multiple services

**Lessons learned**:
1. Authentication certificates require extra scrutiny (affect all users)
2. Practice emergency deployment procedures for authentication services
3. Maintain emergency communication channels that don't depend on affected service

## Runbook: Certificate Expiry Response

```markdown
# Runbook: Certificate Expiry Incident Response

## Detection

**Symptoms**:
- TLS handshake failures
- "Certificate expired" errors in logs
- HTTP 502/503 errors from load balancers
- Monitoring alerts: "certificate_expired"

**Verification**:
```bash
# Check certificate expiry
echo | openssl s_client -connect $HOSTNAME:443 -servername $HOSTNAME 2>/dev/null | openssl x509 -noout -dates

# Check current time vs expiry
date -u
```

## Immediate Actions (First 15 minutes)

1. **Declare incident**: P1 severity
2. **Page**: Platform SRE, Security team, Service owner
3. **Create**: Incident channel (#incident-cert-expiry-YYYYMMDD)
4. **Identify**: Which certificate expired
5. **Assess**: Blast radius - what services affected

## Resolution Steps

### Option 1: Cached Valid Certificate Available

```bash
# Check if valid certificate exists in backup
find /backup/certs -name "*$HOSTNAME*" -mtime -90

# Verify backup certificate is valid
openssl x509 -in /backup/certs/hostname.crt -noout -dates

# Deploy backup certificate
./scripts/deploy-certificate.sh --cert /backup/certs/hostname.crt --key /backup/certs/hostname.key
```

### Option 2: Request Emergency Certificate

```bash
# Generate CSR
openssl req -new -key /etc/ssl/private/server.key -out emergency.csr -subj "/CN=$HOSTNAME"

# Submit to CA (ACME or manual)
certbot certonly --csr emergency.csr

# Deploy new certificate
./scripts/deploy-certificate.sh --cert ./0001_cert.pem --key /etc/ssl/private/server.key
```

### Option 3: Self-Signed Temporary (Last Resort)

```bash
# Generate temporary self-signed (7 day validity)
openssl req -x509 -newkey rsa:2048 -nodes -keyout temp.key -out temp.crt -days 7 -subj "/CN=$HOSTNAME"

# Deploy temporary
./scripts/deploy-certificate.sh --cert temp.crt --key temp.key

# CREATE URGENT TICKET: Replace temporary with CA-signed within 24 hours
```

## Verification

```bash
# Verify certificate deployed
echo | openssl s_client -connect $HOSTNAME:443 -servername $HOSTNAME 2>/dev/null | openssl x509 -noout -subject -dates

# Verify service health
curl -I [$hostname - Health](https://$HOSTNAME/health)

# Check error rates returned to normal
./scripts/check-metrics.sh --service $SERVICE_NAME --metric error_rate_5xx
```

## Communication

- Update incident channel every 15 minutes
- Update status page
- Notify stakeholders when resolved
- Schedule post-mortem within 48 hours

## Post-Incident

1. Document timeline in incident ticket
2. Identify root cause
3. Create prevention action items
4. Update runbook with lessons learned
5. Conduct post-mortem meeting
```

## Conclusion

Certificate expiry outages are preventable through proper monitoring, automation, and organizational discipline. The technical solutions exist and are well-understood; failures are almost always organizational. Prevention requires:

1. **Comprehensive discovery**: Can't renew what you don't know exists
2. **Reliable monitoring**: Alerts must reach responsible parties
3. **Automated renewal**: Manual processes don't scale
4. **Clear ownership**: Someone must be accountable
5. **Regular testing**: Practice emergency response procedures

The investment in prevention is orders of magnitude smaller than the cost of outages. A certificate expiry outage is always a failure of process, never a failure of technology.
