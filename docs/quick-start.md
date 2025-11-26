---
title: Quick Start Guide
last_updated: 2025-11-10
---

# Quick Start Guide

**Choose your role to see relevant scenarios and next steps:**

- [For Executives](#for-executives) - Business case, vendor evaluation, ROI measurement
- [For Security Leaders](#for-security-leaders) - Implementation planning, risk assessment, compliance
- [For Engineers](#for-engineers) - Technical implementation, troubleshooting, architecture

---

## For Executives

### "We need to automate certificate management - where do we start?"

**Your situation:** Certificate-related outages are affecting revenue, or you're planning cloud migration and current manual processes won't scale.

**Next steps:**

1. Read the [Executive Summary](index.md) to understand ROI and strategic value
2. Review [Case Studies](architecture/case-studies.md) to see implementations at similar organizations
3. Have your security leadership review the business case and technical requirements
4. [Contact Axon Shield](https://axonshield.com/contact) for implementation assessment

**Timeline:** Initial assessment takes 2-4 weeks to establish baseline and define success metrics.

**Expected outcome:** Clear business case with ROI projections, vendor shortlist, and implementation roadmap.

---

### "We had a certificate outage - how do we prevent the next one?"

**Your situation:** Certificate expiration caused service disruption. Board/customers are asking what you're doing to prevent recurrence.

**Immediate actions:**

1. Review [Expired Certificate Outages](troubleshooting/expired-certificate-outages.md) for emergency response procedures
2. Conduct post-mortem to understand root cause (inventory gap? monitoring failure? manual process breakdown?)
3. Implement immediate monitoring: [Monitoring and Alerting](operations/monitoring-and-alerting.md)

**Short-term (30-60 days):**

1. Complete certificate inventory: [Inventory and Discovery](operations/inventory-and-discovery.md)
2. Implement automated expiry monitoring with 30-day advance alerts
3. Document all certificates and ownership

**Long-term (6-12 months):**

1. Plan automation implementation: [Renewal Automation](operations/renewal-automation.md)
2. Evaluate platforms: [Vendor Comparison Matrix](vendors/vendor-comparison-matrix.md)
3. Execute automation rollout with external expertise

**Key message for board:** "We're implementing comprehensive certificate management automation to eliminate manual processes that caused this outage. Expected completion: [date]. Investment: [amount]. ROI: [payback period]."

---

### "How do we measure ROI and success of automation?"

**Your situation:** You're implementing or considering certificate automation and need metrics to justify investment and track progress.

**Establish baseline (before automation):**

- How many certificates do you currently have? (Most organizations underestimate by 3-10x)
- What does manual management cost annually? (Labor hours × hourly rate)
- What was your last certificate-related outage cost? (Revenue loss + recovery cost + reputation)
- How long does certificate provisioning take? (Time from request to deployment)

**Success metrics to track monthly:**

**Operational metrics:**

- Certificate provisioning time (target: <5 minutes vs. weeks before)
- Certificate management overhead (target: 90%+ reduction in FTE hours)
- Expiration-related outages (target: zero)
- Inventory accuracy (target: 99%+)

**Financial metrics:**

- Labor cost reduction (baseline cost - current cost)
- Outage avoidance value (previous annual outage cost × probability)
- ROI calculation: (Annual savings + avoided costs) / Implementation cost

**Strategic metrics:**

- Deployment velocity (features blocked on certificates before vs. after)
- Cloud migration progress (certificates no longer bottleneck)
- Compliance audit efficiency (audit prep time before vs. after)

**See detailed framework:** [Success Metrics and KPIs](strategy/success-metrics.md)

**Reporting cadence:**

- Weekly: Operational metrics to implementation team
- Monthly: Progress dashboard to security leadership
- Quarterly: ROI and strategic impact to executive leadership

---

### "We're evaluating vendors - what should we consider?"

**Your situation:** You have budget approval and need to select a certificate management platform.

**Evaluation framework:**

**1. Understand your requirements first (before vendor demos):**

- Scale: How many certificates? How fast are you growing?
- Architecture: Single cloud, multi-cloud, hybrid, on-premises?
- Use cases: Web servers only, or also service mesh, IoT, code signing, physical access?
- Compliance: What regulatory requirements apply? (PCI-DSS, SOC 2, FedRAMP, etc.)
- Integration: What systems need certificate automation? (Kubernetes, AWS, Azure, load balancers, etc.)

**2. Review vendor capabilities objectively:**

- [Vendor Comparison Matrix](vendors/vendor-comparison-matrix.md) - Feature comparison across major platforms
- Individual vendor deep-dives: [Venafi](vendors/venafi-platform.md), [DigiCert](vendors/digicert-certcentral.md), [Keyfactor](vendors/keyfactor-command.md), [HashiCorp Vault](vendors/hashicorp-vault-pki.md)

**3. Key evaluation criteria:**

**Technical capabilities:**

- Certificate discovery (can it find existing certificates automatically?)
- Automation coverage (which systems/platforms supported?)
- CA integration (works with your existing or planned CAs?)
- API quality (for custom integrations)

**Operational considerations:**

- Implementation complexity (timeline and resource requirements)
- Ongoing operational overhead (how much care and feeding?)
- Vendor support quality (response times, expertise level)
- Migration path (how do you get from current state to automated?)

**Financial factors:**

- Total cost of ownership (licensing + professional services + ongoing maintenance)
- Pricing model (per certificate? per server? per user?)
- Hidden costs (training, custom integrations, support contracts)

**Strategic fit:**

- Vendor roadmap alignment with your architecture direction
- Multi-cloud strategy support
- Acquisition/integration history (will vendor be around in 5 years?)

**4. Validate vendor claims:**

- Request reference customers with similar scale/architecture
- Test POC with YOUR infrastructure (not vendor's demo environment)
- Verify support responsiveness during POC
- Check actual implementation timelines from references (not vendor projections)

**5. Common pitfalls to avoid:**

- Selecting based on features list without testing in your environment
- Underestimating implementation complexity and timeline
- Not budgeting for professional services (you'll need them)
- Choosing cheapest option without considering TCO
- Vendor lock-in without clear migration path

**Our recommendation:** [Contact us](https://axonshield.com/contact) for unbiased vendor assessment. We've implemented all major platforms at enterprise scale and know which vendor claims are real versus marketing.

---

## For Security Leaders

### "I need to assess our PKI readiness for automation"

**Your situation:** Executive leadership wants certificate automation, but you need to understand current state and requirements before committing to timeline/budget.

**Assessment framework:**

**1. Inventory and discovery (2-4 weeks):**

- How many certificates do we actually have? Where are they deployed?
- Tools: [Inventory and Discovery](operations/inventory-and-discovery.md)
- Common finding: Organizations discover 3-10x more certificates than they thought

**2. Architecture assessment (1-2 weeks):**

- What CA infrastructure do we have? (Internal PKI? Cloud-only? Hybrid?)
- Review: [CA Architecture](implementation/ca-architecture.md)
- Key questions: Root CA governance, intermediate CA strategy, HSM requirements

**3. Process documentation (1-2 weeks):**

- How do certificates get issued today? (Document all workflows)
- How many different processes exist? (Usually 5-15 different workflows)
- Who owns what? (Org chart of certificate responsibilities)

**4. Risk assessment (1 week):**

- What's our historical outage frequency? Cost?
- What's our compliance posture? Any audit findings?
- Review: [Threat Models and Attack Vectors](security/threat-models-and-attack-vectors.md)

**5. Requirements definition (1-2 weeks):**

- What must automation accomplish? (Zero outages? Faster provisioning? Compliance?)
- What constraints exist? (Regulatory? Technical? Organizational?)
- What's our risk tolerance? (Aggressive automation vs. cautious approach?)

**Deliverable:** PKI Readiness Report with:

- Current state assessment (inventory, processes, risks)
- Gap analysis (where are we vs. where we need to be)
- Requirements definition (functional and non-functional)
- Vendor evaluation criteria
- Implementation roadmap with phases
- Budget estimate (platform + services + internal labor)

**Timeline:** 6-10 weeks for comprehensive assessment

---

### "We're implementing zero-trust - how does PKI fit?"

**Your situation:** Zero-trust initiative requires strong identity for all services, and you need certificate-based authentication strategy.

**Understanding the connection:**

Zero-trust principle: "Never trust, always verify" - every connection must prove identity cryptographically.

**Certificate requirements for zero-trust:**

- Every service needs identity certificate (not just edge services)
- Short-lived certificates (24-48 hours typical)
- Automatic rotation (zero manual intervention)
- Service mesh integration (Istio, Linkerd, Consul)

**Implementation path:**

**1. Understand zero-trust architecture:**

- Review: [Zero-Trust Architecture](architecture/zero-trust-architecture.md)
- Key concept: Certificates become identity layer for all services

**2. Service mesh certificates:**

- Review: [Service Mesh Certificates](architecture/service-mesh-certificates.md)
- Options: Istio (built-in CA), Linkerd (built-in CA), Consul (Vault integration)

**3. Mutual TLS implementation:**

- Review: [Mutual TLS Patterns](architecture/mutual-tls-patterns.md)
- Both client and server authenticate with certificates

**4. Automation requirements:**

- Review: [Certificate-as-Code](architecture/certificate-as-code.md)
- Must automate everything - manual processes don't work at zero-trust scale

**Key insight:** You cannot implement zero-trust without automated certificate management. The math doesn't work - too many certificates changing too frequently for manual processes.

**Timeline:** Zero-trust + PKI automation typically 12-18 months for enterprise rollout.

---

### "We need to meet compliance requirements (PCI-DSS, SOC 2, etc.)"

**Your situation:** Upcoming audit and certificate management is flagged as area of concern. Need to demonstrate controls.

**Compliance framework:**

**1. Understand requirements:**

- Review: [Compliance and Audit](security/compliance-and-audit.md)
- Key standards: PCI-DSS (certificate rotation), SOC 2 (access controls), FedRAMP (FIPS 140-2)

**2. Required controls:**

**Certificate inventory:**

- Authoritative list of all certificates
- Location, purpose, owner, expiry date
- Automated discovery (not manual spreadsheet)

**Lifecycle management:**

- Documented issuance process
- Automated renewal
- Revocation procedures
- Key ceremony for CA operations (if applicable)

**Access controls:**

- Who can request certificates?
- Who can approve?
- Separation of duties

**Monitoring:**

- Automated expiry alerts (30+ days advance warning)
- Failed renewal detection
- Unauthorized certificate detection

**Audit trail:**

- Complete history of certificate operations
- Who did what when
- Tamper-proof logging

**3. Evidence collection:**

For auditors, you need to provide:

- Certificate inventory report (current state)
- Policy documentation (approved processes)
- Access control matrix (who has what permissions)
- Monitoring configuration (alert rules)
- Historical audit logs (past 12 months)
- Incident response procedures (what happens when certificate expires)

**4. Automation benefits for compliance:**

Manual processes create audit findings:

- Incomplete inventory (can't find all certificates)
- Inconsistent processes (different teams do it differently)
- Missing audit trail (no logs of manual operations)
- Failed controls (expiration happens despite process)

Automated processes provide:

- Complete inventory (automated discovery)
- Consistent enforcement (policy-as-code)
- Comprehensive audit trail (Git history + platform logs)
- Demonstrated controls (zero outages proves monitoring works)

**Timeline for audit prep:**

- Manual processes: 40+ hours per audit
- Automated processes: 4 hours (generate reports from platform)

---

### "We're planning cloud migration - how do we handle certificates?"

**Your situation:** Migrating from on-premises to AWS/Azure/multi-cloud, and certificate management needs to work across environments.

**Migration strategy:**

**1. Understand multi-cloud certificate challenges:**

- Review: [Multi-Cloud PKI](implementation/multi-cloud-pki.md)
- Key insight: Different clouds have different certificate management approaches

**2. Architecture decisions:**

**Option A: Cloud-native certificate management**

- AWS: ACM (automatic renewal, limited export)
- Azure: Key Vault (flexible, requires more management)
- GCP: Certificate Manager (similar to ACM)
- Pro: Native integration, easy to start
- Con: Cloud lock-in, inconsistent across providers

**Option B: Unified certificate platform**

- Single platform (Venafi, Keyfactor) managing all clouds
- Pro: Consistent process, unified visibility
- Con: Additional cost, integration complexity

**Option C: Hybrid approach**

- Cloud-native for public-facing certificates
- Unified platform for internal certificates
- Pro: Best of both worlds
- Con: Two systems to maintain

**3. Migration phases:**

**Phase 1: Establish hybrid state (2-3 months)**

- Deploy certificate automation in cloud
- Keep on-premises manual processes
- No disruption to existing systems

**Phase 2: Gradual migration (6-12 months)**

- Migrate workloads to cloud
- Certificate management follows workload
- Automated provisioning in cloud

**Phase 3: Consolidation (3-6 months)**

- Decommission on-premises certificate infrastructure
- Unified management platform
- Complete cloud-native operations

**4. Key considerations:**

**CA strategy:**

- Keep existing CA? Migrate to cloud CA? Hybrid?
- Review: [Cloud vs On-Premises](patterns/cloud-vs-on-premises.md)

**Certificate export:**

- Some cloud services don't allow private key export
- Plan for services that need portable certificates

**Disaster recovery:**

- Cross-region replication
- Cross-cloud backup
- Review: [High Availability & Disaster Recovery](patterns/high-availability-disaster-recovery.md)

**5. Common mistakes to avoid:**

- Assuming cloud migration = automatic certificate management (it doesn't)
- Not planning for applications that need on-premises certificates during migration
- Underestimating certificate count in cloud (10-100x more than on-premises)
- Forgetting about legacy applications that can't move to cloud

---

### "I need to choose between building vs. buying certificate automation"

**Your situation:** Engineering team wants to build custom solution. You need to evaluate build vs. buy decision objectively.

**Decision framework:**

**Build custom solution when:**

- Very specific requirements not met by any vendor
- Existing strong PKI expertise in-house (2+ dedicated engineers)
- Existing automation platform to extend (not starting from scratch)
- Long-term commitment to maintenance and operations
- Budget for ongoing development (feature parity with vendors)

**Buy platform when:**

- Standard enterprise requirements
- Limited PKI expertise in-house
- Need solution operational quickly (3-6 months)
- Want vendor support and updates
- Scale makes DIY uneconomical

**Hybrid approach:**

- Buy core platform for standard use cases
- Build custom integrations for unique requirements
- Leverage vendor API for extensions

**TCO analysis:**

**Build costs:**

- Initial development: 2-3 engineers × 6-12 months = $300K-$600K
- Ongoing maintenance: 1-2 engineers ongoing = $200K-$400K annually
- Feature development: Playing catch-up with vendor roadmaps
- Risk: Key person dependency, security vulnerabilities

**Buy costs:**

- Platform licensing: $50K-$200K annually
- Implementation: $50K-$150K one-time
- Professional services: $50K-$100K annually
- Ongoing maintenance: ~10% of license cost

**Reality check:**

- Most "build" projects underestimate complexity by 3-5x
- DIY solutions rarely achieve feature parity with mature platforms
- Opportunity cost: Engineering time spent on undifferentiated infrastructure

**Our recommendation:** Buy platform for 90% of use cases, build custom integrations for the 10% that matter for competitive advantage.

---

## For Engineers

### "I need to implement PKI from scratch"

**Your situation:** Organization has no PKI infrastructure. You're starting from zero.

**Implementation path:**

**1. Learn fundamentals (1-2 weeks):**

- [What is PKI?](foundations/what-is-pki.md) - Core concepts
- [Certificate Anatomy](foundations/certificate-anatomy.md) - How certificates work
- [Trust Models](foundations/trust-models.md) - CA hierarchies
- [Cryptographic Primitives](foundations/cryptographic-primitives.md) - The math behind PKI

**2. Design CA architecture (2-4 weeks):**

- [CA Architecture](implementation/ca-architecture.md) - Designing CA hierarchies
- [CA Hierarchies](patterns/ca-hierarchies.md) - Common patterns
- Key decisions:

  - Root CA: Offline air-gapped? Cloud-hosted?
  - Intermediate CAs: How many? For what purposes?
  - HSM: Required for compliance? Which vendor?

**3. Choose deployment model:**

- [Cloud vs On-Premises](patterns/cloud-vs-on-premises.md)
- Options:

  - Cloud-hosted CA (AWS Private CA, Azure Key Vault, Google CAS)
  - On-premises CA (Microsoft CA, OpenSSL-based, commercial)
  - Hybrid (root offline, intermediates online)

**4. Implement certificate lifecycle:**

- [Certificate Lifecycle Management](operations/certificate-lifecycle-management.md)
- Critical components:

  - Issuance workflow
  - Renewal automation
  - Revocation procedures
  - Key backup and recovery

**5. Security controls:**

- [Private Key Protection](security/private-key-protection.md)
- [Key Management Best Practices](security/key-management-best-practices.md)
- Must haves:

  - HSM for CA private keys (if compliance requires)
  - Proper key ceremony procedures
  - Separation of duties

**6. Operations:**

- [Monitoring and Alerting](operations/monitoring-and-alerting.md)
- [Certificate Rotation Strategies](operations/certificate-rotation-strategies.md)

**Reference architecture:**

```
Root CA (offline, HSM-backed)
└── Issuing CA (online, automated)
    ├── Web server certificates (90 days)
    ├── Internal service certificates (30 days)
    └── Code signing certificates (365 days)
```

**Timeline:** 3-6 months for production-ready PKI infrastructure

**Recommendation:** Don't do this alone. PKI is complex and mistakes are expensive. [Contact us](https://axonshield.com/contact) for architecture review.

---

### "I need to fix an immediate certificate problem"

**Your situation:** Production is broken due to certificate issue. You need answers fast.

**Quick troubleshooting:**

**Problem: Certificate expired**

- [Expired Certificate Outages](troubleshooting/expired-certificate-outages.md)
- Emergency fix: Get new certificate issued ASAP
- Root cause: Why didn't monitoring catch this?
- Prevention: Implement automated renewal

**Problem: "Certificate validation failed"**

- [Chain Validation Errors](troubleshooting/chain-validation-errors.md)
- Check: Is intermediate CA certificate deployed?
- Check: Is root CA trusted by client?
- Check: Certificate chain order correct?

**Problem: Wrong certificate deployed**

- [Common Misconfigurations](troubleshooting/common-misconfigurations.md)
- Verify: Certificate Subject Alternative Names match hostname
- Verify: Certificate not expired
- Verify: Private key matches certificate

**Problem: Performance degradation**

- [Performance Bottlenecks](troubleshooting/performance-bottlenecks.md)
- Check: OCSP responder latency
- Check: Certificate chain length
- Check: TLS session resumption configured

**Debugging commands:**

```bash
# Check certificate details
openssl x509 -in certificate.crt -text -noout

# Verify certificate chain
openssl verify -CAfile root-ca.crt -untrusted intermediate-ca.crt certificate.crt

# Test TLS connection
openssl s_client -connect example.com:443 -showcerts

# Check certificate expiry
openssl x509 -in certificate.crt -noout -enddate

# Verify private key matches certificate
openssl x509 -noout -modulus -in certificate.crt | openssl md5
openssl rsa -noout -modulus -in private.key | openssl md5
```

---

### "I'm implementing service mesh with mTLS"

**Your situation:** Migrating to Kubernetes with Istio/Linkerd/Consul. Need to understand mTLS for service-to-service communication.

**Implementation guide:**

**1. Understand mTLS:**

- [Mutual TLS Patterns](architecture/mutual-tls-patterns.md)
- Key concept: Both client and server present certificates
- Why: Cryptographic proof of identity for zero-trust

**2. Service mesh specifics:**

- [Service Mesh Certificates](architecture/service-mesh-certificates.md)
- Istio: Citadel for certificate issuance
- Linkerd: Built-in certificate rotation
- Consul: Vault integration for PKI

**3. Certificate lifecycle in service mesh:**

**Short-lived certificates:**

- Typical: 24-48 hour lifespans
- Automatic rotation
- No manual intervention

**Certificate issuance:**
```yaml
# Istio automatically issues certificates to workloads
# No manual certificate requests needed
apiVersion: v1
kind: Service
metadata:
  name: payment-service
spec:
  # Istio sidecar automatically gets certificate
  ports:
    - port: 8080
      name: https
```

**4. Troubleshooting mTLS:**

**Certificate rotation failures:**

- Symptom: Intermittent 5xx errors during rotation
- Cause: Overlapping certificate validity not configured
- Fix: Configure rotation at 50% lifetime

**Performance issues:**

- Symptom: Increased latency after enabling mTLS
- Cause: TLS handshake overhead
- Fix: Connection pooling, session resumption

**Service communication failures:**

- Symptom: Services can't talk to each other
- Cause: mTLS enabled but not all services in mesh
- Fix: Gradual rollout with permissive mode first

**5. Best practices:**

- Enable mTLS in permissive mode first (allow both mTLS and plain)
- Monitor certificate issuance success rate
- Test rotation under load before production
- Have observability into certificate validation failures

---

### "I need to automate certificate deployment with Infrastructure-as-Code"

**Your situation:** Using Terraform/CloudFormation/Kubernetes. Need to integrate certificate management into IaC workflows.

**Implementation guide:**

**1. Understand Certificate-as-Code:**

- [Certificate-as-Code](architecture/certificate-as-code.md)
- Principle: Certificates defined in code, deployed automatically
- Benefits: Version control, code review, consistent deployment

**2. Implementation by platform:**

**Terraform:**
```hcl
resource "aws_acm_certificate" "api" {
  domain_name = "api.example.com"
  validation_method = "DNS"
  
  lifecycle {
    create_before_destroy = true
  }
}
```

**Kubernetes + cert-manager:**
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: api-tls
spec:
  secretName: api-tls-secret
  issuerRef:
    name: letsencrypt-prod
  dnsNames:
    - api.example.com
```

**3. CI/CD integration:**

```yaml
# GitHub Actions
- name: Validate certificates
  run: |
    yamllint certificates/
    conftest test certificates/
    
- name: Deploy certificates
  run: |
    terraform apply -auto-approve
```

**4. Policy as code:**

```rego
# OPA policy: Deny long-lived certificates
deny[msg] {
    input.kind == "Certificate"
    duration_days := input.spec.duration / 24
    duration_days > 90
    msg := "Certificate validity exceeds 90 days"
}
```

**5. Best practices:**

- NEVER commit private keys to Git
- Use secrets management (Vault, AWS Secrets Manager)
- Validate certificates in CI before deployment
- Monitor certificate issuance in CD pipeline
- Implement policy enforcement at PR stage

---

### "I need to debug certificate validation failures"

**Your situation:** Applications failing with "certificate validation error" but you don't know why.

**Systematic debugging:**

**1. Identify failure mode:**

**Error: "Certificate has expired"**

- Check certificate expiry: `openssl x509 -in cert.crt -noout -dates`
- Check system time (clock skew can cause false expiry)
- Get new certificate

**Error: "Certificate chain validation failed"**

- [Chain Validation Errors](troubleshooting/chain-validation-errors.md)
- Check intermediate certificate deployed: `openssl s_client -connect host:443 -showcerts`
- Verify chain order: certificate → intermediate → root
- Check root CA in trust store

**Error: "Hostname doesn't match certificate"**

- Check Subject Alternative Names: `openssl x509 -in cert.crt -noout -text | grep "Subject Alternative Name"`
- Verify hostname matches SAN entries
- Check for wildcard certificate mismatch

**Error: "Certificate has been revoked"**

- Check OCSP: `openssl ocsp -issuer issuer.crt -cert cert.crt -url <http://ocsp.example.com`>
- Verify CRL: Download and check CRL
- Get new certificate

**2. Validation debugging:**

```bash
# Verify full certificate chain
openssl verify -verbose -CAfile root.crt -untrusted intermediate.crt certificate.crt

# Check TLS connection details
openssl s_client -connect example.com:443 -servername example.com

# Test specific TLS version
openssl s_client -connect example.com:443 -tls1_2

# Check certificate bundle
cat certificate.crt intermediate.crt > bundle.crt
openssl verify -CAfile root.crt bundle.crt
```

**3. Common root causes:**

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Works in browser, fails in code | Missing intermediate cert in bundle | Add intermediate to certificate bundle |
| Fails intermittently | OCSP responder timeout | Configure OCSP soft-fail or use CRL |
| Works with curl, fails with Python | Trust store mismatch | Specify CA bundle in code |
| Worked yesterday, broken today | Certificate rotation | Check new certificate deployed everywhere |

---

### "I need to implement certificate monitoring"

**Your situation:** Need to build monitoring before automating certificate management. Want to prevent surprises.

**Monitoring implementation:**

**1. What to monitor:**

- [Monitoring and Alerting](operations/monitoring-and-alerting.md)

**Certificate inventory:**

- Total certificate count
- Certificates by type (TLS, code signing, etc.)
- Certificates by location (AWS, Azure, on-premises)
- Certificates by owner/team

**Certificate health:**

- Days until expiry (alert at 30, 14, 7 days)
- Certificates already expired but still deployed
- Certificates using weak cryptography (RSA 1024, SHA-1)
- Certificates with missing intermediate CA

**Certificate operations:**

- Issuance success/failure rate
- Renewal success/failure rate
- Deployment success/failure rate
- Average time to issue/renew

**2. Monitoring tools:**

**Prometheus + Grafana:**
```yaml
# blackbox_exporter for certificate monitoring
- job_name: 'certificate-expiry'
  metrics_path: /probe
  params:
    module: [tls_connect]
  static_configs:
    - targets:
      - api.example.com:443
      - db.example.com:5432
  relabel_configs:
    - source_labels: [__address__]
      target_label: __param_target
```

**cert-manager metrics:**
```promql
# Alert on certificate about to expire
certmanager_certificate_expiration_timestamp_seconds - time() < 86400 * 30
```

**3. Alerting rules:**

**Critical (page ops immediately):**

- Certificate expired and still in use
- Certificate renewal failed and <7 days to expiry
- Certificate issuance failed for critical service

**Warning (alert during business hours):**

- Certificate <30 days to expiry
- Certificate using weak crypto
- Certificate without monitoring

**Info (dashboard only):**

- Certificate renewed successfully
- New certificate discovered
- Certificate inventory changed

**4. Dashboard design:**

**Executive dashboard:**

- Total certificate count
- Certificates expiring in next 30 days
- Zero expiration-related outages (days since last)
- Automation coverage percentage

**Operations dashboard:**

- Certificate expiry timeline (next 90 days)
- Renewal success rate (last 30 days)
- Certificates by location/owner
- Recent certificate operations

**Troubleshooting dashboard:**

- Failed renewal attempts
- Certificates with validation errors
- OCSP/CRL response times
- Certificate issuance latency

---

## Next Steps

**After using this quick start guide:**

1. **For detailed implementation:** See the [Technical Knowledge Base](technical-guide.md) for comprehensive documentation
2. **For business case:** See the [Executive Summary](index.md) for ROI and strategic value
3. **For real-world examples:** See [Case Studies](architecture/case-studies.md) for enterprise implementations
4. **For expert guidance:** [Contact Axon Shield](https://axonshield.com/contact) for consulting on your specific situation

---

**Have questions about your specific scenario?** [Contact us](https://axonshield.com/contact) - we've implemented certificate automation at Nexus (30,000 certificates), Apex Capital (75,000 certificates including physical access), and Vortex (15,000 certificates with service mesh).
