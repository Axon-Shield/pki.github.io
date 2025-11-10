# Certificate-as-Code

## Why This Matters

**For executives:** Certificate-as-Code reduces operational risk by eliminating manual certificate processes that cause 94% of preventable outages. It enables infrastructure automation that scales without linear cost increases.

**For security leaders:** Treating certificates as code provides complete audit trails (Git history), consistent policy enforcement, and prevents the "SSH into production server to fix certificate" pattern that bypasses security controls. It's foundational for DevSecOps and compliance automation.

**For engineers:** You need Certificate-as-Code when deploying to Kubernetes, using infrastructure-as-code (Terraform, CloudFormation), or implementing GitOps workflows. It's how you avoid certificate management becoming a deployment bottleneck.

**Common scenario:** Your team is deploying microservices to Kubernetes. Developers need certificates for new services but the current process requires submitting tickets to InfoSec and waiting 2-4 weeks. Certificate provisioning is blocking deployment velocity. You need self-service certificate management with automated policy enforcement.

---

## Overview

Certificate-as-Code treats certificate definitions, policies, and lifecycle management as code—versioned, reviewed, tested, and automatically deployed. This approach brings infrastructure-as-code principles to PKI, enabling consistent, auditable, and scalable certificate management.

**Core principle**: Certificate requests, configurations, and policies should be declared in code, reviewed like code, tested like code, and deployed automatically. Manual certificate operations don't scale.

## Why Certificate-as-Code

Traditional manual certificate management fails at scale:

- Error-prone manual processes
- Inconsistent configurations
- Poor auditability
- Slow provisioning
- Difficult disaster recovery

Certificate-as-Code provides:

- Version-controlled certificate definitions
- Automated provisioning and renewal
- Consistent enforcement of policies
- Complete audit trail (Git history)
- Infrastructure-as-code integration

## Decision Framework

**Use Certificate-as-Code when:**

- Managing 100+ certificates across infrastructure
- Using infrastructure-as-code tools (Terraform, CloudFormation, Kubernetes)
- Implementing DevOps/GitOps workflows
- Need automated compliance audit trails
- Frequent certificate provisioning (daily/weekly deployments)

**Don't use Certificate-as-Code when:**

- Small scale (<20 certificates) with infrequent changes
- Manual processes are working fine and won't scale
- Team lacks Git/IaC expertise and can't invest in training
- Legacy systems that can't integrate with automation

**Hybrid approach when:**

- Mixed environment (some modern, some legacy)
- Gradual migration from manual to automated processes
- Different certificate types with different management needs (long-lived certs manually, short-lived certs automated)

**Red flags:**

- Implementing Certificate-as-Code without automated certificate management platform (will just automate the manual work, not eliminate it)
- No code review process (defeats audit trail benefit)
- Storing private keys in code repositories (never do this)
- Treating Certificate-as-Code as "set and forget" without ongoing maintenance

## Terraform for Certificates

Define certificates in Terraform:

```hcl
# Certificate resource
resource "aws_acm_certificate" "api" {
  domain_name               = "api.example.com"
  subject_alternative_names = ["*.api.example.com"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "api-certificate"
    Environment = "production"
    Team        = "platform"
    AutoRenew   = "true"
  }
}

# Validation records
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.api.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = aws_route53_zone.main.zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
}

# Load balancer using certificate
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.api.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
```

## Kubernetes Certificate Resources

Cert-manager provides Kubernetes-native certificate management:

```yaml
# Certificate resource
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: api-tls
  namespace: production
spec:
  secretName: api-tls-secret
  duration: 2160h  # 90 days
  renewBefore: 720h  # Renew 30 days before expiry
  
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  
  dnsNames:
    - api.example.com
    - "*.api.example.com"
  
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always

---
# ClusterIssuer for Let's Encrypt
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - dns01:
          route53:
            region: us-east-1

---
# Ingress using certificate
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: api-tls-secret
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api-service
                port:
                  number: 80
```

## GitOps Workflow

Manage certificates through Git:

```
Developer                  Git Repo                  Cluster
    │                         │                         │
    │─── Create cert.yaml ───>│                         │
    │                         │                         │
    │─── Pull Request ───────>│                         │
    │                         │                         │
    │     Review/Approve      │                         │
    │                         │                         │
    │─── Merge ──────────────>│                         │
    │                         │                         │
    │                         │─── ArgoCD Sync ───────>│
    │                         │                         │
    │                         │        cert-manager     │
    │                         │        issues cert      │
    │                         │                         │
    │<──── Notification ──────┴─────<< deployed >>>────│
```

## Policy as Code

Define certificate policies in code:

```python
# conftest.rego (OPA policy)
package certificate_policy

# Deny certificates with validity > 90 days
deny[msg] {
    input.kind == "Certificate"
    duration_hours := time.parse_duration_ns(input.spec.duration) / 3600000000000
    duration_hours > 2160  # 90 days
    msg := sprintf("Certificate validity %v exceeds maximum 90 days", [duration_hours / 24])
}

# Require ECDSA for new certificates
deny[msg] {
    input.kind == "Certificate"
    input.spec.privateKey.algorithm != "ECDSA"
    msg := "Certificates must use ECDSA algorithm"
}

# Require rotation policy
deny[msg] {
    input.kind == "Certificate"
    not input.spec.privateKey.rotationPolicy
    msg := "Certificate must specify key rotation policy"
}
```

Apply policy in CI/CD:

```bash
# Validate certificate definition against policy
conftest test certificate.yaml
```

## Ansible for Certificate Deployment

Automate certificate deployment:

```yaml
---
- name: Deploy TLS Certificate
  hosts: web_servers
  tasks:
    - name: Generate private key
      openssl_privatekey:
        path: /etc/ssl/private/{{ cert_name }}.key
        size: 2048
        mode: '0600'

    - name: Generate CSR
      openssl_csr:
        path: /etc/ssl/csr/{{ cert_name }}.csr
        privatekey_path: /etc/ssl/private/{{ cert_name }}.key
        common_name: "{{ cert_common_name }}"
        subject_alt_name: "{{ cert_san }}"

    - name: Submit CSR to CA
      uri:
        url: "{{ ca_api_url }}/issue"
        method: POST
        body: "{{ lookup('file', '/etc/ssl/csr/' + cert_name + '.csr') }}"
        headers:
          Authorization: "Bearer {{ ca_api_token }}"
      register: cert_response

    - name: Install certificate
      copy:
        content: "{{ cert_response.json.certificate }}"
        dest: /etc/ssl/certs/{{ cert_name }}.crt
        mode: '0644'
      notify: Reload nginx

  handlers:
    - name: Reload nginx
      service:
        name: nginx
        state: reloaded
```

## CI/CD Integration

Integrate certificate validation into pipelines:

```yaml
# GitHub Actions
name: Certificate Validation
on: [pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Validate certificate definitions
        run: |
          # Check certificate YAML syntax
          yamllint certificates/
          
          # Validate against policy
          conftest test certificates/
          
          # Check for secrets in code
          gitleaks detect
      
      - name: Preview changes
        run: |
          terraform plan -out=plan.tfplan
          
      - name: Comment plan on PR
        uses: actions/github-script@v6
        with:
          script: |
            const output = await exec.getExecOutput('terraform', ['show', '-no-color', 'plan.tfplan']);
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: output.stdout
            });
```

## Lessons from Production

### What We Learned at Sky UK (Kubernetes + cert-manager)

Sky UK implemented Certificate-as-Code using cert-manager in Kubernetes for 15,000+ certificates. Initial implementation had challenges:

**Problem 1: "Everything automated" created blind spots**

We assumed that once cert-manager was configured, certificates would "just work." In production:

- Certificate validation failures were silent (pods just failed to start)
- No visibility into certificate issuance attempts or failures
- When Let's Encrypt rate limits hit, we had no warning system
- Debugging required diving into cert-manager logs across multiple clusters

**What we did:** Built comprehensive observability layer:

- Prometheus metrics for certificate issuance success/failure rates
- Alerts for certificates not issuing within 5 minutes of request
- Dashboard showing certificate status, expiry, and renewal attempts
- Automated Slack notifications for failed issuance with actionable error messages

**Problem 2: Policy-as-code was too restrictive at first**

We implemented strict OPA policies requiring:

- All certificates ECDSA (not RSA)
- All certificates 90 days or less
- All certificates use DNS-01 validation

This broke legitimate use cases:

- Some legacy applications only supported RSA
- External partners required longer-lived certificates
- Some domains couldn't use DNS-01 (no API access to DNS provider)

**What we did:** Implemented policy exceptions with approval workflow:

- Default policies apply to 95% of certificates
- Exception process for legitimate edge cases
- Exceptions documented in code with justification
- Quarterly review of exceptions to reduce over time

**Problem 3: Git became operational bottleneck**

With 50+ developers deploying services, certificate PRs piled up:

- Platform team reviewing hundreds of certificate PRs per week
- Developers waited hours/days for certificate approval
- "Just copy/paste from another certificate" led to inconsistent configurations

**What we did:** Implemented self-service with automated policy enforcement:

- Developers create certificate definitions in their service repos
- CI/CD automatically validates against policies
- Auto-approve if policy compliant
- Only manual review for policy exceptions
- Reduced platform team review burden by 90%

**Warning signs you're heading for same mistakes:**

- Implementing Certificate-as-Code without observability into certificate operations
- Setting policies without understanding existing legitimate use cases
- Centralizing certificate definitions when scale demands distributed ownership
- Assuming "automated" means "zero operational overhead"

### What We Learned at Deutsche Bank (Terraform + Multi-Cloud)

Deutsche Bank implemented Certificate-as-Code with Terraform managing certificates across AWS, Azure, and on-premises. Challenges:

**Problem 1: State management became complex**

Certificate state in Terraform included sensitive data:

- Private keys (should never be in state)
- Certificate serial numbers and expiry dates
- Deployment locations

With 25,000+ certificates, Terraform state files grew to hundreds of MB. State management became operational burden:

- Long terraform plan/apply times
- Merge conflicts in state
- Difficulty troubleshooting state drift

**What we did:** Hybrid approach with state separation:

- Terraform manages certificate definitions and policies
- cert-manager/Venafi manages actual certificate issuance and renewal
- Terraform references certificates by identifier, doesn't manage full lifecycle
- Reduced state size by 90%, eliminated sensitive data in state

**Problem 2: Certificate rotation caused Terraform drift**

Certificates auto-renewed by cert-manager or Venafi would have different serial numbers than Terraform expected. Terraform plan would show "drift" even though everything was working correctly.

**What we did:** Configure Terraform to ignore certificate serial numbers and expiry dates:
```hcl
lifecycle {
  ignore_changes = [
    certificate_body,  # Changes on renewal
    not_after,         # Changes on renewal
  ]
}
```

**Problem 3: Multi-cloud complexity**

Different cloud providers had different certificate management capabilities:

- AWS ACM: Automatic renewal, limited export
- Azure Key Vault: Manual renewal, full export capability
- On-premises: Full manual management

Trying to abstract this into single Terraform module created more complexity than it solved.

**What we did:** Platform-specific implementations with shared policy layer:

- Separate Terraform modules for AWS, Azure, on-prem
- Shared OPA policies enforced across all platforms
- Accept that certificate management will look different per platform
- Focus on consistent outcomes (all certificates monitored, all auto-renewed) not consistent implementation

**Warning signs you're heading for same mistakes:**

- Putting sensitive data in Terraform state
- Ignoring state drift from certificate renewal
- Trying to abstract multi-cloud differences into single implementation
- Managing certificate lifecycle entirely in Terraform instead of delegating to specialized tools

## Best Practices

**Version control:**

- All certificate definitions in Git
- Meaningful commit messages explaining certificate purpose
- Required code reviews for certificate changes
- Separate repos for production vs non-production environments

**Automation:**

- Automatic certificate issuance on merge
- Automatic renewal without human intervention
- Automatic deployment to target systems
- Zero manual SSH into servers for certificate operations

**Testing:**

- Validate syntax in CI (yamllint, terraform validate)
- Test against policies before merge (conftest, OPA)
- Preview changes before apply (terraform plan)
- Smoke tests after deployment (curl with certificate validation)

**Security:**

- NEVER commit private keys to Git
- Use secrets management (Vault, AWS Secrets Manager, Sealed Secrets)
- Least-privilege service accounts for certificate operations
- Audit all certificate changes through Git history

**Observability:**

- Metrics for certificate issuance success/failure
- Alerts for failed certificate operations
- Dashboard showing certificate inventory and expiry
- Automated notifications for upcoming renewals

## Common Anti-Patterns

**Anti-pattern 1: Storing private keys in Git**
```hcl
# NEVER DO THIS
resource "aws_acm_certificate" "bad" {
  private_key      = file("private-key.pem")  # NEVER in Git!
  certificate_body = file("certificate.pem")
}
```

**Correct approach:**
```hcl
# Reference certificates by identifier, let cert-manager manage keys
resource "aws_lb_listener_certificate" "api" {
  listener_arn    = aws_lb_listener.https.arn
  certificate_arn = data.aws_acm_certificate.api.arn  # Reference only
}
```

**Anti-pattern 2: Manual certificate operations mixed with automation**

Half the certificates automated, half manual. This creates confusion about source of truth and leads to drift.

**Correct approach:** Gradual migration - automate progressively, but maintain clear separation between automated and manual certificates until migration complete.

**Anti-pattern 3: No policy enforcement**

Allowing any certificate configuration in code without validation. Defeats benefit of consistency.

**Correct approach:** Policy-as-code with CI/CD validation. Automatically reject non-compliant certificates, provide clear error messages.

## Business Impact

**Cost of getting this wrong:** Manual certificate management at scale costs $120K-$240K annually in labor alone (for 1,000 certificates). Without Certificate-as-Code, organizations experience 3-4 certificate-related outages per year, each costing $300K-$1M. Certificate provisioning becomes deployment bottleneck, slowing feature velocity and time-to-market.

**Value of getting this right:** Certificate-as-Code reduces operational overhead by 90%, eliminates manual certificate-related outages, and enables rapid deployment velocity. Git-based audit trails simplify compliance (SOC 2, PCI-DSS), reducing audit preparation from weeks to hours. Infrastructure automation scales without linear cost increases.

**Executive summary:** See [ROI of Automation](index.md#the-business-case-in-three-numbers) for business case framework.

---

## When to Bring in Expertise

**You can probably handle this yourself if:**

- You have <500 certificates and single cloud environment
- Team has strong IaC and GitOps experience
- You're using mature tooling (cert-manager, Terraform cloud providers)
- Simple use cases without complex policy requirements

**Consider getting help if:**

- You have 1,000+ certificates or multi-cloud complexity
- Need to implement policy-as-code with exception handling
- Migrating from manual to automated certificate management
- Team lacks Certificate-as-Code experience and needs training

**Definitely call us if:**

- You have 5,000+ certificates across complex infrastructure
- Need to integrate Certificate-as-Code with existing enterprise PKI
- Implementing in regulated environment (financial services, healthcare)
- Previous automation attempts failed and need troubleshooting

We've implemented Certificate-as-Code at Sky UK (15,000+ certificates, Kubernetes/cert-manager), Deutsche Bank (multi-cloud Terraform, 25,000+ certificates), and Barclays (enterprise PKI integration). We know where the complexity hides and what actually works at scale.

---

## References

### Infrastructure as Code

**"Infrastructure as Code" (O'Reilly)**
- Morris, K. "Infrastructure as Code: Managing Servers in the Cloud." 2nd Edition, O'Reilly, 2020.

**Terraform Documentation**
- HashiCorp. "Terraform Documentation."
  - https://www.terraform.io/docs

**Terraform AWS Provider - ACM**
- HashiCorp. "AWS Provider: aws_acm_certificate."
  - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate

### Kubernetes Certificate Management

**cert-manager Documentation**
- cert-manager. "cert-manager Documentation."
  - https://cert-manager.io/docs/

**Kubernetes Documentation - Managing TLS in a Cluster**
- Kubernetes. "Managing TLS in a Cluster."
  - https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/

### GitOps

**"GitOps - Operations by Pull Request" (Weaveworks)**
- Weaveworks. "Guide to GitOps."
  - https://www.weave.works/technologies/gitops/

**Argo CD Documentation**
- Argo Project. "Argo CD - Declarative GitOps CD for Kubernetes."
  - https://argo-cd.readthedocs.io/

**Flux Documentation**
- Flux Project. "Flux - GitOps for Kubernetes."
  - https://fluxcd.io/docs/

### Policy as Code

**Open Policy Agent Documentation**
- Open Policy Agent. "OPA Documentation."
  - https://www.openpolicyagent.org/docs/

**Conftest**
- Open Policy Agent. "Conftest - Write tests against structured configuration data."
  - https://www.conftest.dev/

**Rego Policy Language**
- OPA. "Policy Language."
  - https://www.openpolicyagent.org/docs/latest/policy-language/

### CI/CD Integration

**"Continuous Delivery" (Addison-Wesley)**
- Humble, J., Farley, D. "Continuous Delivery: Reliable Software Releases through Build, Test, and Deployment Automation." 2010.

**GitHub Actions Documentation**
- GitHub. "GitHub Actions Documentation."
  - https://docs.github.com/en/actions

**GitLab CI/CD**
- GitLab. "GitLab CI/CD."
  - https://docs.gitlab.com/ee/ci/

### Configuration Management

**Ansible Documentation**
- Red Hat. "Ansible Documentation."
  - https://docs.ansible.com/

**Ansible openssl Modules**
- Ansible. "Community.crypto Collection."
  - https://docs.ansible.com/ansible/latest/collections/community/crypto/

### ACME Protocol

**RFC 8555 - ACME**
- Barnes, R., et al. "Automatic Certificate Management Environment (ACME)." RFC 8555, March 2019.
  - https://tools.ietf.org/html/rfc8555

**Let's Encrypt Documentation**
- Let's Encrypt. "Let's Encrypt Documentation."
  - https://letsencrypt.org/docs/

**Boulder - ACME Server**
- Let's Encrypt. "Boulder - An ACME-based CA."
  - https://github.com/letsencrypt/boulder

### Secrets Management

**HashiCorp Vault Documentation**
- HashiCorp. "Vault Documentation."
  - https://www.vaultproject.io/docs

**AWS Secrets Manager**
- AWS. "AWS Secrets Manager Documentation."
  - https://docs.aws.amazon.com/secretsmanager/

**Azure Key Vault**
- Microsoft. "Azure Key Vault Documentation."
  - https://docs.microsoft.com/en-us/azure/key-vault/

### Security Scanning

**gitleaks**
- Gitleaks. "Protect and discover secrets using Gitleaks."
  - https://github.com/gitleaks/gitleaks

**TruffleHog**
- Truffle Security. "Find credentials all over the place."
  - https://github.com/trufflesecurity/trufflehog

### Best Practices

**"Site Reliability Engineering" (O'Reilly)**
- Beyer, B., et al. "Site Reliability Engineering: How Google Runs Production Systems." O'Reilly, 2016.
- Automation and toil reduction

**"The DevOps Handbook" (IT Revolution Press)**
- Kim, G., et al. "The DevOps Handbook." IT Revolution Press, 2016.
- Infrastructure automation
- Deployment pipelines
