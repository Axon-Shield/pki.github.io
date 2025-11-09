# Certificate-as-Code

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
    │                         │─── ArgoCD Sync ────────>│
    │                         │                         │
    │                         │        cert-manager     │
    │                         │        issues cert      │
    │                         │                         │
    │<──── Notification ──────┴──────<< deployed >>>────│
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

## Best Practices

**Version control**:
- All certificate definitions in Git
- Meaningful commit messages
- Required code reviews
- Separate repos for environments

**Automation**:
- Automatic certificate issuance
- Automatic renewal
- Automatic deployment
- Zero manual intervention

**Testing**:
- Validate syntax in CI
- Test against policies
- Preview changes before apply
- Smoke tests after deployment

**Security**:
- Never commit private keys
- Use secrets management
- Least-privilege service accounts
- Audit all changes

## Conclusion

Certificate-as-Code transforms PKI from manual operations to declarative infrastructure management. By treating certificates as code, organizations achieve consistency, auditability, and scalability while reducing errors and operational overhead.

The combination of IaC tools (Terraform, Kubernetes), GitOps workflows, policy-as-code (OPA), and CI/CD integration creates a robust, automated certificate management system that scales from dozens to thousands of certificates.

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
