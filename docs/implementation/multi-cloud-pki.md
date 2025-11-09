# Multi-Cloud PKI

## TL;DR

Multi-cloud PKI architectures enable organizations to manage certificates consistently across AWS, Azure, GCP, and on-premises infrastructure while avoiding vendor lock-in and maintaining unified security policies. The fundamental challenge is that each cloud provider offers different native certificate services (AWS ACM, Azure Key Vault Certificates, GCP Certificate Manager) with incompatible APIs, limited portability, and varying feature sets. Successful multi-cloud PKI requires: centralized certificate authority infrastructure independent of any single cloud, unified certificate lifecycle automation using cloud-agnostic tools (Terraform, Kubernetes cert-manager, HashiCorp Vault), consistent secrets management across environments, service mesh integration for microservices (Istio, Linkerd, Consul Connect), and comprehensive visibility through centralized monitoring. Organizations should prioritize interoperability over cloud-native features, establish clear policies for when to use managed services versus self-hosted PKI, and build automation that works identically across all clouds.

**Key Insight**: The promise of cloud portability fails in practice if your PKI is deeply coupled to provider-specific services. A successful multi-cloud strategy treats certificate management as a horizontal platform service that spans clouds rather than vertical integration within each cloud's ecosystem. This requires accepting some friction (managing your own CA instead of using native services) in exchange for true portability and unified control.

---

## Overview

Multi-cloud PKI addresses the operational reality that most enterprises use multiple cloud providers, maintain on-premises infrastructure, and require consistent certificate management across all environments. This creates challenges around:

**Architectural Challenges**:



- Divergent APIs and data models across cloud providers
- Different certificate validation and renewal workflows
- Incompatible secrets management systems
- Varied integration patterns for compute services
- Cloud-specific networking and security boundaries

**Operational Challenges**:



- Maintaining visibility across dispersed certificate inventory
- Consistent policy enforcement independent of cloud provider
- Unified renewal and lifecycle management
- Cross-cloud certificate distribution
- Audit and compliance across heterogeneous environments

**Strategic Considerations**:



- Vendor lock-in risks when using cloud-native PKI services
- Cost optimization across cloud billing models
- Disaster recovery and multi-region failover
- Regulatory requirements for data sovereignty
- Migration flexibility between clouds

---

## Cloud Provider Certificate Services

### AWS Certificate Manager (ACM)

AWS's managed certificate service for AWS resources:

**Capabilities**:



- Free certificates for AWS-integrated services
- Automatic renewal with no customer action
- Integration with ELB, CloudFront, API Gateway, Elastic Beanstalk
- Supports public (via Amazon's CA) and private certificates
- Regional service with certificate-per-region requirement
- No export of private keys for public certificates

**Limitations**:



- Only works with AWS services (cannot export most certificates)
- No support for client certificates
- Limited to 398-day validity
- Regional isolation requires certificate duplication
- Cannot use with EC2 instances directly (must use load balancer)

**Use Cases**:



- Public-facing websites on CloudFront or ALB
- API Gateway REST APIs
- Internal services using Private CA
- Temporary certificates for testing

**Terraform Example**:
```hcl
# Request ACM certificate
resource "aws_acm_certificate" "example" {
  domain_name       = "example.com"
  validation_method = "DNS"
  
  subject_alternative_names = [
    "www.example.com",
    "api.example.com"
  ]
  
  tags = {
    Environment = "production"
    ManagedBy   = "Terraform"
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Create DNS validation records
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.example.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

# Wait for validation
resource "aws_acm_certificate_validation" "example" {
  certificate_arn         = aws_acm_certificate.example.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# Attach to load balancer
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.example.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate_validation.example.certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }
}
```

**AWS Private CA**:
```hcl
# Create private CA
resource "aws_acmpca_certificate_authority" "example" {
  type = "ROOT"
  
  certificate_authority_configuration {
    key_algorithm     = "RSA_2048"
    signing_algorithm = "SHA256WITHRSA"
    
    subject {
      common_name  = "Example Corp Root CA"
      organization = "Example Corp"
      country      = "US"
    }
  }
  
  permanent_deletion_time_in_days = 7
}

# Issue certificate from private CA
resource "aws_acmpca_certificate" "server" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.example.arn
  certificate_signing_request = tls_cert_request.server.cert_request_pem
  signing_algorithm           = "SHA256WITHRSA"
  
  validity {
    type  = "DAYS"
    value = 90
  }
}
```

### Azure Key Vault Certificates

Azure's integrated certificate management within Key Vault:

**Capabilities**:



- Unified storage for certificates, keys, and secrets
- Automatic renewal with supported CAs (DigiCert, GlobalSign)
- Manual import of certificates from any CA
- Export of certificates with private keys (for entitled users)
- Integration with Azure App Service, Application Gateway, CDN
- RBAC integration with Azure AD
- Soft-delete and purge protection

**Limitations**:



- Per-vault limits (5000 certificate versions)
- Regional service requiring cross-region replication
- API throttling can impact automation at scale
- Cost per certificate operation (retrieval, update)
- Limited to Azure-integrated services

**Use Cases**:



- Azure App Service custom domains
- Application Gateway SSL termination
- Azure Functions HTTPS
- VM-based applications with Key Vault integration
- Client certificate authentication

**Terraform Example**:
```hcl
# Create Key Vault
resource "azurerm_key_vault" "example" {
  name                = "example-kv"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
  
  soft_delete_retention_days = 90
  purge_protection_enabled   = true
  
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    
    ip_rules = ["1.2.3.4"]
  }
}

# Import certificate
resource "azurerm_key_vault_certificate" "imported" {
  name         = "imported-cert"
  key_vault_id = azurerm_key_vault.example.id
  
  certificate {
    contents = filebase64("certificate.pfx")
    password = var.pfx_password
  }
}

# Create self-signed certificate
resource "azurerm_key_vault_certificate" "selfsigned" {
  name         = "selfsigned-cert"
  key_vault_id = azurerm_key_vault.example.id
  
  certificate_policy {
    issuer_parameters {
      name = "Self"
    }
    
    key_properties {
      exportable = true
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = true
    }
    
    lifetime_action {
      action {
        action_type = "AutoRenew"
      }
      
      trigger {
        days_before_expiry = 30
      }
    }
    
    secret_properties {
      content_type = "application/x-pkcs12"
    }
    
    x509_certificate_properties {
      extended_key_usage = ["1.3.6.1.5.5.7.3.1"]  # Server auth
      
      key_usage = [
        "digitalSignature",
        "keyEncipherment",
      ]
      
      subject            = "CN=example.com"
      validity_in_months = 12
      
      subject_alternative_names {
        dns_names = ["example.com", "www.example.com"]
      }
    }
  }
}

# Use certificate with App Service
resource "azurerm_app_service_certificate" "example" {
  name                = "example-cert"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  key_vault_secret_id = azurerm_key_vault_certificate.imported.secret_id
}

resource "azurerm_app_service_custom_hostname_binding" "example" {
  hostname            = "www.example.com"
  app_service_name    = azurerm_app_service.example.name
  resource_group_name = azurerm_resource_group.example.name
  ssl_state           = "SniEnabled"
  thumbprint          = azurerm_app_service_certificate.example.thumbprint
}
```

### Google Cloud Certificate Manager

GCP's newer certificate management service:

**Capabilities**:



- Global service (not regional like AWS ACM)
- Automatic certificate provisioning for external HTTPS load balancers
- DNS authorization via Cloud DNS
- Certificate maps for routing to multiple certificates
- Integration with Cloud Load Balancing, Cloud CDN
- Self-managed certificates for custom CAs

**Limitations**:



- Relatively new service (GA in 2021)
- Limited to GCP load balancers and CDN
- Cannot use certificates on Compute Engine instances
- No client certificate support
- Regional Certificate Manager for internal load balancers

**Use Cases**:



- Global HTTPS load balancers
- Multi-region CDN deployments
- GKE ingress with managed certificates
- Cloud Run custom domains

**Terraform Example**:
```hcl
# DNS authorization for domain validation
resource "google_certificate_manager_dns_authorization" "default" {
  name        = "dns-auth"
  description = "DNS authorization for example.com"
  domain      = "example.com"
}

# Create DNS record for validation
resource "google_dns_record_set" "cname" {
  name         = google_certificate_manager_dns_authorization.default.dns_resource_record[0].name
  type         = google_certificate_manager_dns_authorization.default.dns_resource_record[0].type
  ttl          = 300
  managed_zone = google_dns_managed_zone.default.name
  rrdatas      = [google_certificate_manager_dns_authorization.default.dns_resource_record[0].data]
}

# Create certificate
resource "google_certificate_manager_certificate" "default" {
  name        = "example-cert"
  description = "Certificate for example.com"
  scope       = "DEFAULT"
  
  managed {
    domains = [
      "example.com",
      "www.example.com"
    ]
    
    dns_authorizations = [
      google_certificate_manager_dns_authorization.default.id
    ]
  }
}

# Create certificate map
resource "google_certificate_manager_certificate_map" "default" {
  name        = "cert-map"
  description = "Certificate map for load balancer"
}

resource "google_certificate_manager_certificate_map_entry" "default" {
  name         = "cert-map-entry"
  description  = "Map entry for example.com"
  map          = google_certificate_manager_certificate_map.default.name
  certificates = [google_certificate_manager_certificate.default.id]
  hostname     = "example.com"
}

# Attach to load balancer
resource "google_compute_target_https_proxy" "default" {
  name             = "https-proxy"
  url_map          = google_compute_url_map.default.id
  certificate_map  = "//certificatemanager.googleapis.com/${google_certificate_manager_certificate_map.default.id}"
}
```

---

## Cross-Cloud Architecture Patterns

### Centralized CA with Distributed Issuance

Single certificate authority serving all clouds:

```
                    ┌──────────────────┐
                    │  Centralized CA  │
                    │   (HashiCorp     │
                    │     Vault or     │
                    │   Custom PKI)    │
                    └────────┬─────────┘
                             │
                             │ HTTPS/ACME
           ┌─────────────────┼─────────────────┐
           │                 │                 │
      ┌────▼────┐       ┌────▼────┐      ┌────▼────┐
      │   AWS   │       │  Azure  │      │   GCP   │
      │ Issuer  │       │ Issuer  │      │ Issuer  │
      │ Agent   │       │ Agent   │      │ Agent   │
      └────┬────┘       └────┬────┘      └────┬────┘
           │                 │                 │
      ┌────▼────┐       ┌────▼────┐      ┌────▼────┐
      │ Secrets │       │   Key   │      │ Secret  │
      │ Manager │       │  Vault  │      │ Manager │
      └────┬────┘       └────┬────┘      └────┬────┘
           │                 │                 │
      ┌────▼────┐       ┌────▼────┐      ┌────▼────┐
      │   EC2   │       │   VMs   │      │  GCE    │
      │   ECS   │       │   AKS   │      │  GKE    │
      │   EKS   │       │  App Svc│      │Cloud Run│
      └─────────┘       └─────────┘      └─────────┘
```

**Implementation**:
```python
class MultiCloudCertificateIssuer:
    """Centralized certificate issuance for multiple clouds"""
    
    def __init__(self, vault_url, vault_token):
        import hvac
        
        self.vault = hvac.Client(url=vault_url, token=vault_token)
        
        # Cloud-specific clients
        self.aws_sm = boto3.client('secretsmanager')
        self.azure_kv = SecretClient(
            vault_url="https://example-kv.vault.azure.net/",
            credential=DefaultAzureCredential()
        )
        self.gcp_sm = secretmanager.SecretManagerServiceClient()
        
    def issue_certificate(self, common_name, cloud_provider, secret_path):
        """Issue certificate and distribute to appropriate cloud"""
        
        # Issue from Vault PKI
        response = self.vault.secrets.pki.generate_certificate(
            name='multi-cloud-role',
            common_name=common_name,
            ttl='90d',
            mount_point='pki-int'
        )
        
        certificate = response['data']['certificate']
        private_key = response['data']['private_key']
        ca_chain = response['data']['ca_chain']
        
        # Combine into full chain
        full_chain = certificate + '\n' + '\n'.join(ca_chain)
        
        # Distribute to cloud-specific secrets manager
        if cloud_provider == 'aws':
            self.store_in_aws(secret_path, full_chain, private_key)
        elif cloud_provider == 'azure':
            self.store_in_azure(secret_path, full_chain, private_key)
        elif cloud_provider == 'gcp':
            self.store_in_gcp(secret_path, full_chain, private_key)
        
        return {
            'certificate': certificate,
            'secret_path': secret_path,
            'cloud_provider': cloud_provider,
            'expires': response['data']['expiration']
        }
    
    def store_in_aws(self, secret_name, certificate, private_key):
        """Store certificate in AWS Secrets Manager"""
        
        secret_value = json.dumps({
            'certificate': certificate,
            'private_key': private_key
        })
        
        try:
            self.aws_sm.create_secret(
                Name=secret_name,
                SecretString=secret_value,
                Tags=[
                    {'Key': 'ManagedBy', 'Value': 'MultiCloudPKI'},
                    {'Key': 'Type', 'Value': 'TLSCertificate'}
                ]
            )
        except self.aws_sm.exceptions.ResourceExistsException:
            self.aws_sm.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_value
            )
    
    def store_in_azure(self, secret_name, certificate, private_key):
        """Store certificate in Azure Key Vault"""
        
        # Combine into PFX format for Azure
        pfx_bytes = self.create_pfx(certificate, private_key)
        
        self.azure_kv.set_secret(
            name=secret_name,
            value=base64.b64encode(pfx_bytes).decode()
        )
    
    def store_in_gcp(self, secret_name, certificate, private_key):
        """Store certificate in GCP Secret Manager"""
        
        project_id = 'your-project-id'
        parent = f"projects/{project_id}"
        
        secret_value = json.dumps({
            'certificate': certificate,
            'private_key': private_key
        })
        
        # Create secret if doesn't exist
        try:
            self.gcp_sm.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_name,
                    "secret": {
                        "replication": {"automatic": {}}
                    }
                }
            )
        except Exception:
            pass  # Secret already exists
        
        # Add secret version
        parent_secret = f"{parent}/secrets/{secret_name}"
        self.gcp_sm.add_secret_version(
            request={
                "parent": parent_secret,
                "payload": {"data": secret_value.encode()}
            }
        )
```

### Federated CA Model

Multiple CAs per cloud, cross-signed for trust:

```
                    ┌──────────────────┐
                    │    Root CA       │
                    │  (On-premises    │
                    │     HSM)         │
                    └────────┬─────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
      ┌────▼────┐       ┌────▼────┐      ┌────▼────┐
      │   AWS   │       │  Azure  │      │   GCP   │
      │ Issuing │       │ Issuing │      │ Issuing │
      │   CA    │       │   CA    │      │   CA    │
      └────┬────┘       └────┬────┘      └────┬────┘
           │                 │                 │
   Local issuance    Local issuance    Local issuance
   in AWS VPC        in Azure VNet     in GCP VPC
```

**Benefits**:



- Reduced latency (local issuance)
- Cloud isolation for security
- Compliance with data residency
- Failure isolation

**Challenges**:



- Complex trust chain management
- Certificate distribution complexity
- Increased operational overhead
- CA key management per cloud

### Service Mesh Integration

Using service mesh for multi-cloud certificate automation:

```yaml
# Istio configuration for multi-cloud
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: multi-cloud
spec:
  meshConfig:
    # Centralized CA
    ca:
      address: "vault.example.com:8200"
      tlsSettings:
        mode: SIMPLE
        
    # Certificate settings
    certificates:
      - secretName: istio-ca-secret
        dnsNames:
          - "*.aws.example.com"
          - "*.azure.example.com"
          - "*.gcp.example.com"
    
    # Trust domain spanning clouds
    trustDomain: "example.com"
    
  components:
    pilot:
      k8s:
        env:
          # Enable multi-cluster
          - name: PILOT_ENABLE_CROSS_CLUSTER_WORKLOAD_ENTRY
            value: "true"
          - name: PILOT_SKIP_VALIDATE_TRUST_DOMAIN
            value: "true"
```

---

## Kubernetes cert-manager for Multi-Cloud

Cert-manager provides cloud-agnostic certificate automation:

### Installation Across Clouds

```bash
# Install cert-manager (same across all clouds)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Verify installation
kubectl get pods -n cert-manager
```

### Vault Issuer Configuration

```yaml
# vault-issuer.yaml - Same configuration across AWS, Azure, GCP clusters
apiVersion: v1
kind: Secret
metadata:
  name: vault-token
  namespace: cert-manager
type: Opaque
data:
  token: <base64-encoded-vault-token>
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: vault-issuer
spec:
  vault:
    server: https://vault.example.com:8200
    path: pki-int/sign/kubernetes
    caBundle: <base64-encoded-ca-bundle>
    auth:
      tokenSecretRef:
        name: vault-token
        key: token
```

### Certificate Request

```yaml
# certificate.yaml - Works identically across all clouds
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-app
  namespace: production
spec:
  secretName: example-app-tls
  duration: 2160h  # 90 days
  renewBefore: 720h  # 30 days
  
  subject:
    organizations:
      - Example Corp
  
  commonName: example-app.example.com
  
  dnsNames:
    - example-app.example.com
    - example-app.aws.example.com
    - example-app.azure.example.com
    - example-app.gcp.example.com
  
  issuerRef:
    name: vault-issuer
    kind: ClusterIssuer
    group: cert-manager.io
  
  privateKey:
    algorithm: RSA
    size: 2048
    rotationPolicy: Always
```

### Ingress Integration

```yaml
# ingress.yaml - Standard Kubernetes, cloud-agnostic
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-app
  namespace: production
  annotations:
    cert-manager.io/cluster-issuer: vault-issuer
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - example-app.example.com
      secretName: example-app-tls
  rules:
    - host: example-app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: example-app
                port:
                  number: 80
```

---

## HashiCorp Vault Multi-Cloud Deployment

### Architecture

```
                     ┌─────────────────┐
                     │  Load Balancer  │
                     │   (Multi-Cloud  │
                     │    Endpoint)    │
                     └────────┬────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
       ┌────▼────┐       ┌────▼────┐      ┌────▼────┐
       │  Vault  │       │  Vault  │      │  Vault  │
       │  Node   │◄─────►│  Node   │◄────►│  Node   │
       │  (AWS)  │       │ (Azure) │      │  (GCP)  │
       └────┬────┘       └────┬────┘      └────┬────┘
            │                 │                 │
       ┌────▼────┐       ┌────▼────┐      ┌────▼────┐
       │   DynamoDB│      │  Azure  │      │Firestore│
       │  Storage  │      │ Storage │      │ Storage │
       └───────────┘      └─────────┘      └─────────┘
```

### Terraform Deployment

```hcl
# modules/vault-cluster/main.tf
variable "cloud_provider" {
  description = "Cloud provider (aws, azure, gcp)"
  type        = string
}

variable "region" {
  description = "Cloud region"
  type        = string
}

# AWS Vault Cluster
module "vault_aws" {
  source = "./modules/vault-cluster"
  count  = var.deploy_aws ? 1 : 0
  
  cloud_provider = "aws"
  region         = "us-east-1"
  
  vault_version  = "1.15.0"
  instance_count = 3
  instance_type  = "m5.large"
  
  storage_backend = "dynamodb"
  
  kms_key_id = aws_kms_key.vault.id
  
  tags = {
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}

# Azure Vault Cluster
module "vault_azure" {
  source = "./modules/vault-cluster"
  count  = var.deploy_azure ? 1 : 0
  
  cloud_provider = "azure"
  region         = "eastus"
  
  vault_version  = "1.15.0"
  instance_count = 3
  instance_type  = "Standard_D2s_v3"
  
  storage_backend = "azure"
  
  key_vault_id = azurerm_key_vault.vault.id
}

# GCP Vault Cluster
module "vault_gcp" {
  source = "./modules/vault-cluster"
  count  = var.deploy_gcp ? 1 : 0
  
  cloud_provider = "gcp"
  region         = "us-central1"
  
  vault_version  = "1.15.0"
  instance_count = 3
  instance_type  = "n1-standard-2"
  
  storage_backend = "firestore"
  
  kms_key_id = google_kms_crypto_key.vault.id
}

# Global load balancer
resource "cloudflare_load_balancer" "vault" {
  zone_id = var.cloudflare_zone_id
  name    = "vault.example.com"
  
  default_pool_ids = [
    cloudflare_load_balancer_pool.aws.id,
    cloudflare_load_balancer_pool.azure.id,
    cloudflare_load_balancer_pool.gcp.id
  ]
  
  fallback_pool_id = cloudflare_load_balancer_pool.aws.id
  
  session_affinity = "cookie"
}

resource "cloudflare_load_balancer_pool" "aws" {
  name = "vault-aws"
  
  origins {
    name    = "vault-aws-1"
    address = module.vault_aws[0].endpoint
    enabled = true
  }
  
  monitor = cloudflare_load_balancer_monitor.vault.id
}

# Health monitor
resource "cloudflare_load_balancer_monitor" "vault" {
  type     = "https"
  path     = "/v1/sys/health"
  interval = 60
  timeout  = 5
  retries  = 2
  
  expected_codes = "200,429,473,503"  # Various Vault health states
}
```

### PKI Secrets Engine Configuration

```bash
# Enable PKI secrets engine
vault secrets enable -path=pki-root pki
vault secrets enable -path=pki-int pki

# Tune max lease TTL
vault secrets tune -max-lease-ttl=87600h pki-root  # 10 years
vault secrets tune -max-lease-ttl=43800h pki-int   # 5 years

# Generate root CA
vault write -field=certificate pki-root/root/generate/internal \
    common_name="Example Corp Root CA" \
    ttl=87600h > root-ca.crt

# Generate intermediate CSR
vault write -field=csr pki-int/intermediate/generate/internal \
    common_name="Example Corp Intermediate CA" \
    > pki-int.csr

# Sign intermediate with root
vault write -field=certificate pki-root/root/sign-intermediate \
    csr=@pki-int.csr \
    format=pem_bundle \
    ttl=43800h > intermediate-ca.crt

# Import signed intermediate
vault write pki-int/intermediate/set-signed \
    certificate=@intermediate-ca.crt

# Configure URLs
vault write pki-int/config/urls \
    issuing_certificates="https://vault.example.com:8200/v1/pki-int/ca" \
    crl_distribution_points="https://vault.example.com:8200/v1/pki-int/crl"

# Create role for multi-cloud certificates
vault write pki-int/roles/multi-cloud \
    allowed_domains="example.com,aws.example.com,azure.example.com,gcp.example.com" \
    allow_subdomains=true \
    max_ttl="2160h" \
    key_type="rsa" \
    key_bits=2048
```

---

## Secrets Management Integration

### Unified Secrets Distribution

```python
class MultiCloudSecretsManager:
    """Distribute certificates across cloud secrets managers"""
    
    def __init__(self):
        # Initialize cloud clients
        self.aws_sm = boto3.client('secretsmanager', region_name='us-east-1')
        self.azure_kv = SecretClient(
            vault_url="https://example-kv.vault.azure.net/",
            credential=DefaultAzureCredential()
        )
        self.gcp_sm = secretmanager.SecretManagerServiceClient()
        self.gcp_project = 'your-project-id'
    
    def distribute_certificate(self, cert_pem, key_pem, ca_chain, target_clouds):
        """Distribute certificate to multiple clouds"""
        
        results = {}
        
        for cloud_config in target_clouds:
            cloud = cloud_config['provider']
            secret_name = cloud_config['secret_name']
            
            try:
                if cloud == 'aws':
                    arn = self.store_aws(secret_name, cert_pem, key_pem, ca_chain)
                    results['aws'] = {'success': True, 'arn': arn}
                    
                elif cloud == 'azure':
                    url = self.store_azure(secret_name, cert_pem, key_pem, ca_chain)
                    results['azure'] = {'success': True, 'url': url}
                    
                elif cloud == 'gcp':
                    name = self.store_gcp(secret_name, cert_pem, key_pem, ca_chain)
                    results['gcp'] = {'success': True, 'name': name}
                    
            except Exception as e:
                results[cloud] = {'success': False, 'error': str(e)}
        
        return results
    
    def store_aws(self, secret_name, cert_pem, key_pem, ca_chain):
        """Store in AWS Secrets Manager"""
        
        secret_value = json.dumps({
            'certificate': cert_pem,
            'private_key': key_pem,
            'ca_chain': ca_chain,
            'updated_at': datetime.utcnow().isoformat()
        })
        
        try:
            response = self.aws_sm.create_secret(
                Name=secret_name,
                SecretString=secret_value,
                Tags=[
                    {'Key': 'Type', 'Value': 'TLSCertificate'},
                    {'Key': 'ManagedBy', 'Value': 'MultiCloudPKI'}
                ]
            )
            return response['ARN']
            
        except self.aws_sm.exceptions.ResourceExistsException:
            response = self.aws_sm.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_value
            )
            return response['ARN']
    
    def store_azure(self, secret_name, cert_pem, key_pem, ca_chain):
        """Store in Azure Key Vault as certificate"""
        
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
        
        # Load certificate and key
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
        
        # Create PFX/PKCS12
        pfx = pkcs12.serialize_key_and_certificates(
            name=b"certificate",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(b"")
        )
        
        # Import to Key Vault
        poller = self.azure_kv.import_certificate(
            certificate_name=secret_name,
            certificate_bytes=pfx
        )
        
        return poller.result().id
    
    def store_gcp(self, secret_name, cert_pem, key_pem, ca_chain):
        """Store in GCP Secret Manager"""
        
        parent = f"projects/{self.gcp_project}"
        
        secret_value = json.dumps({
            'certificate': cert_pem,
            'private_key': key_pem,
            'ca_chain': ca_chain,
            'updated_at': datetime.utcnow().isoformat()
        })
        
        # Create secret if doesn't exist
        try:
            secret = self.gcp_sm.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_name,
                    "secret": {
                        "replication": {
                            "automatic": {}
                        },
                        "labels": {
                            "type": "tls-certificate",
                            "managed-by": "multi-cloud-pki"
                        }
                    }
                }
            )
        except Exception:
            secret = self.gcp_sm.get_secret(
                request={"name": f"{parent}/secrets/{secret_name}"}
            )
        
        # Add new version
        version = self.gcp_sm.add_secret_version(
            request={
                "parent": secret.name,
                "payload": {"data": secret_value.encode()}
            }
        )
        
        return version.name
```

---

## Monitoring and Visibility

### Centralized Certificate Inventory

```python
class MultiCloudCertificateInventory:
    """Maintain unified certificate inventory across clouds"""
    
    def __init__(self, db_connection):
        self.db = db_connection
        
        # Cloud clients
        self.aws_acm = boto3.client('acm')
        self.aws_sm = boto3.client('secretsmanager')
        self.azure_kv = SecretClient(...)
        self.gcp_cm = CertificateManagerClient()
    
    def scan_all_clouds(self):
        """Scan certificates across all cloud providers"""
        
        inventory = {
            'aws': self.scan_aws(),
            'azure': self.scan_azure(),
            'gcp': self.scan_gcp(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Store in database
        self.store_inventory(inventory)
        
        # Analyze for issues
        issues = self.analyze_inventory(inventory)
        
        return {
            'inventory': inventory,
            'issues': issues,
            'summary': self.generate_summary(inventory)
        }
    
    def scan_aws(self):
        """Scan AWS certificates from ACM and Secrets Manager"""
        
        certificates = []
        
        # Scan ACM certificates in all regions
        for region in ['us-east-1', 'us-west-2', 'eu-west-1']:
            acm = boto3.client('acm', region_name=region)
            
            paginator = acm.get_paginator('list_certificates')
            for page in paginator.paginate():
                for cert_summary in page['CertificateSummaryList']:
                    cert = acm.describe_certificate(
                        CertificateArn=cert_summary['CertificateArn']
                    )['Certificate']
                    
                    certificates.append({
                        'cloud': 'aws',
                        'region': region,
                        'service': 'acm',
                        'id': cert['CertificateArn'],
                        'domain': cert['DomainName'],
                        'sans': cert.get('SubjectAlternativeNames', []),
                        'issuer': cert.get('Issuer'),
                        'not_before': cert['NotBefore'].isoformat(),
                        'not_after': cert['NotAfter'].isoformat(),
                        'status': cert['Status'],
                        'in_use': len(cert.get('InUseBy', [])) > 0
                    })
        
        # Scan Secrets Manager for certificates
        sm_certs = self.scan_aws_secrets_manager()
        certificates.extend(sm_certs)
        
        return certificates
    
    def scan_azure(self):
        """Scan Azure Key Vault certificates"""
        
        certificates = []
        
        # List all vaults (would need to iterate subscriptions/resource groups)
        for vault_url in self.get_azure_vaults():
            client = CertificateClient(
                vault_url=vault_url,
                credential=DefaultAzureCredential()
            )
            
            for cert_properties in client.list_properties_of_certificates():
                cert = client.get_certificate(cert_properties.name)
                
                certificates.append({
                    'cloud': 'azure',
                    'service': 'key_vault',
                    'vault': vault_url,
                    'id': cert.id,
                    'name': cert.name,
                    'sans': self.extract_sans_from_azure(cert),
                    'not_before': cert.properties.not_before.isoformat(),
                    'not_after': cert.properties.not_after.isoformat(),
                    'enabled': cert.properties.enabled
                })
        
        return certificates
    
    def scan_gcp(self):
        """Scan GCP Certificate Manager"""
        
        certificates = []
        
        client = CertificateManagerClient()
        
        # List certificates across all locations
        for location in ['global', 'us-central1', 'europe-west1']:
            parent = f"projects/{self.gcp_project}/locations/{location}"
            
            for cert in client.list_certificates(parent=parent):
                certificates.append({
                    'cloud': 'gcp',
                    'location': location,
                    'service': 'certificate_manager',
                    'id': cert.name,
                    'domains': cert.managed.domains if cert.managed else [],
                    'expire_time': cert.expire_time.isoformat() if cert.expire_time else None,
                    'scope': cert.scope
                })
        
        return certificates
    
    def analyze_inventory(self, inventory):
        """Identify issues in certificate inventory"""
        
        issues = []
        now = datetime.utcnow()
        
        for cloud, certificates in inventory.items():
            if cloud == 'timestamp':
                continue
                
            for cert in certificates:
                # Check expiration
                not_after = datetime.fromisoformat(cert['not_after'].replace('Z', '+00:00'))
                days_until_expiry = (not_after - now).days
                
                if days_until_expiry < 0:
                    issues.append({
                        'severity': 'critical',
                        'type': 'expired',
                        'cloud': cloud,
                        'certificate': cert['id'],
                        'domain': cert.get('domain', cert.get('name')),
                        'expired_days_ago': abs(days_until_expiry)
                    })
                elif days_until_expiry < 30:
                    issues.append({
                        'severity': 'warning',
                        'type': 'expiring_soon',
                        'cloud': cloud,
                        'certificate': cert['id'],
                        'domain': cert.get('domain', cert.get('name')),
                        'days_until_expiry': days_until_expiry
                    })
                
                # Check if certificate is unused
                if 'in_use' in cert and not cert['in_use']:
                    issues.append({
                        'severity': 'info',
                        'type': 'unused',
                        'cloud': cloud,
                        'certificate': cert['id']
                    })
        
        return issues
```

### Metrics and Alerting

```python
from prometheus_client import Gauge, Counter

# Define metrics
certificates_total = Gauge(
    'multicloud_certificates_total',
    'Total certificates',
    ['cloud', 'status']
)

certificates_expiring = Gauge(
    'multicloud_certificates_expiring',
    'Certificates expiring soon',
    ['cloud', 'days_threshold']
)

certificate_renewals = Counter(
    'multicloud_certificate_renewals_total',
    'Certificate renewals',
    ['cloud', 'success']
)

class MultiCloudMetrics:
    """Collect and expose metrics for multi-cloud certificates"""
    
    def update_metrics(self, inventory):
        """Update Prometheus metrics from inventory"""
        
        # Reset gauges
        certificates_total._metrics.clear()
        certificates_expiring._metrics.clear()
        
        for cloud, certificates in inventory.items():
            if cloud == 'timestamp':
                continue
            
            # Count by status
            status_counts = {}
            for cert in certificates:
                status = cert.get('status', 'unknown')
                status_counts[status] = status_counts.get(status, 0) + 1
            
            for status, count in status_counts.items():
                certificates_total.labels(cloud=cloud, status=status).set(count)
            
            # Count expiring certificates
            now = datetime.utcnow()
            expiring_30 = 0
            expiring_60 = 0
            expiring_90 = 0
            
            for cert in certificates:
                not_after = datetime.fromisoformat(cert['not_after'].replace('Z', '+00:00'))
                days = (not_after - now).days
                
                if days < 30:
                    expiring_30 += 1
                if days < 60:
                    expiring_60 += 1
                if days < 90:
                    expiring_90 += 1
            
            certificates_expiring.labels(cloud=cloud, days_threshold='30').set(expiring_30)
            certificates_expiring.labels(cloud=cloud, days_threshold='60').set(expiring_60)
            certificates_expiring.labels(cloud=cloud, days_threshold='90').set(expiring_90)
```

---

## Common Pitfalls

### Cloud-Specific Lock-In
**Problem**: Deep integration with cloud-native services makes migration impossible  
**Solution**: Use cloud-agnostic tools (Vault, cert-manager), maintain portability as design principle

### Inconsistent Policies
**Problem**: Different certificate policies across clouds create security gaps  
**Solution**: Centralized policy engine, enforce at issuance regardless of cloud

### Secret Sprawl
**Problem**: Certificates stored inconsistently across cloud secret stores  
**Solution**: Unified secrets management strategy, automated distribution

### Monitoring Blindness
**Problem**: Cannot see certificates across all clouds simultaneously  
**Solution**: Centralized inventory system, regular scanning, unified dashboards

### Manual Processes
**Problem**: Cloud-specific renewal processes create operational burden  
**Solution**: Automation using cert-manager or similar tools that work identically everywhere

---

## Security Considerations

### Trust Chain Management
- Maintain consistent root CA across all clouds
- Protect root CA private key in HSM or air-gapped system
- Document and test trust chain validation
- Plan for CA key rotation across all environments

### Secrets Security
- Encrypt certificates at rest in all cloud secret stores
- Use IAM/RBAC to restrict certificate access
- Audit all certificate retrievals
- Implement secrets rotation policies

### Network Security
- Use private endpoints for certificate issuance
- Encrypt all certificate distribution
- Implement network segmentation
- Monitor for unauthorized access patterns

### Compliance
- Maintain audit logs across all clouds
- Document certificate lifecycle for compliance
- Implement retention policies consistently
- Regular compliance assessments

---

## Real-World Examples

### Large Financial Institution
Multi-cloud deployment across AWS, Azure, on-premises:


- Centralized Vault cluster for certificate issuance
- 50,000+ certificates across 3 clouds and on-prem
- 90-day certificate lifetimes with automated renewal
- Kubernetes cert-manager in all clouds
- Istio service mesh for mTLS across clouds
- Centralized monitoring via Splunk
- Compliance reporting for PCI-DSS, SOC 2

**Lessons**: Centralization essential at scale, cloud-agnostic tools critical, automation non-negotiable, visibility requires dedicated tooling.

### SaaS Provider
Global deployment across AWS and GCP:


- HashiCorp Vault in both clouds
- Let's Encrypt for external certificates
- Vault PKI for internal microservices
- Cert-manager in all Kubernetes clusters
- Unified certificate inventory system
- Automated renewal 30 days before expiry
- Prometheus metrics for monitoring

**Lessons**: Public and private PKI can coexist, Kubernetes makes multi-cloud simpler, observability prevents outages, automation enables developer self-service.

### Enterprise with Hybrid Cloud
Azure primary, AWS secondary, large on-premises:


- On-premises root CA (air-gapped)
- Issuing CAs in Azure and AWS
- SCEP for legacy systems
- ACME for modern workloads
- Azure Key Vault and AWS Secrets Manager
- Manual approval for external certificates
- Automated internal certificates

**Lessons**: Hybrid requires multiple protocols, legacy systems need different approaches, governance layers can slow automation, gradual migration necessary.

---

## Further Reading

### Standards and Documentation
- NIST SP 800-57: Key Management Recommendations
- Cloud Security Alliance: PKI in Cloud Environments
- AWS ACM Documentation: https://docs.aws.amazon.com/acm/
- Azure Key Vault Certificates: https://docs.microsoft.com/azure/key-vault/certificates/
- GCP Certificate Manager: https://cloud.google.com/certificate-manager/docs

### Related Pages
- [Certificate Issuance Workflows](./certificate-issuance-workflows.md) - Workflow automation
- [ACME Protocol Implementation](./acme-protocol-implementation.md) - ACME servers
- [HSM Integration](./hsm-integration.md) - Hardware security modules
- [Certificate Lifecycle Management](./certificate-lifecycle-management.md) - Lifecycle automation
- [CA Architecture](./ca-architecture.md) - CA design patterns

### Tools and Projects
- cert-manager: https://cert-manager.io/
- HashiCorp Vault: https://www.vaultproject.io/
- Istio: https://istio.io/
- SPIFFE/SPIRE: https://spiffe.io/
- Terraform: https://www.terraform.io/

---

**Last Updated**: 2025-11-09  
**Maintenance Notes**: Update cloud provider service features regularly (frequent changes), add new multi-cloud tools, expand service mesh patterns, track cloud pricing changes for PKI services