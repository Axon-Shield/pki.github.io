# High Availability and Disaster Recovery

## Overview

PKI infrastructure is critical path for most organizations—when certificate services are unavailable, applications fail to start, APIs reject connections, and business grinds to halt. Yet many organizations deploy PKI as a single point of failure, assuming it will never fail. This assumption proves expensive when certificate authorities become unavailable during business-critical moments.

**Core principle**: Plan for failure. PKI components will fail—hardware faults, software bugs, operator errors, security incidents, and natural disasters all threaten availability. Resilient PKI architecture assumes failure and designs around it.

## Availability Requirements

### Understanding Your Needs

Not all PKI components need the same availability:

**Certificate issuance**:
- For automated systems (ACME, APIs): High availability needed (99.9%+)
- For manual requests: Lower availability acceptable (99%)
- Can often tolerate brief outages if retry mechanisms exist
- Impact: New certificates can't be issued during outage

**Certificate validation** (OCSP/CRL):
- Critical for security: Should be highly available (99.95%+)
- Failure may block all TLS connections depending on policy
- Caching provides resilience during brief outages
- Impact: Applications may fail to start or reject connections

**Certificate revocation**:
- Emergency revocations need immediate processing
- Regular revocations can tolerate some delay
- Impact: Compromised certificates remain trusted longer

Calculate acceptable downtime:

```python
class AvailabilityCalculator:
    """
    Calculate downtime for different availability targets
    """
    
    AVAILABILITY_TARGETS = {
        '90%': {
            'year': timedelta(days=36.5),
            'month': timedelta(days=3),
            'week': timedelta(hours=16.8),
            'day': timedelta(hours=2.4)
        },
        '99%': {
            'year': timedelta(days=3.65),
            'month': timedelta(hours=7.2),
            'week': timedelta(hours=1.68),
            'day': timedelta(minutes=14.4)
        },
        '99.9%': {
            'year': timedelta(hours=8.76),
            'month': timedelta(minutes=43.2),
            'week': timedelta(minutes=10.1),
            'day': timedelta(seconds=86.4)
        },
        '99.95%': {
            'year': timedelta(hours=4.38),
            'month': timedelta(minutes=21.6),
            'week': timedelta(minutes=5.04),
            'day': timedelta(seconds=43.2)
        },
        '99.99%': {
            'year': timedelta(minutes=52.56),
            'month': timedelta(minutes=4.32),
            'week': timedelta(seconds=60.5),
            'day': timedelta(seconds=8.64)
        },
        '99.999%': {
            'year': timedelta(minutes=5.26),
            'month': timedelta(seconds=25.9),
            'week': timedelta(seconds=6.05),
            'day': timedelta(seconds=0.864)
        }
    }
    
    def business_impact(self, availability_target: str, 
                       revenue_per_hour: float) -> dict:
        """
        Calculate business impact of downtime
        """
        downtime_per_year = self.AVAILABILITY_TARGETS[availability_target]['year']
        downtime_hours = downtime_per_year.total_seconds() / 3600
        
        return {
            'availability': availability_target,
            'downtime_per_year': str(downtime_per_year),
            'downtime_hours': downtime_hours,
            'revenue_impact': revenue_per_hour * downtime_hours,
            'cost_per_hour': revenue_per_hour,
            'monthly_downtime': str(self.AVAILABILITY_TARGETS[availability_target]['month'])
        }
```

## High Availability Patterns

### Active-Passive with Shared Storage

Classic HA pattern: two CA servers sharing certificate database and HSM.

```
┌─────────────┐          ┌─────────────┐
│   Primary   │          │  Secondary  │
│  CA Server  │          │  CA Server  │
└──────┬──────┘          └──────┬──────┘
       │                        │
       └────────┬───────────────┘
                │
         ┌──────▼──────┐
         │   Shared    │
         │   Storage   │
         │  (Database) │
         └──────┬──────┘
                │
         ┌──────▼──────┐
         │  Network    │
         │    HSM      │
         └─────────────┘
```

**Characteristics**:
- Primary handles all requests
- Secondary monitors primary health
- Failover when primary fails
- Both servers access same data
- Single HSM (network-attached)

**Advantages**:
- Simple to understand and operate
- Consistent data (single database)
- Fast failover (seconds to minutes)
- Lower infrastructure cost

**Disadvantages**:
- Database is single point of failure
- HSM is single point of failure
- No geographic distribution
- Failover requires automation or manual intervention

**Implementation**:

```python
class ActivePassiveCA:
    """
    Active-passive CA with shared storage
    """
    
    def __init__(self):
        # Shared components
        self.database = PostgreSQL(
            hosts=['db-primary', 'db-replica'],
            replication='synchronous'
        )
        
        self.hsm = NetworkHSM(
            model='thales_luna_sa',
            ha_config='network_attached',
            partition='ca_partition'
        )
        
        # Primary CA server
        self.primary = CAServer(
            hostname='ca-primary',
            database=self.database,
            hsm=self.hsm,
            role='active'
        )
        
        # Secondary CA server
        self.secondary = CAServer(
            hostname='ca-secondary',
            database=self.database,
            hsm=self.hsm,
            role='standby'
        )
        
        # Heartbeat and failover
        self.cluster = Pacemaker(
            nodes=[self.primary, self.secondary],
            virtual_ip='10.1.2.100',
            resource_constraints={
                'ca_service': 'only_one_active',
                'virtual_ip': 'follows_ca_service'
            }
        )
    
    def handle_primary_failure(self):
        """
        Automatic failover to secondary
        """
        # 1. Detect primary failure (missed heartbeats)
        if not self.primary.is_healthy():
            
            # 2. Fence primary (prevent split-brain)
            self.cluster.fence_node(self.primary)
            
            # 3. Activate secondary
            self.secondary.activate()
            
            # 4. Move virtual IP to secondary
            self.cluster.move_virtual_ip(self.secondary)
            
            # 5. Resume operations
            # Clients automatically connect to new active via VIP
```

### Active-Active with Load Balancing

Multiple CA servers actively handling requests.

```
               ┌──────────────┐
               │Load Balancer │
               └───────┬──────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
   ┌────▼────┐    ┌────▼────┐   ┌────▼────┐
   │  CA-1   │    │  CA-2   │   │  CA-3   │
   │ Active  │    │ Active  │   │ Active  │
   └────┬────┘    └────┬────┘   └────┬────┘
        │              │              │
        └──────────────┼──────────────┘
                       │
                ┌──────▼──────┐
                │  Database   │
                │  Cluster    │
                └──────┬──────┘
                       │
                ┌──────▼──────┐
                │  HSM Pool   │
                └─────────────┘
```

**Characteristics**:
- All servers active and processing requests
- Load balancer distributes traffic
- Shared database cluster
- HSM pool or key replication

**Advantages**:
- Higher throughput than active-passive
- No failover needed (load balancer routes around failures)
- Better resource utilization
- Scales horizontally

**Disadvantages**:
- More complex configuration
- Database synchronization challenges
- HSM key synchronization required
- Higher infrastructure cost

**Implementation considerations**:

```python
class ActiveActiveCA:
    """
    Active-active CA cluster
    """
    
    def __init__(self):
        # Database cluster
        self.database = PostgreSQLCluster(
            nodes=[
                'db-1.example.com',
                'db-2.example.com',
                'db-3.example.com'
            ],
            replication='multi-master',
            consistency='strong'
        )
        
        # HSM pool (networked HSMs or replicated keys)
        self.hsm_pool = HSMPool([
            NetworkHSM('hsm-1.example.com', partition='ca'),
            NetworkHSM('hsm-2.example.com', partition='ca'),
            NetworkHSM('hsm-3.example.com', partition='ca')
        ])
        
        # CA servers
        self.ca_servers = [
            CAServer('ca-1', self.database, self.hsm_pool),
            CAServer('ca-2', self.database, self.hsm_pool),
            CAServer('ca-3', self.database, self.hsm_pool)
        ]
        
        # Load balancer
        self.load_balancer = LoadBalancer(
            algorithm='least_connections',
            servers=self.ca_servers,
            health_check={
                'interval': 10,  # seconds
                'timeout': 5,
                'unhealthy_threshold': 3,
                'healthy_threshold': 2,
                'path': '/health'
            },
            session_affinity=False  # No sticky sessions needed
        )
    
    def handle_server_failure(self, failed_server: CAServer):
        """
        Automatic handling of server failure
        """
        # Load balancer automatically routes around failed server
        # No manual intervention needed
        
        # Alert operations team
        self.alert(f"CA server {failed_server.hostname} failed health check")
        
        # Remaining servers continue handling all traffic
        # No service disruption
```

### Geographic Distribution

CA infrastructure across multiple regions for resilience and latency.

```
       Region A (Primary)              Region B (DR)
┌──────────────────────────┐   ┌──────────────────────────┐
│  ┌────────────────┐      │   │      ┌────────────────┐  │
│  │Load Balancer   │      │   │      │Load Balancer   │  │
│  └────┬───────────┘      │   │      └────┬───────────┘  │
│       │                  │   │           │              │
│  ┌────▼────┐  ┌────────┐│   │  ┌────────┐  ┌────▼────┐│
│  │  CA-1   │  │  CA-2  ││   │  │  CA-3  │  │  CA-4   ││
│  └────┬────┘  └────┬───┘│   │  └────┬───┘  └────┬────┘│
│       │            │    │   │       │           │     │
│  ┌────▼────────────▼──┐ │   │  ┌────▼───────────▼───┐ │
│  │   Database         │◄┼───┼─►│   Database         │ │
│  │   Primary          │ │   │  │   Replica          │ │
│  └────┬───────────────┘ │   │  └────────────────────┘ │
│       │                 │   │                          │
│  ┌────▼──────┐          │   │          ┌────────────┐ │
│  │   HSM     │          │   │          │    HSM     │ │
│  └───────────┘          │   │          └────────────┘ │
└──────────────────────────┘   └──────────────────────────┘
        │                               │
        └───────────Replication─────────┘
```

**Characteristics**:
- CA infrastructure in multiple geographic regions
- Primary region handles normal traffic
- DR region ready for failover
- Database replication across regions
- HSM key replication (or backup/restore)

**Advantages**:
- Resilience to regional outages
- Lower latency for distributed users
- Geographic redundancy
- Disaster recovery built-in

**Disadvantages**:
- Complex replication and consistency
- Higher latency for cross-region operations
- More expensive infrastructure
- Network dependencies between regions

**Deployment pattern**:

```python
class GeographicDistribution:
    """
    Multi-region CA deployment
    """
    
    def __init__(self):
        # Primary region (active)
        self.region_a = Region(
            name='us-east-1',
            ca_servers=[
                CAServer('ca-1a'),
                CAServer('ca-2a')
            ],
            database=DatabaseCluster([
                'db-1a', 'db-2a'
            ], role='primary'),
            hsm=HSMCluster(['hsm-1a']),
            load_balancer='lb-a.example.com'
        )
        
        # DR region (standby)
        self.region_b = Region(
            name='us-west-2',
            ca_servers=[
                CAServer('ca-1b'),
                CAServer('ca-2b')
            ],
            database=DatabaseCluster([
                'db-1b', 'db-2b'
            ], role='replica'),
            hsm=HSMCluster(['hsm-1b']),
            load_balancer='lb-b.example.com'
        )
        
        # Cross-region replication
        self.replication = DatabaseReplication(
            source=self.region_a.database,
            target=self.region_b.database,
            mode='async',  # or 'sync' for stronger consistency
            lag_alert_threshold=timedelta(seconds=30)
        )
        
        # Global DNS for failover
        self.dns = Route53(
            domain='ca.example.com',
            primary_endpoint=self.region_a.load_balancer,
            failover_endpoint=self.region_b.load_balancer,
            health_check_interval=30,
            failover_policy='automatic'
        )
    
    def regional_failover(self):
        """
        Failover to DR region
        """
        # 1. Detect primary region failure
        if not self.region_a.is_healthy():
            
            # 2. Promote replica database to primary
            self.region_b.database.promote_to_primary()
            
            # 3. Activate CA servers in DR region
            for ca_server in self.region_b.ca_servers:
                ca_server.activate()
            
            # 4. Update DNS to point to DR region
            self.dns.update_primary(self.region_b.load_balancer)
            
            # 5. Verify DR region operations
            assert self.region_b.is_healthy()
            
            # 6. Alert operations team
            self.alert("Failover to Region B completed")
```

## Disaster Recovery

### Recovery Time Objective (RTO) and Recovery Point Objective (RPO)

Define acceptable recovery parameters:

**RTO** - How quickly must services be restored?
- Tier 1 (Critical): < 1 hour
- Tier 2 (Important): < 4 hours  
- Tier 3 (Standard): < 24 hours

**RPO** - How much data loss is acceptable?
- Tier 1 (Critical): Zero data loss (synchronous replication)
- Tier 2 (Important): < 5 minutes of data loss
- Tier 3 (Standard): < 1 hour of data loss

```python
class DisasterRecoveryPlanning:
    """
    Define recovery objectives for PKI components
    """
    
    COMPONENT_TIERS = {
        'issuing_ca_production': {
            'rto': timedelta(hours=1),
            'rpo': timedelta(0),  # Zero data loss
            'tier': 1,
            'justification': 'Certificate issuance critical for production deployments'
        },
        
        'ocsp_responder': {
            'rto': timedelta(minutes=15),
            'rpo': timedelta(hours=1),  # OCSP responses cached
            'tier': 1,
            'justification': 'Certificate validation required for all TLS connections'
        },
        
        'crl_publication': {
            'rto': timedelta(hours=4),
            'rpo': timedelta(hours=24),  # CRL published daily
            'tier': 2,
            'justification': 'CRL updates can tolerate some delay'
        },
        
        'certificate_inventory': {
            'rto': timedelta(hours=24),
            'rpo': timedelta(hours=1),
            'tier': 3,
            'justification': 'Inventory for management, not critical path'
        },
        
        'root_ca': {
            'rto': timedelta(days=7),
            'rpo': timedelta(0),  # Cannot lose root key
            'tier': 1,
            'justification': 'Root CA offline, rarely used, but key loss catastrophic'
        }
    }
```

### Backup Strategies

**What to backup**:

1. **CA private keys** (critical)
   - HSM-encrypted backups
   - Split across multiple custodians (Shamir's Secret Sharing)
   - Geographic distribution
   - Test restoration quarterly

2. **CA certificates**
   - Full certificate chains
   - All intermediate CA certificates
   - Historical certificates (for validation)

3. **Configuration**
   - CA server configuration
   - Certificate profiles and policies
   - Issuance rules and workflows
   - Validation configurations

4. **Database**
   - Certificate issuance records
   - Audit logs
   - Revocation lists
   - OCSP responder data

5. **Documentation**
   - Certificate Policy / CPS
   - Operational procedures
   - Recovery procedures
   - Contact information

**Backup implementation**:

```python
class PKIBackupSystem:
    """
    Comprehensive PKI backup and recovery
    """
    
    def __init__(self):
        self.backup_schedule = {
            'ca_keys': {
                'frequency': 'on_generation',  # One-time + after rotation
                'method': 'hsm_export_encrypted',
                'storage': 'multiple_geographic_locations',
                'encryption': 'split_key_custody',
                'test_frequency': 'quarterly'
            },
            
            'database': {
                'frequency': 'continuous',  # Streaming replication
                'method': 'pg_replication',
                'retention': '90_days',
                'test_frequency': 'monthly'
            },
            
            'configuration': {
                'frequency': 'daily',
                'method': 'git_repository',
                'storage': 'github_enterprise',
                'retention': 'indefinite'
            },
            
            'audit_logs': {
                'frequency': 'real_time',
                'method': 'siem_forwarding',
                'retention': '7_years',
                'immutable': True
            }
        }
    
    def backup_ca_private_key(self, ca: CA):
        """
        Backup CA private key with split custody
        """
        # 1. Export key from HSM (encrypted)
        encrypted_key_blob = ca.hsm.export_key(
            key_id=ca.key_id,
            wrap_key=self.backup_wrap_key
        )
        
        # 2. Split using Shamir's Secret Sharing (3-of-5)
        shares = SecretSharer.split_secret(
            encrypted_key_blob,
            threshold=3,
            num_shares=5
        )
        
        # 3. Distribute to custodians
        custodians = [
            'security_officer',
            'ca_administrator',
            'ciso',
            'safety_deposit_box_a',
            'safety_deposit_box_b'
        ]
        
        for custodian, share in zip(custodians, shares):
            self.distribute_key_share(custodian, share)
        
        # 4. Document backup
        self.log_backup_event(ca, custodians)
    
    def test_backup_restoration(self):
        """
        Regularly test backup restoration procedures
        """
        # Test in isolated environment
        test_env = IsolatedTestEnvironment()
        
        # Attempt to restore from backup
        try:
            # Restore database
            restored_db = self.restore_database(
                target=test_env.database,
                backup_date=datetime.now() - timedelta(days=1)
            )
            
            # Restore configuration
            restored_config = self.restore_configuration(
                target=test_env.ca_server
            )
            
            # Verify restoration
            assert restored_db.validate_integrity()
            assert restored_config.validate()
            
            # Test CA operations
            test_cert = test_env.ca.issue_test_certificate()
            assert test_cert is not None
            
            return TestResult(success=True, message="Backup restoration successful")
            
        except Exception as e:
            return TestResult(success=False, error=str(e))
```

### Recovery Procedures

**Scenario 1: Single Server Failure**

Restore time: < 1 hour (RTO)

```
1. Detect failure via monitoring
2. Automatic failover to standby (if configured)
   OR
   Manual server rebuild:
   - Provision new server
   - Restore configuration from backup/repo
   - Point to shared database
   - Connect to HSM
   - Test and activate
3. Verify operations normal
4. Document incident
```

**Scenario 2: Database Corruption**

Restore time: < 4 hours (RTO)

```
1. Detect corruption (integrity checks, application errors)
2. Stop all CA operations
3. Assess corruption extent
4. Restore from most recent clean backup:
   - Identify backup point before corruption
   - Restore database from backup
   - Replay transaction logs if available
   - Verify database integrity
5. Restart CA operations
6. Verify recently issued certificates
7. Document incident and root cause
```

**Scenario 3: Complete Datacenter Loss**

Restore time: < 24 hours (RTO)

```
1. Declare disaster
2. Activate DR site:
   - Promote DR database replica to primary
   - Activate DR CA servers
   - Update DNS to DR location
   - Verify HSM connectivity
3. Resume operations at DR site
4. Communicate status to stakeholders
5. Monitor DR site operations
6. Plan primary site recovery
7. Execute failback when primary restored
```

**Scenario 4: HSM Failure**

Restore time: < 4 hours (RTO) if spare available

```
1. Detect HSM failure
2. If spare HSM available:
   - Restore keys from encrypted backup
   - Requires multiple custodians (3-of-5 shares)
   - Reconstitute keys in new HSM
   - Verify key integrity
   - Resume operations
3. If no spare:
   - Procure emergency replacement HSM
   - Restore keys (multiple custodians required)
   - May take days if HSM must be acquired
4. Document incident
5. Review HSM redundancy
```

**Scenario 5: Root CA Key Loss**

Restore time: Weeks (catastrophic scenario)

```
1. Attempt key recovery:
   - Gather custodians with key shares
   - Reconstitute root key
   - Verify key matches root certificate
2. If recovery impossible:
   - DISASTER: Entire PKI must be rebuilt
   - Generate new root CA
   - Reissue all intermediate CAs
   - Reissue all end-entity certificates
   - Update all trust stores
   - May take months for complete transition
3. Root cause analysis
4. Implement additional protections
```

### Recovery Testing

Regular testing ensures recovery procedures work when needed:

```python
class DisasterRecoveryTesting:
    """
    Regular DR testing and validation
    """
    
    def __init__(self):
        self.test_schedule = {
            'component_recovery': 'monthly',
            'database_restoration': 'monthly',
            'full_dr_failover': 'quarterly',
            'tabletop_exercise': 'quarterly',
            'full_disaster_simulation': 'annually'
        }
    
    def monthly_component_recovery(self):
        """
        Test recovery of individual components
        """
        tests = []
        
        # Test 1: Restore CA server from configuration
        tests.append(self.test_ca_server_rebuild())
        
        # Test 2: Database point-in-time recovery
        tests.append(self.test_database_restoration())
        
        # Test 3: Configuration restoration
        tests.append(self.test_configuration_restoration())
        
        # Report results
        return TestReport(tests)
    
    def quarterly_full_failover(self):
        """
        Full failover to DR site
        """
        # 1. Schedule during maintenance window
        # 2. Announce test to all stakeholders
        # 3. Execute failover procedure
        # 4. Verify DR site operations
        # 5. Run synthetic transactions
        # 6. Fail back to primary
        # 7. Document lessons learned
        pass
    
    def annual_disaster_simulation(self):
        """
        Comprehensive disaster recovery drill
        """
        # Simulate complete primary site loss
        # - No notice (surprise drill)
        # - Activate full DR procedures
        # - Involve all teams
        # - Time all recovery steps
        # - Document everything
        # - Post-drill review and improvements
        pass
```

## Monitoring for HA/DR

### Health Checks

Continuous monitoring of all PKI components:

```python
class PKIHealthMonitoring:
    """
    Comprehensive health monitoring for HA/DR
    """
    
    def monitor_ca_health(self):
        """
        Monitor CA server health
        """
        checks = {
            'service_responding': self.check_ca_service(),
            'hsm_connectivity': self.check_hsm_connection(),
            'database_connectivity': self.check_database(),
            'disk_space': self.check_disk_space(),
            'certificate_expiry': self.check_ca_certificate_expiry(),
            'cpu_usage': self.check_cpu(),
            'memory_usage': self.check_memory(),
            'audit_logging': self.check_audit_logs()
        }
        
        # Aggregate health status
        if all(checks.values()):
            return HealthStatus.HEALTHY
        elif checks['service_responding'] and checks['hsm_connectivity']:
            return HealthStatus.DEGRADED
        else:
            return HealthStatus.UNHEALTHY
    
    def monitor_replication_lag(self):
        """
        Monitor database replication for DR
        """
        lag = self.measure_replication_lag()
        
        if lag > timedelta(minutes=5):
            self.alert(
                severity='critical',
                message=f'Replication lag {lag} exceeds threshold'
            )
        elif lag > timedelta(minutes=1):
            self.alert(
                severity='warning',
                message=f'Replication lag elevated: {lag}'
            )
    
    def monitor_backup_health(self):
        """
        Monitor backup success and freshness
        """
        last_backup = self.get_last_backup_time()
        backup_age = datetime.now() - last_backup
        
        if backup_age > timedelta(hours=25):  # Daily backup + buffer
            self.alert(
                severity='critical',
                message=f'Last backup {backup_age} ago, may be stale'
            )
```

## Best Practices

**High availability**:
- Active-passive sufficient for most organizations
- Active-active for high-volume or global deployments
- Load balancer with health checks
- Automated failover where possible
- Geographic distribution for critical systems
- Regular failover testing

**Disaster recovery**:
- Define RTO and RPO for each component
- Backup everything (keys, data, configuration, docs)
- Test backups regularly (monthly minimum)
- Geographic distribution of backups
- Documented and tested recovery procedures
- DR site ready and regularly validated

**Monitoring**:
- Comprehensive health checks
- Replication lag monitoring
- Backup success monitoring
- Alerting on any anomalies
- Dashboard for system health
- Regular capacity planning

**Testing**:
- Monthly component recovery tests
- Quarterly full DR failovers
- Annual disaster simulation
- Tabletop exercises for scenarios
- Document all test results
- Improve procedures based on findings

## Conclusion

High availability and disaster recovery aren't luxuries for PKI—they're requirements. When your PKI fails, your entire digital infrastructure fails with it. The investment in HA/DR infrastructure and regular testing pays for itself the first time it prevents or quickly resolves an outage.

Build resilience in layers: component redundancy, geographic distribution, comprehensive backups, documented procedures, and regular testing. Don't wait for a disaster to discover your recovery procedures don't work. Test them now, while the stakes are low.

Remember: You don't have HA/DR until you've tested it. Untested disaster recovery procedures are fiction, not insurance.

## References

### Business Continuity Standards

**ISO 22301 - Business Continuity Management**
- ISO. "Security and resilience — Business continuity management systems." ISO 22301:2019.
  - https://www.iso.org/standard/75106.html
- Business continuity framework
- Recovery strategies
- Testing requirements

**NIST SP 800-34 - Contingency Planning Guide**
- NIST. "Contingency Planning Guide for Federal Information Systems." Revision 1, May 2010.
  - https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final
- Contingency planning framework
- Recovery strategies
- Testing and exercises

**BS 25999 / ISO 22313 - Business Continuity Management**
- ISO. "Security and resilience — Business continuity management systems — Guidance on the use of ISO 22301." ISO 22313:2020.
- Implementation guidance
- Recovery time objectives
- Business impact analysis

### Disaster Recovery Planning

**NIST SP 800-184 - Guide for Cybersecurity Event Recovery**
- NIST. "Guide for Cybersecurity Event Recovery." December 2016.
  - https://csrc.nist.gov/publications/detail/sp/800-184/final
- Recovery planning framework
- Communication strategies
- Lessons learned process

**"Disaster Recovery Planning" (Wiley)**
- Wallace, M., Webber, L. "The Disaster Recovery Handbook: A Step-by-Step Plan to Ensure Business Continuity." 3rd Edition, AMACOM, 2017.
- Comprehensive DR planning
- Testing methodologies
- Recovery strategies

### High Availability Architecture

**"Site Reliability Engineering" (O'Reilly)**
- Beyer, B., et al. "Site Reliability Engineering: How Google Runs Production Systems." O'Reilly, 2016.
  - https://sre.google/books/
- Reliability principles
- Eliminating single points of failure
- Testing and validation

**"Designing Data-Intensive Applications" (O'Reilly)**
- Kleppmann, M. "Designing Data-Intensive Applications." O'Reilly, 2017.
- Replication patterns
- Consistency models
- Distributed systems reliability

### Database High Availability

**PostgreSQL High Availability Documentation**
- PostgreSQL. "High Availability, Load Balancing, and Replication."
  - https://www.postgresql.org/docs/current/high-availability.html
- Streaming replication
- Synchronous vs asynchronous
- Failover configuration

**MySQL Group Replication**
- Oracle. "MySQL Group Replication."
  - https://dev.mysql.com/doc/refman/8.0/en/group-replication.html
- Multi-primary replication
- Automatic failover
- Conflict detection

**MongoDB Replica Sets**
- MongoDB. "Replication."
  - https://docs.mongodb.com/manual/replication/
- Replica set configuration
- Automatic failover
- Read preference strategies

### HSM Backup and Recovery

**NIST SP 800-57 Part 2 - Key Management**
- NIST. "Recommendation for Key Management: Part 2 - Best Practices for Key Management Organizations." Revision 1, May 2019.
  - https://csrc.nist.gov/publications/detail/sp/800-57-part-2/rev-1/final
- Key backup strategies
- Disaster recovery for keys
- Geographic distribution

**Thales Luna HSM - Backup and Recovery**
- Thales. "Luna HSM Backup and Recovery Guide."
- HSM backup procedures
- Key replication
- Disaster recovery testing

**PKCS #11 - Backup and Restore**
- OASIS. "PKCS #11 Cryptographic Token Interface."
  - http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/
- Token backup mechanisms
- Key wrapping
- Secure transport

### Load Balancing and Clustering

**HAProxy Documentation**
- HAProxy. "The Reliable, High Performance TCP/HTTP Load Balancer."
  - http://www.haproxy.org/
- Health check configuration
- Session persistence
- Failover strategies

**Keepalived - VRRP Implementation**
- Keepalived. "Keepalived for Linux."
  - https://www.keepalived.org/
- Virtual IP failover
- Health checking
- VRRP protocol

**Pacemaker + Corosync**
- ClusterLabs. "Pacemaker Cluster Resource Manager."
  - https://clusterlabs.org/pacemaker/
- Cluster resource management
- Fencing and STONITH
- Resource constraints

### Cloud HA/DR

**AWS Well-Architected Framework - Reliability Pillar**
- AWS. "Reliability Pillar - AWS Well-Architected Framework."
  - https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/
- Multi-AZ deployment
- Backup strategies
- Disaster recovery patterns

**Azure Site Recovery**
- Microsoft. "Azure Site Recovery."
  - https://docs.microsoft.com/en-us/azure/site-recovery/
- Replication and failover
- Recovery plans
- Testing procedures

**Google Cloud Architecture Framework - Reliability**
- Google Cloud. "Architecture Framework: Reliability."
  - https://cloud.google.com/architecture/framework/reliability
- Regional and multi-regional deployment
- Backup and disaster recovery
- RPO and RTO planning

### Monitoring and Observability

**Prometheus - High Availability**
- Prometheus. "High Availability."
  - https://prometheus.io/docs/introduction/faq/#can-prometheus-be-made-highly-available
- Federation and remote storage
- Monitoring best practices

**Nagios / Icinga Monitoring**
- Nagios. "Nagios Core Documentation."
  - https://www.nagios.org/documentation/
- Infrastructure monitoring
- Service checks
- Alert escalation

**NIST SP 800-92 - Log Management**
- NIST. "Guide to Computer Security Log Management." September 2006.
  - https://csrc.nist.gov/publications/detail/sp/800-92/final
- Log management strategies
- Monitoring and analysis
- Retention requirements

### Backup Technologies

**Veeam Backup & Replication**
- Veeam. "Veeam Backup & Replication."
  - https://www.veeam.com/
- Backup best practices
- Replication strategies
- Recovery testing

**Commvault**
- Commvault. "Backup and Recovery."
- Enterprise backup solutions
- Disaster recovery planning

**AWS Backup**
- AWS. "AWS Backup."
  - https://aws.amazon.com/backup/
- Centralized backup service
- Backup policies
- Cross-region backup

### RTO/RPO Calculation

**"The Business Impact Analysis and Risk Assessment" (Rothstein Associates)**
- Rothstein, P. "Business Impact Analysis and Risk Assessment." 2007.
- BIA methodology
- RTO/RPO determination
- Cost analysis

**DRII Professional Practices**
- Disaster Recovery Institute International. "Professional Practices."
  - https://drii.org/
- Business continuity standards
- Recovery planning
- Professional certifications

### Geographic Redundancy

**"Multi-Site High Availability Design" (Cisco)**
- Cisco. "Multi-Site High Availability Design Guide."
- Geographic distribution patterns
- Active-active vs active-passive
- WAN considerations

**DNS-Based Global Load Balancing**
- AWS Route 53 Traffic Management
  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html
- Health checks and failover
- Latency-based routing
- Geolocation routing

### Testing and Validation

**"Disaster Recovery Testing" (SANS Institute)**
- SANS Institute. "Disaster Recovery Testing Best Practices."
- Testing methodologies
- Tabletop exercises
- Full-scale drills

**NIST SP 800-84 - Test, Training, and Exercise Programs**
- NIST. "Guide to Test, Training, and Exercise Programs for IT Plans and Capabilities." September 2006.
  - https://csrc.nist.gov/publications/detail/sp/800-84/final
- Exercise design and execution
- Evaluation criteria
- Improvement process

### Recovery Procedures

**"IT Disaster Recovery Planning For Dummies"**
- Snedaker, S. "IT Disaster Recovery Planning For Dummies." Wiley, 2008.
- Practical recovery planning
- Step-by-step procedures
- Common pitfalls

**ITIL Service Design - Availability Management**
- AXELOS. "ITIL 4: Service Design."
- Availability management practices
- Service continuity
- Capacity planning

### Compliance Requirements

**PCI DSS - Requirement 12.10**
- PCI Security Standards Council. "PCI DSS v4.0 - Requirement 12.10: Incident Response."
- Incident response plan requirements
- Business continuity planning
- Testing requirements

**FFIEC Business Continuity Planning**
- Federal Financial Institutions Examination Council. "Business Continuity Planning IT Examination Handbook."
  - https://ithandbook.ffiec.gov/
- Financial sector BCP requirements
- Testing and maintenance
- Third-party dependencies

**SOC 2 - Availability Criteria**
- AICPA. "SOC 2 - Trust Services Criteria."
- System availability commitments
- Recovery procedures
- Change management

### Network Resilience

**BGP Best Practices for Redundancy**
- IETF. "BGP Operations and Security." RFC 7454.
  - https://tools.ietf.org/html/rfc7454
- Multi-homing strategies
- Prefix filtering
- Route diversity

**MPLS VPN for HA**
- RFC 4364. "BGP/MPLS IP Virtual Private Networks (VPNs)."
  - https://tools.ietf.org/html/rfc4364
- VPN redundancy
- Fast reroute
- Backup paths

### Academic Research

**"Availability in Globally Distributed Storage Systems"**
- Ford, D., et al. "Availability in Globally Distributed Storage Systems." OSDI 2010.
- Google's production experience
- Replication strategies
- Failure analysis

**"The Tail at Scale"**
- Dean, J., Barroso, L.A. "The Tail at Scale." Communications of the ACM, 2013.
- Latency variability in distributed systems
- Request hedging
- Tiered service levels

### Industry Standards

**NFPA 1600 - Disaster/Emergency Management**
- National Fire Protection Association. "Standard on Disaster/Emergency Management and Business Continuity Programs." NFPA 1600, 2019.
- Emergency management standards
- Business continuity requirements
- Program management
