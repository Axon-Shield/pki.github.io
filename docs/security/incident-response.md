# Incident Response

## Overview

Despite best efforts at prevention, PKI security incidents will occur. The difference between a manageable incident and a catastrophic breach often comes down to preparation and response speed. Effective incident response for PKI requires specialized procedures beyond general security incident response, because certificate compromise affects trust relationships across entire infrastructures and potentially with customers and partners.

**Core principle**: Hope for the best, but prepare for the worst. Fast, decisive incident response limits damage and demonstrates security maturity to stakeholders and auditors.

## PKI-Specific Incident Response

### Unique Characteristics of PKI Incidents

PKI incidents differ from typical security incidents in several critical ways:

**Trust relationships**: A compromised CA affects not just the directly compromised system but everything that trusts certificates from that CA. This includes internal systems, customer applications, partner integrations, and potentially millions of users.

**Time sensitivity**: Certificate compromise requires immediate action. Every hour of delay is another hour attackers can issue fraudulent certificates or use stolen private keys for impersonation.

**Widespread impact**: A single compromised intermediate CA might affect thousands of certificates across hundreds of services. Revoking and replacing them all requires coordinated

 action across multiple teams and business units.

**Detection difficulty**: Unlike a ransomware attack where systems stop working, certificate compromise may go undetected for extended periods. Attackers can stealthily use compromised keys or issue fraudulent certificates while everything appears normal.

**Recovery complexity**: Recovery isn't as simple as restoring from backup. Compromised certificates must be revoked and replaced, trust chains updated, and potentially entire CA hierarchies rebuilt. This takes time even with good preparation.

## Incident Classification

### PKI Incident Severity Levels

```yaml
severity_levels:
  p0_critical:
    name: "Critical - Root CA Compromise"
    description: "Root CA private key compromised or suspected compromised"
    impact: "Complete PKI failure, all certificates potentially invalid"
    response_time: "Immediate (minutes)"
    escalation: "C-level executives, external auditors, legal"
    examples:
      - Root CA private key stolen
      - HSM tamper detection for root CA
      - Unauthorized access to root CA ceremony
    
  p1_high:
    name: "High - Intermediate CA Compromise"
    description: "Intermediate CA private key compromised"
    impact: "All certificates from this CA must be revoked and replaced"
    response_time: "Within 1 hour"
    escalation: "Security leadership, infrastructure directors"
    examples:
      - Intermediate CA private key exposed
      - Unauthorized certificate issuance detected
      - CA operator credentials stolen
  
  p2_medium:
    name: "Medium - Certificate Compromise"
    description: "Individual certificate private key compromised"
    impact: "Specific service impersonation possible"
    response_time: "Within 4 hours"
    escalation: "Security team, service owners"
    examples:
      - TLS certificate private key leaked
      - Certificate found in public repository
      - Suspected use of stolen certificate
  
  p3_low:
    name: "Low - Process Violation"
    description: "Policy violation or process failure"
    impact: "Potential security weakness, no confirmed compromise"
    response_time: "Within 24 hours"
    escalation: "PKI team, compliance"
    examples:
      - Weak certificate issued against policy
      - Validation procedure bypassed
      - Missing documentation for issuance
```

### Incident Type Taxonomy

```python
class PKIIncidentTypes:
    """
    Classification of PKI security incidents
    """
    
    INCIDENT_TYPES = {
        'key_compromise': {
            'description': 'Private key material accessed by unauthorized party',
            'subtypes': [
                'root_ca_key_theft',
                'intermediate_ca_key_theft',
                'certificate_private_key_theft',
                'key_backup_compromise'
            ],
            'indicators': [
                'Unauthorized certificate issuance',
                'Unexpected certificate usage from unusual IPs',
                'File access logs show key file access',
                'HSM tamper alert',
                'Key found in public location'
            ]
        },
        
        'unauthorized_issuance': {
            'description': 'Certificate issued without proper authorization',
            'subtypes': [
                'fraudulent_domain_validation',
                'insider_abuse',
                'compromised_ra_credentials',
                'validation_bypass'
            ],
            'indicators': [
                'Certificate appears in CT logs unexpectedly',
                'Domain owner didn\'t request certificate',
                'Certificate doesn\'t match internal records',
                'Validation steps missing from audit log'
            ]
        },
        
        'validation_failure': {
            'description': 'Certificate validation procedures failed',
            'subtypes': [
                'domain_validation_bypass',
                'organization_validation_failure',
                'ev_validation_shortcut',
                'policy_violation'
            ],
            'indicators': [
                'Certificate issued for domain without validation',
                'Missing documentation in issuance record',
                'Validation completed too quickly',
                'Automated checks bypassed'
            ]
        },
        
        'availability': {
            'description': 'PKI services unavailable',
            'subtypes': [
                'ca_system_outage',
                'ocsp_responder_down',
                'crl_publication_failure',
                'hsm_failure'
            ],
            'indicators': [
                'Certificate issuance requests failing',
                'Validation checks timing out',
                'Certificate revocation checks failing',
                'HSM not responding'
            ]
        },
        
        'process_failure': {
            'description': 'PKI operational processes not followed',
            'subtypes': [
                'missing_approval',
                'inadequate_validation',
                'improper_revocation',
                'expired_certificates'
            ],
            'indicators': [
                'Audit findings',
                'Compliance violations',
                'Process documentation gaps',
                'Certificate expiry causing outage'
            ]
        }
    }
```

## Detection and Alerting

### Monitoring for Incidents

Effective incident response starts with detection. Organizations need multiple detection mechanisms:

**Certificate Transparency monitoring**: Subscribe to CT log feeds for your domains. Alert immediately on any unexpected certificate issuance. This is your early warning system for fraudulent certificates.

**Audit log monitoring**: Analyze CA audit logs in real-time for anomalies: unusual issuance volumes, off-hours activity, operations by unexpected users, validation failures, authentication failures, or privilege escalations.

**Network monitoring**: Watch for certificates appearing on your network that weren't issued by your CA. Monitor for unexpected certificate changes on services. Track certificate fingerprints and alert on changes.

**Endpoint detection**: Monitor access to private key files and certificate stores. Alert on key file reads by unauthorized processes. Track certificate installation and removal. Monitor HSM access patterns.

**External notification**: Monitor security mailing lists for CA compromise announcements. Watch for reports of your certificates being used maliciously. Subscribe to threat intelligence feeds mentioning your domains.

### Alert Triage

Not every alert indicates an incident requiring full response. Implement triage procedures:

**Automated triage**: Use SIEM rules to correlate alerts, suppress false positives based on known patterns, escalate based on severity and confidence, and enrich alerts with context.

**Human triage**: For ambiguous alerts, investigate quickly (within 15 minutes), gather additional context, make escalation decision, and document triage outcome.

**Escalation criteria**: Escalate immediately for confirmed key compromise, unauthorized certificate in CT logs, HSM tamper alerts, or CA system breaches. Escalate within 1 hour for suspicious activity with incomplete information, policy violations with potential security impact, or repeated validation failures. Standard handling for routine operational issues and false positives.

## Incident Response Phases

### Phase 1: Preparation

Preparation happens before incidents occur. This is the most important phase—poor preparation makes effective response impossible.

**Response team**: Establish a PKI incident response team with defined roles: Incident Commander (coordinates overall response), PKI Security Lead (technical expertise), CA Administrator (system access), Security Operations (investigation), Legal Counsel (compliance and notification), Communications (internal and external), and Business Representatives (service owners).

Define communication channels: dedicated Slack/Teams channel for incidents, conference bridge for major incidents, escalation procedures and contact information, and out-of-band communication for CA compromise.

**Playbooks**: Develop detailed playbooks for each incident type. Each playbook should cover detection indicators, severity assessment, immediate containment actions, investigation steps, eradication procedures, recovery steps, and communication requirements.

**Tools and access**: Ensure the response team has necessary access pre-approved: CA system access (with break-glass procedures), HSM access, audit log access, certificate inventory system, revocation mechanisms, and communication tools.

Maintain incident response toolkits: CA CLI tools for emergency operations, scripts for bulk certificate revocation, CRL/OCSP manipulation tools, forensic analysis tools, and backup/restore utilities.

**Practice**: Conduct tabletop exercises quarterly to walk through incident scenarios. Run full-scale simulations annually with all teams involved. Test specific procedures like emergency revocation and CA failover. Document lessons learned and update playbooks.

### Phase 2: Detection and Analysis

When a potential incident is detected:

**Initial assessment**: Verify the alert is legitimate and not a false positive. Determine initial scope and impact. Classify incident severity. Decide if escalation is needed.

**Evidence collection**: Preserve all evidence immediately. Capture system logs, audit logs, network traffic captures, system memory dumps, and disk images if appropriate. Maintain chain of custody for forensic evidence.

**Scope determination**: Identify what was compromised: which keys, how many certificates, which systems, what time period. Determine how the compromise occurred. Assess potential attacker access and capabilities. Identify all affected services and users.

**Impact analysis**: Assess business impact: which services are affected, how many users or customers impacted, what data might be at risk, and potential financial or reputation impact.

### Phase 3: Containment

Immediate actions to stop ongoing damage:

**Short-term containment**: Isolate compromised systems from the network immediately. Revoke compromised credentials. Disable affected accounts or services. Block attacker access. Begin monitoring for additional compromise.

For confirmed key compromise, emergency revoke the certificate immediately, disable the compromised key, notify all relying parties, publish emergency CRL, and update OCSP responders.

**Long-term containment**: Implement workarounds to maintain service availability. Deploy temporary replacement certificates. Route around compromised infrastructure. Maintain containment while preparing for eradication.

**Evidence preservation**: Create forensic images of affected systems. Save all logs with extended retention. Document all containment actions taken. Maintain access to evidence for investigation.

### Phase 4: Eradication

Remove the threat from the environment:

**Root cause analysis**: Determine exactly how the compromise occurred. Identify the vulnerability exploited. Assess if other systems have the same vulnerability. Document the complete attack chain.

**Threat removal**: Remove malware or backdoors from compromised systems. Patch vulnerabilities that enabled the attack. Secure insecure configurations. Remove attacker access methods. Verify attacker no longer has access.

**System remediation**: Rebuild compromised systems from trusted media. Update all authentication credentials. Rotate all potentially compromised keys. Harden systems against re-compromise. Verify security baseline restored.

### Phase 5: Recovery

Restore normal operations:

**Service restoration**: Deploy replacement certificates. Verify trust chains. Test critical applications. Gradually restore services. Monitor for issues during restoration. Communicate status to stakeholders.

**Verification**: Confirm replacement certificates working correctly. Verify compromised certificates revoked. Test that old certificates no longer accepted. Validate all security controls functioning. Confirm normal operations restored.

**Post-recovery monitoring**: Enhanced monitoring for 30+ days after recovery. Watch for signs of re-compromise. Monitor for use of old certificates. Track relying party adoption of new certificates.

### Phase 6: Post-Incident Activity

Learning from the incident:

**Post-mortem**: Conduct blameless post-mortem within one week. Document detailed timeline of events. Identify what worked well. Identify gaps and failures. Generate action items for improvement.

**Documentation**: Write complete incident report including what happened, impact and scope, response actions taken, lessons learned, and recommendations. Update incident response playbooks based on lessons learned. Share knowledge with broader organization.

**Process improvement**: Implement security improvements to prevent recurrence. Update monitoring to detect similar incidents faster. Improve containment procedures based on experience. Train team on new procedures.

## Incident Scenarios and Response Playbooks

### Scenario 1: Root CA Private Key Compromise

This is the worst-case PKI incident.

**Detection**: HSM tamper alert, unauthorized access to root CA vault, root CA key found in backup that shouldn't exist, or unexpected certificate issuance from root CA.

**Immediate actions** (within 1 hour):
1. Activate critical incident response team, including C-level executives
2. Isolate root CA systems completely (air-gap if necessary)
3. Stop all certificate issuance from affected root
4. Begin forensic evidence collection
5. Notify board, legal counsel, and cyber insurance
6. Prepare public disclosure if required by regulations

**Investigation** (hours 1-24):
1. Determine extent of compromise: when did it occur, what was accessed, how many certificates might be affected
2. Identify all certificates issued from compromised root
3. Assess if any fraudulent certificates were issued
4. Determine if subordinate CA keys also compromised
5. Build complete timeline of compromise

**Containment** (days 1-3):
1. Revoke root CA certificate in all trust stores (if possible and appropriate)
2. Notify all browser vendors and OS vendors
3. Communicate with all customers and partners
4. Deploy new temporary root CA for critical operations
5. Begin mass revocation of certificates from compromised root

**Recovery** (weeks 1-12):
1. Generate new root CA with enhanced security
2. Issue new intermediate CAs
3. Re-issue all affected certificates
4. Update all relying party trust stores
5. Decommission compromised root CA completely

**Long-term** (months 1-6):
1. Enhanced security review of all PKI infrastructure
2. Third-party security audit
3. Process improvements to prevent recurrence
4. Potential reorganization of CA hierarchy
5. Regular progress reporting to leadership

### Scenario 2: TLS Certificate Private Key Leaked

More common scenario with more limited scope.

**Detection**: Private key found in public GitHub repository, key file discovered in backup with wrong permissions, CT log shows same certificate serial number used with different keys, or certificate observed in use from unexpected IP addresses.

**Immediate actions** (within 1 hour):
1. Revoke the compromised certificate immediately
2. Remove the exposed key from wherever it was found
3. Notify service owner
4. Generate replacement certificate with new key
5. Begin deployment of replacement

**Investigation** (hours 1-6):
1. Determine how key was exposed
2. Check if other keys exposed the same way
3. Review audit logs for unauthorized usage
4. Assess if key was actually used by attackers
5. Identify all systems using this certificate

**Containment and recovery** (hours 6-24):
1. Deploy replacement certificate to all affected systems
2. Verify old certificate no longer in use
3. Confirm revocation effective via OCSP/CRL
4. Monitor for attempted use of revoked certificate
5. Update deployment procedures to prevent recurrence

**Post-incident**:
1. Document how exposure occurred
2. Implement controls to prevent similar exposure
3. Review other certificates for similar issues
4. Training for developers on secure key handling
5. Update git pre-commit hooks to catch secrets

### Scenario 3: Unauthorized Certificate Issuance

Certificate issued without proper authorization.

**Detection**: Certificate appears in CT logs that wasn't requested, domain owner reports certificate they didn't issue, certificate doesn't appear in internal issuance records, or validation documentation missing.

**Immediate actions** (within 2 hours):
1. Determine if issuance was malicious or error
2. Revoke the unauthorized certificate
3. Verify domain owner awareness
4. Check for other unauthorized issuances
5. Secure CA credentials if compromised

**Investigation** (hours 2-12):
1. Review CA audit logs for issuance
2. Identify who/what issued the certificate
3. Determine how validation was bypassed
4. Check if CA credentials were compromised
5. Assess insider threat possibility

**Remediation** (hours 12-48):
1. Fix validation bypass vulnerability
2. Rotate CA credentials if compromised
3. Enhanced monitoring for similar issues
4. Review all recent issuances for anomalies
5. Strengthen validation procedures

**Post-incident**:
1. Update issuance validation procedures
2. Implement additional authorization checks
3. Enhance CT monitoring
4. Training for CA operators
5. Consider external audit of CA processes

## Communication During Incidents

### Internal Communication

**Stakeholder updates**: Provide regular status updates to leadership (every 2 hours for critical incidents, every 4 hours for high severity), technical teams (continuous updates during active response), business units (when services are affected), and legal and compliance (throughout incident lifecycle).

**Communication format**: Use standard templates for incident updates including current status, actions taken, actions in progress, next steps, estimated time to resolution, and impact assessment.

**Escalation communication**: Clearly communicate when escalating: severity level, business impact, resources needed, decisions required, and timeline for escalation path.

### External Communication

**Customer communication**: For incidents affecting customers, communicate quickly and transparently. Explain what happened (at appropriate detail level), what the impact is, what actions customers should take, what you're doing to fix it, and when resolution is expected.

**Regulatory notification**: Understand notification requirements: data breach laws (vary by jurisdiction), industry-specific requirements (PCI-DSS, HIPAA, etc.), CA/Browser Forum requirements for public CAs, and contractual obligations.

Notify within required timeframes: preliminary notification within hours, detailed notification within days, and final report within weeks.

**Public disclosure**: For incidents involving public CA compromise or significant customer impact, prepare public statements coordinated with legal, public relations, and executive leadership. Be transparent but don't provide attackers with operational details. Focus on customer impact and remediation.

**Partner notification**: Notify partners who depend on your certificates promptly. Provide technical details partners need for their own response. Coordinate if partner systems also affected. Maintain communication throughout incident.

## Tools and Automation

### Incident Response Automation

```python
class PKIIncidentResponse:
    """
    Automated incident response actions for PKI
    """
    
    async def handle_compromised_certificate(self, 
                                            cert: Certificate,
                                            severity: str) -> ResponseResult:
        """
        Automated response to certificate compromise
        """
        result = ResponseResult()
        
        # Step 1: Immediate revocation
        result.add_action("Revoking certificate")
        revocation = await self.emergency_revoke(
            cert,
            reason='keyCompromise',
            revocation_date=datetime.now()
        )
        
        # Step 2: Notify stakeholders
        result.add_action("Notifying stakeholders")
        await self.notify_certificate_compromise(cert, severity)
        
        # Step 3: Generate replacement
        result.add_action("Generating replacement certificate")
        replacement = await self.issue_replacement_certificate(cert)
        
        # Step 4: Deploy replacement
        result.add_action("Deploying replacement")
        deployment = await self.emergency_deploy(replacement)
        
        # Step 5: Verify
        result.add_action("Verifying remediation")
        verification = await self.verify_compromise_remediation(
            original=cert,
            replacement=replacement
        )
        
        return result
```

### Forensic Tools

Maintain tools for incident investigation: certificate parsing and analysis tools, CT log querying scripts, audit log analysis scripts, network traffic analysis (Wireshark, tcpdump), memory forensics tools, and disk forensics tools.

## Post-Incident Review

Every incident should result in documented learnings and improvements.

**Post-mortem template**:
- Incident summary (what happened, when, impact)
- Timeline of events (detailed chronology)
- Root cause analysis (how it happened)
- Response evaluation (what worked, what didn't)
- Lessons learned
- Action items (with owners and due dates)
- Playbook updates needed

**Continuous improvement**: Track incident metrics (time to detect, time to contain, time to recover), identify recurring issues, measure improvement over time, and share lessons across organization.

## Conclusion

PKI incident response requires specialized knowledge, advance preparation, and decisive action. Organizations that invest in preparation—developing playbooks, training teams, conducting exercises, and maintaining tooling—respond to incidents faster and more effectively, limiting damage and demonstrating security maturity.

The key to effective incident response is not avoiding all incidents (impossible), but responding so well that incidents have minimal impact, recovery is swift, and the organization emerges stronger with improved security posture.

Remember: It's not if an incident will occur, but when. Your preparation today determines your success tomorrow.
