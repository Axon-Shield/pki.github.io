This plan establishes a structured approach for maintaining a private Wikipedia-style knowledge base on Public Key Infrastructure and certificate management. The system is designed to enable LLM-driven updates while preventing unnecessary churn, maintaining high-quality references, and providing practical value.

## Core Principles

### 1. Update Discipline
- **Semantic changes only**: Update content when meaning or accuracy improves, not for stylistic preferences
- **Evidence-based**: All significant claims require citations from authoritative sources
- **Incremental improvement**: Small, targeted updates rather than wholesale rewrites
- **Change justification**: Every update must have a clear reason logged in metadata

### 2. Quality Standards
- **Primary sources preferred**: RFC standards, vendor documentation, academic papers, vendor security advisories
- **Recency markers**: Date-stamp time-sensitive information (e.g., "As of 2024, the recommended...")
- **Cross-reference integrity**: Automated checking that internal links remain valid
- **Practical utility**: Every page must include actionable guidance or decision-making support

---

## Site Structure & Taxonomy

### Level 1: Core Domains

```
/foundations/          # Fundamental concepts
/standards/            # Protocols, RFCs, specifications  
/implementation/       # Technical how-to and architecture
/operations/           # Lifecycle management, automation
/security/             # Threats, defenses, incident response
/vendors/              # Product comparisons, capabilities
/patterns/             # Architecture patterns, case studies
/troubleshooting/      # Common problems and solutions
/glossary/             # Terms and definitions
```

### Level 2: Example Page Hierarchy

```
/foundations/
  ├── what-is-pki.md
  ├── certificate-anatomy.md
  ├── trust-models.md
  ├── cryptographic-primitives.md
  └── public-private-key-pairs.md

/standards/
  ├── x509-standard.md
  ├── tls-protocol.md
  ├── ocsp-and-crl.md
  ├── pkcs-standards.md
  └── certificate-transparency.md

/implementation/
  ├── ca-architecture.md
  ├── hsm-integration.md
  ├── certificate-issuance-workflows.md
  ├── acme-protocol-implementation.md
  └── multi-cloud-pki.md

/operations/
  ├── certificate-lifecycle-management.md
  ├── renewal-automation.md
  ├── inventory-and-discovery.md
  ├── monitoring-and-alerting.md
  └── certificate-rotation-strategies.md

/security/
  ├── private-key-protection.md
  ├── ca-compromise-scenarios.md
  ├── certificate-pinning.md
  ├── common-vulnerabilities.md
  └── incident-response-playbooks.md

/vendors/
  ├── venafi-platform.md
  ├── digicert-certcentral.md
  ├── keyfactor-command.md
  ├── hashicorp-vault-pki.md
  └── vendor-comparison-matrix.md

/patterns/
  ├── zero-trust-architecture.md
  ├── service-mesh-certificates.md
  ├── mutual-tls-patterns.md
  ├── certificate-as-code.md
  └── case-study-financial-services.md

/troubleshooting/
  ├── expired-certificate-outages.md
  ├── chain-validation-errors.md
  ├── performance-bottlenecks.md
  └── common-misconfigurations.md
```

---

## Page Template Structure

### Standard Page Format

```markdown
---
title: [Page Title]
category: [foundations|standards|implementation|operations|security|vendors|patterns|troubleshooting]
last_updated: YYYY-MM-DD
last_reviewed: YYYY-MM-DD
version: X.Y
status: [stable|draft|needs-review|deprecated]
tags: [tag1, tag2, tag3]
---

# [Page Title]

> **TL;DR**: [2-3 sentence executive summary for busy readers]

## Overview

[3-4 paragraphs introducing the topic, its importance, and what this page covers]

**Related Pages**: [[link-to-page-1]], [[link-to-page-2]], [[link-to-page-3]]

## Key Concepts

[Core information organized in logical sections]

### [Subsection Title]

[Content with inline citations]

According to RFC 5280[^1], certificate extensions provide...

## Practical Guidance

### When to Use This Approach

- Scenario 1: [Specific use case]
- Scenario 2: [Another use case]

### Implementation Steps

1. **Step 1**: [Action with reasoning]
   - Consideration: [Important point]
   - Pitfall: [Common mistake to avoid]

2. **Step 2**: [Next action]
   - Example: [Concrete example]

### Decision Framework

| Factor | Option A | Option B | Recommendation |
|--------|----------|----------|----------------|
| Performance | [pros/cons] | [pros/cons] | [guidance] |
| Security | [assessment] | [assessment] | [guidance] |

## Common Pitfalls

- **Pitfall 1**: [What goes wrong]
  - **Why it happens**: [Root cause]
  - **How to avoid**: [Prevention strategy]
  - **How to fix**: [Remediation]

## Security Considerations

[Security-specific guidance for this topic]

- Threat: [Specific threat]
  - Impact: [What could happen]
  - Mitigation: [How to defend]

## Real-World Examples

### Case Study: [Company/Scenario]

[Brief description of implementation with outcomes]

**Key Takeaway**: [Lesson learned]

## Further Reading

### Essential Resources
- [RFC/Standard Title](URL) - [One sentence describing why it's essential]
- [Vendor Documentation](URL) - [What it covers]

### Advanced Topics
- [[Internal link to related deep-dive]]
- [External resource](URL)

## References

[^1]: Full citation: Cooper, D., et al. "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile." RFC 5280, May 2008. https://www.rfc-editor.org/rfc/rfc5280
[^2]: [Additional citation]

## Change History

| Date | Version | Changes | Reason |
|------|---------|---------|--------|
| 2024-01-15 | 1.1 | Added ACME protocol section | New protocol adoption increasing |
| 2023-11-03 | 1.0 | Initial creation | - |

---

**Quality Checks**: 






- [ ] All claims cited from authoritative sources
- [ ] Cross-references validated
- [ ] Practical guidance included
- [ ] Examples are current and relevant
- [ ] Security considerations addressed
```

---

## LLM Update Instructions

### Update Triggers (When to Modify Pages)

The LLM should update pages when:

1. **Factual Corrections**
   - Error in technical details discovered
   - RFC or standard misinterpreted
   - Broken or outdated external links

2. **New Authoritative Information**
   - New RFC published affecting the topic
   - Major vendor releases changing best practices
   - Security vulnerabilities disclosed
   - Industry standards updated (CA/B Forum, NIST)

3. **Significant Industry Events**
   - Major certificate-related outages with public postmortems
   - New attack techniques published in academic papers
   - Regulatory changes (eIDAS, WebTrust requirements)

4. **Gap Filling**
   - Missing cross-references identified
   - Practical guidance section empty or weak
   - No examples provided for complex topics
   - Missing security considerations

5. **Staleness Indicators**
   - Last_reviewed date > 6 months ago
   - References to deprecated protocols without context
   - "Current" recommendations from >2 years ago

### Update Restrictions (When NOT to Modify)

The LLM should NOT update pages for:

1. **Stylistic preferences** - Don't rewrite for tone unless actively confusing
2. **Synonym swapping** - "certificate" vs "cert" is fine, don't normalize
3. **Restructuring working content** - If organization is clear, leave it
4. **Adding marginal examples** - Only add examples that significantly clarify
5. **Expanding complete sections** - Don't pad content that's already comprehensive
6. **Citation format changes** - Unless switching to a better primary source
7. **Rewording clear explanations** - If it's accurate and clear, preserve it

### Update Process

#### Step 1: Pre-Update Assessment

```
Before modifying any page, the LLM must:

1. Read the entire current page
2. Check last_updated and last_reviewed dates
3. Review change history to understand edit patterns
4. Identify specific sentences/sections that need changes
5. Verify authoritative sources for new information
6. Check that proposed changes meet update triggers above
```

#### Step 2: Minimal Diff Approach

```
When updating:

1. Change ONLY the specific sentences/paragraphs that need correction
2. Preserve existing formatting, headers, and structure
3. Keep existing citations unless replacing with better sources
4. Add new citations inline: [^N] (incrementing from last number)
5. Append new references to References section
6. Do not reorder sections unless critically necessary
```

#### Step 3: Documentation

```
After each update:

1. Update the version number:
   - Major version (X.0) for substantial content additions
   - Minor version (X.Y) for corrections and small additions

2. Add entry to Change History table:
   | 2024-11-08 | 1.3 | Fixed OCSP validation flow, added ref to RFC 6960 | Inaccurate description of nonce handling |

3. Update last_updated field in frontmatter

4. If changes are substantial, set status to "needs-review"
```

#### Step 4: Cross-Reference Maintenance

```
When adding/removing content:

1. Search wiki for pages linking to current page
2. Update those pages if context changed significantly
3. Add new cross-references where relevant
4. Validate all [[internal-links]] resolve correctly
```

### Monthly Review Process

Once per month, the LLM should:

1. **Scan for stale pages** (last_reviewed > 6 months)
2. **Check for new relevant RFCs** (search IETF database)
3. **Review vendor changelog pages** for major PKI product updates
4. **Search for recent security advisories** affecting PKI
5. **Identify missing interconnections** between related pages
6. **Generate maintenance report** listing:
   - Pages updated this month with change summary
   - Pages flagged for human review (status: needs-review)
   - Missing content gaps identified
   - Broken external links found

---

## Reference Management

### Source Hierarchy (Most Authoritative to Least)

1. **Standards Bodies**
   - IETF RFCs ([Rfc-editor](https://www.rfc-editor.org/))
   - CA/Browser Forum guidelines ([Cabforum](https://cabforum.org/))
   - NIST publications ([Nist](https://csrc.nist.gov/))
   - ISO/IEC standards

2. **Vendor Primary Documentation**
   - Official product documentation
   - Security advisories and bulletins
   - Engineering blogs (when describing their own systems)

3. **Academic Research**
   - Peer-reviewed papers on cryptography/PKI
   - Conference proceedings (ACM CCS, USENIX Security, etc.)

4. **Industry Analyses**
   - Professional security researchers
   - Established PKI vendors (Sectigo, DigiCert technical blogs)
   - Reputable security publications (e.g., SANS, CIS)

5. **Avoid/Use Sparingly**
   - General blog posts without citations
   - Stack Overflow (can link for specific technical issues)
   - Marketing materials
   - Wikipedia (use its citations instead)

### Citation Format

Use footnote-style citations with full references at page bottom:

```markdown
The CA/Browser Forum's Baseline Requirements[^1] specify that...

## References

[^1]: CA/Browser Forum, "Baseline Requirements for the Issuance and Management of Publicly-Trusted Certificates," Version 1.8.5, March 2024. https://cabforum.org/baseline-requirements-documents/
```

### External Link Maintenance

- **Check quarterly**: All external URLs for 404s
- **Archive important sources**: Use web.archive.org for critical references
- **Prefer permalinks**: RFC URLs, DOI links for papers, specific version docs
- **Note access dates**: For web resources that may change

---

## Cross-Reference Strategy

### Link Density Guidelines

- **Minimum**: Every page should link to 3-5 related pages
- **Optimal**: 8-12 internal links for substantial pages
- **Context**: Only link when it genuinely aids understanding

### Link Patterns

```markdown
# Good Cross-Referencing

When implementing [[certificate-lifecycle-management]], you'll need to 
consider [[renewal-automation]] strategies and [[monitoring-and-alerting]] 
to prevent outages.

For the cryptographic details, see [[cryptographic-primitives]].

# Poor Cross-Referencing (Don't do this)

Certificates are important. See [[what-is-pki]], [[certificate-anatomy]], 
[[trust-models]], [[x509-standard]], [[tls-protocol]], [[ca-architecture]],
and [[certificate-lifecycle-management]] for more information.
```

### Bidirectional Linking

When creating link from Page A → Page B:
1. Consider if Page B should also link back to Page A
2. Add to "Related Pages" section if bidirectional relationship exists

### Link Maintenance Queries

LLM should regularly search for:




- Pages with <3 internal links (potential orphans)
- Pages with >20 links (may be too dense)
- Broken [[wiki-links]]
- Topics mentioned but not linked

---

## Content Quality Metrics

### Self-Assessment Checklist (for LLM to run)

Before marking a page as "stable", verify:

```yaml
Completeness:
  - Has TL;DR summary: [ ]
  - Has overview section: [ ]
  - Has practical guidance: [ ]
  - Has security considerations: [ ]
  - Has at least 1 example: [ ]
  - Has 3+ authoritative citations: [ ]

Clarity:
  - Technical terms defined on first use: [ ]
  - Assumptions stated explicitly: [ ]
  - Steps in logical order: [ ]
  - Jargon minimized or explained: [ ]

Utility:
  - Actionable recommendations provided: [ ]
  - Common pitfalls identified: [ ]
  - Decision framework included (where applicable): [ ]
  - Real-world examples given: [ ]

Connections:
  - 3+ internal cross-references: [ ]
  - Related pages section populated: [ ]
  - Glossary terms linked: [ ]

Maintenance:
  - All external links working: [ ]
  - Time-sensitive info dated: [ ]
  - Version history recorded: [ ]
  - Status field accurate: [ ]
```

## Success Metrics

Track these to ensure the wiki provides value:

1. **Content Coverage**
   - Total pages created
   - Pages per category
   - Glossary term count

2. **Content Quality**
   - Pages marked "stable" vs "draft"
   - Average citations per page
   - Average internal links per page
   - Pages with practical guidance %

3. **Maintenance Health**
   - Average page age (last_reviewed)
   - % pages reviewed in last 90 days
   - Broken link count
   - Pages flagged for human review

4. **Update Efficiency**
   - Changes per month
   - Lines changed per update (aim: small)
   - Rollback frequency (aim: low)
   - Time from industry event to wiki update


## Appendix: Glossary Page Template

```markdown
---
title: Glossary
category: reference
last_updated: YYYY-MM-DD
---

# PKI & Certificate Management Glossary

## A

### ACME (Automated Certificate Management Environment)
**Definition**: A protocol for automating certificate issuance and renewal between certificate authorities and web servers.

**Context**: Developed by Let's Encrypt, now IETF standard RFC 8555. Widely used for TLS certificate automation.

**Related**: [[acme-protocol-implementation]], [[renewal-automation]]

**Reference**: [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)

---

### Authority Information Access (AIA)
**Definition**: X.509 certificate extension indicating where to obtain information about the issuing CA.

**Context**: Contains URLs for CA certificates (caIssuers) and OCSP responders. Critical for certificate chain building.

**Related**: [[certificate-anatomy]], [[chain-validation-errors]]

**Reference**: [RFC 5280 Section 4.2.2.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1)

## B

[Continue alphabetically...]
```
