# Cloud Compliance Guard

## Automated Cloud Compliance & Governance Auditing Platform

**CC CP Review**

### Project Team

| Name | Roll No. | PRN |
|---|---:|---:|
| Kunal Yawatkar | 60 | 124 |
| Ankit Vyavahare | 54 | 124 |
| Sai Shidruk | 17 | 12414406 |

**Project Guide:** Prof. Pawan Wawage

---

# Slide 1 — Title Slide

## Cloud Compliance Guard

**Automated Cloud Compliance & Governance Auditing Platform**

**CC CP Review**

### Project Team

- Kunal Yawatkar — Roll No. 60 — PRN 124
- Ankit Vyavahare — Roll No. 54 — PRN 124
- Sai Shidruk — Roll No. 17 — PRN 12414406

**Project Guide:** Prof. Pawan Wawage

---

# Slide 2 — Introduction & Problem Statement

## Cloud Adoption is Accelerating

Cloud adoption is increasing, making cloud environments larger and more complex.

### Key Problems

- Cloud configurations and policies change frequently, making continuous monitoring difficult.
- Manual compliance monitoring is slow and error-prone.
- Violations may be detected late, increasing security and compliance risks.
- A growing cloud environment requires continuous monitoring and governance.

### Manual Monitoring Approach

**Manual Monitoring → Delayed Detection → Higher Risk**

### Automated Monitoring Approach

**Automated Monitoring → Violation Detection → Risk Assessment → Remediation → Audit Recording**

### Proposed Solution

**Cloud Compliance Guard** automates:

1. Monitoring
2. Violation detection
3. Risk assessment
4. Remediation
5. Audit recording

---

# Slide 3 — Technical Architecture

## Event-Driven Serverless Architecture

An event-driven, serverless architecture for end-to-end cloud compliance monitoring and automation on AWS.

### Main Architecture Flow

**AWS Cloud Resources → AWS Config → Amazon EventBridge → Lambda-Based Compliance Pipeline → Compliance Database → Flask Dashboard**

### AWS Cloud Resources

- AWS accounts
- AWS services
- Cloud configurations

### AWS Config

- Continuously records and evaluates resource configurations.

### Amazon EventBridge

- Routes configuration changes and events.

## Lambda-Based Compliance Pipeline

### 1. Rule Engine Lambda

- Evaluates compliance rules.
- Detects violations.

### 2. Risk Classifier Lambda

- Assesses risk severity.
- Prioritizes issues.

### 3. Remediator Lambda

- Executes automated remediation for supported issues.

### 4. Audit Logger Lambda

- Logs events.
- Maintains the audit trail.

### Compliance Database

Stores:

- Compliance data
- Compliance results
- Audit logs

### Flask Dashboard

Provides:

- Visibility
- Reporting
- Insights

## Supporting Services & Tools

### AWS CloudTrail

- Provides API activity logging and audit records.

### Blockchain Anchoring

- Provides immutable storage for audit integrity.

### Python

- Core development language for Lambda functions and tools.

### AWS CLI

- Enables automation, scripting, and integrations.

---

# Slide 4 — System Workflow & Implementation

## System Workflow

The system follows a six-stage workflow:

### 1. Monitor

**AWS Config** evaluates resources with defined rules.

### 2. Detect

The **Rule Engine** identifies compliance violations.

### 3. Classify

The **Risk Classifier** assesses the severity of detected issues.

### 4. Remediate

The **Remediation Lambda** acts on supported issues.

### 5. Audit

The **Audit Logger** records relevant details.

### 6. Visualize

The **Flask Dashboard** displays system status and audit information.

## Implementation Highlights

- Event-driven architecture
- Serverless Lambda functions
- Custom AWS Config rules
- EventBridge triggers
- Python backend
- Audit logging
- Optional blockchain integrity check

---

# Slide 5 — Case Study & Real-World Applications

## Financial Services

- Continuous configuration monitoring
- Regulatory compliance
- Audit trail

## Healthcare

- Sensitive data protection
- Access-control compliance

## E-Commerce

- Secure infrastructure
- Automated misconfiguration detection

## Enterprise IT

- Centralized governance
- Automated policy enforcement

### Key Point

Automation is critical for large cloud environments that require continuous compliance demonstration and audit readiness.

### Scalability

The platform is built with AWS services with documented capabilities to help organizations achieve and maintain cloud compliance at scale.

---

# Slide 6 — Challenges, Security Risks & Limitations

## Security Risks

- Incorrect IAM permissions
- Misconfigurations
- Unauthorized changes
- False positives / negatives
- Risks of automation
- Audit log protection

## Technical Challenges

- Scaling for large environments
- Multiple AWS services
- Complex policies
- Event dependencies
- Audit accuracy

## Limitations

- AWS focus
- Remediation scope is limited
- Compliance rules need updates
- Dashboard depends on data availability

---

# Slide 7 — Future Scope & Conclusion

## Future Scope

- Multi-cloud support
- Additional compliance frameworks
- AI risk prediction & anomaly detection
- Advanced remediation & SIEM integration
- Enhanced blockchain audit verification

## Conclusion

- Automates cloud compliance monitoring and auditing.
- Combines risk assessment, remediation, and audit logging.
- Uses an event-driven cloud architecture to improve governance.
- Provides a foundation for stronger and scalable cloud security governance.

---

# Slide 8 — References

## AWS Official Documentation

- AWS Config User Guide
- AWS Lambda Developer Guide
- Amazon EventBridge User Guide
- AWS CloudTrail User Guide
- AWS Security – Overview

## Research Papers

1. A. Paul et al., **“Amazon Web Services Cloud Compliance Automation with Open Policy Agent,”** IEEE ICOECA, 2024.
2. Y. Martseniuk et al., **“Automated Conformity Verification Concept for Cloud Security,”** CPITS, CEUR Workshop Proceedings, 2024.
3. P. Upadhyaya et al., **“MCP Agents for Automated Cloud Compliance and Governance,”** IJRITCC, 2025.

## Project Repository

https://github.com/46kunal/cloud-compliance-guard
