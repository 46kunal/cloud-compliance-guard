# PolicyGuard — Automated Cloud Compliance & Governance Auditing Platform

**PolicyGuard** is an automated cloud security and governance platform designed to continuously audit AWS environments for compliance violations, calculate real-time risk scores mapped to regulatory frameworks, auto-remediate critical misconfigurations, and maintain a tamper-evident audit log.

---

## 1. Project Overview

PolicyGuard provides an end-to-end security posture management workflow for cloud infrastructure:

* **Continuous Auditing**: Scans AWS resources (S3, IAM, EC2, KMS) for security misconfigurations such as public S3 buckets, over-permissioned IAM wildcard policies, missing encryption at rest, and un-enforced Multi-Factor Authentication (MFA).
* **Framework Alignment**: Maps detected violations to a two-tier compliance framework combining **DPDP Act 2023** (Privacy Tier) and **CIS AWS Foundations Benchmark** (Security Hygiene Tier).
* **Automated Remediation**: Safely corrects high-risk misconfigurations (e.g., closing public bucket access or revoking dangerous permissions) using configurable safety controls.
* **Tamper-Evident Audit Trail**: Records every detection, risk score update, and remediation action in a cryptographic, hash-chained log with optional blockchain anchoring.
* **Real-time Monitoring**: Visualizes compliance scores, active violations, and audit history via an interactive Flask dashboard.

---

## 2. Architecture

The PolicyGuard pipeline follows a event-driven serverless architecture:

```text
[ AWS Resources ] (EC2, S3, IAM, KMS)
        │
        ▼
[ AWS Config & CloudTrail ] (Continuous Monitoring & Event Capture)
        │
        ▼
[ Lambda Rule Engine ] (Policy-as-Code Rule Evaluation)
        │
        ▼
[ Risk Classifier ] (Severity Scoring & Regulatory Mapping)
        │
        ├──────────────────────────────────────┐
        ▼                                      ▼
[ Auto-Remediation Lambda ]          [ Audit Logger Lambda ]
(Executes Fixes via Allowlist)       (Cryptographic Hash-Chained Log)
        │                                      │
        └──────────────────┬───────────────────┘
                           ▼
             [ Compliance Dashboard ]
             (Flask UI, Live Metrics & Audit Trail)
```

1. **Continuous Monitoring**: AWS Config and CloudTrail capture configuration changes across monitored AWS resources.
2. **Rule Engine**: AWS Config triggers the `rule_engine` Lambda function to execute policy-as-code checks.
3. **Risk Classification**: The `risk_classifier` Lambda evaluates severity, assigns risk scores, and tags violations with regulatory references.
4. **Dual Pipeline Execution**:
   * **Auto-Remediation**: Triggers automated corrective actions for allowed high-severity misconfigurations.
   * **Audit Logging**: Appends an entry into a cryptographic hash-chained audit log stored in DynamoDB (and optionally anchored to a blockchain contract).
5. **Visualization**: The Flask web application renders real-time compliance metrics, active violation alerts, and the immutable audit log.

---

## 3. Folder Structure

```text
policyguard/
├── README.md                          # Project documentation and setup guide
├── .gitignore                         # Git exclusion rules for Python, AWS, and Node.js
├── requirements.txt                   # Python package dependencies
├── infra/                             # AWS IAM policies, Config rules, and infra notes
├── lambdas/                           # Serverless Python functions for scanning, scoring, remediation, & logging
├── dashboard/                         # Flask-based web application for compliance visualizer
├── db/                                # Database schemas and seed scripts
├── blockchain/                        # Smart contracts and Hardhat scripts for audit anchoring
├── tests/                             # Unit and integration test suite
├── demo/                              # Violation simulation scripts and demo walkthroughs
└── docs/                              # Architecture specs, compliance mappings, and reports
```

* **[infra/](file:///d:/policyguard-cc/policyguard/infra)**: AWS IAM policy JSON files, AWS Config rule definitions, and setup notes.
* **[lambdas/](file:///d:/policyguard-cc/policyguard/lambdas)**: Core serverless Python functions (`rule_engine`, `risk_classifier`, `remediation`, `audit_logger`).
* **[dashboard/](file:///d:/policyguard-cc/policyguard/dashboard)**: Flask web dashboard routes, HTML templates, CSS, and JavaScript interface files.
* **[db/](file:///d:/policyguard-cc/policyguard/db)**: Database schemas and sample data generation scripts.
* **[blockchain/](file:///d:/policyguard-cc/policyguard/blockchain)**: Solidity contracts (`AuditAnchor.sol`) and Hardhat deployment scripts.
* **[tests/](file:///d:/policyguard-cc/policyguard/tests)**: Pytest test suite covering rule evaluations, risk scoring, remediation safety, and audit logs.
* **[demo/](file:///d:/policyguard-cc/policyguard/demo)**: Violation simulation script (`simulate_violation.py`) and step-by-step demonstration notes.
* **[docs/](file:///d:/policyguard-cc/policyguard/docs)**: Extended architectural documentation and regulatory compliance matrix.

---

## 4. Tech Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Cloud Services** | AWS Config, CloudTrail | Infrastructure monitoring & event capture |
| **Identity & Access** | AWS IAM, IAM Access Analyzer | Access evaluation & permission auditing |
| **Security & Encryption** | AWS KMS, AWS Security Hub | Encryption key management & security posture |
| **Compute & Orchestration** | AWS Lambda, EventBridge | Event-driven serverless pipeline execution |
| **Database** | Amazon DynamoDB | NoSQL storage for state, rules, and audit logs |
| **Backend & Web App** | Python 3.x, Flask | Rule engine logic and web management UI |
| **Frontend** | HTML5, Vanilla CSS, JavaScript | Interactive compliance dashboard |
| **Testing** | Pytest | Automated test runner |
| **Blockchain (Optional)**| Solidity, Hardhat, Web3.py | Immutable audit anchoring smart contracts |

---

## 5. Setup Instructions

### Prerequisites
* Python 3.10+ installed
* AWS CLI configured with active credentials (`aws configure`)
* Node.js & npm (optional, required only for blockchain anchoring)

### Step 1: Clone and Install Dependencies
```bash
git clone https://github.com/your-repo/policyguard.git
cd policyguard
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Deploy Lambda Functions
Deploy the serverless packages from the `lambdas/` directory to AWS Lambda:
```bash
# Example AWS CLI deployment for rule engine
aws lambda create-function \
  --function-name PolicyGuard-RuleEngine \
  --runtime python3.11 \
  --handler lambdas.rule_engine.handler.lambda_handler \
  --role arn:aws:iam::123456789012:role/PolicyGuardLambdaRole \
  --zip-file fileb://lambdas/rule_engine.zip
```

### Step 3: Register AWS Config Custom Rules
Link the `rule_engine` Lambda function to AWS Config using the JSON definition in `infra/config/config-rules.json`:
```bash
aws configservice put-config-rule --config-rule file://infra/config/config-rules.json
```

### Step 4: Configure EventBridge Pipeline Triggers
Set up AWS EventBridge rules to link AWS Config compliance evaluation events to the `risk_classifier`, `remediation`, and `audit_logger` Lambda handlers.

### Step 5: Launch Local Compliance Dashboard
Start the Flask web dashboard locally:
```bash
python dashboard/app.py
```
Open your browser and navigate to `http://127.0.0.1:5000`.

### Step 6: Execute Violation Simulation Demo
To verify the auditing pipeline, run the simulation script to trigger a test compliance violation:
```bash
python demo/simulate_violation.py
```

---

## 6. Compliance Frameworks Referenced

PolicyGuard maps technical cloud violations to a two-tier compliance framework model:

* **Tier 1 — Privacy (DPDP Act 2023 Sec. 8(5) & GDPR Art. 32)**: Mandates reasonable security safeguards and access controls for resources tagged as processing personal data (`handles_personal_data=true`).
* **Tier 2 — Security Hygiene (CIS AWS Foundations Benchmark)**: Industry-standard security benchmarks governing public access restrictions, encryption at rest, administrative port security, and IAM least privilege.

> For a complete mapping of all PolicyGuard rules to regulatory controls, refer to [`docs/compliance_mapping.md`](file:///d:/policyguard-cc/policyguard/docs/compliance_mapping.md).

---

## 7. Safety Notes

* **Safety Controls**: The auto-remediation module includes an explicit **dry-run mode** (`lambdas/remediation/safety/dry_run.py`) and an **allowlist configuration** (`lambdas/remediation/safety/allowlist.json`) to prevent unintended modification of critical production resources.
* **Scope Isolation**: All automated testing and violation simulations must be executed exclusively within dedicated sandbox AWS accounts and owned test resources.

---

## 8. License / Academic Note

> **Note**: PolicyGuard is a student project built for **[Course Name]** and is intended solely for educational and demonstration purposes. It is not intended for production deployment.
