# Cloud Attack Module - Testing & Validation Guide

## Test Framework

### Unit Tests

Test each attack vector in isolation:

```bash
# AWS IMDS v1
export AWS_REGION=us-east-1
python3 -c "
from mod_cloud_attacks import AWSAttacker, Credential, CloudProvider
cred = Credential(provider=CloudProvider.AWS, access_key='test', secret_key='test')
attacker = AWSAttacker(cred)
result = attacker.attack_imds_v1()
print(f'Result: {result.success}')
print(f'Finding: {result.finding.title if result.finding else None}')
"

# GCP Metadata
export GOOGLE_CLOUD_PROJECT=test-project
python3 -c "
from mod_cloud_attacks import GCPAttacker, Credential, CloudProvider
cred = Credential(provider=CloudProvider.GCP, key_path='/tmp/key.json')
attacker = GCPAttacker(cred)
result = attacker.attack_compute_metadata()
print(f'Result: {result.success}')
"

# Azure Managed Identity
export AZURE_SUBSCRIPTION_ID=test-sub
python3 -c "
from mod_cloud_attacks import AzureAttacker, Credential, CloudProvider
cred = Credential(provider=CloudProvider.AZURE, email='test@azure.com')
attacker = AzureAttacker(cred)
result = attacker.attack_managed_identity()
print(f'Result: {result.success}')
"
```

### Integration Tests

Test across multiple attacks:

```bash
# Full AWS attack suite
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py aws --deep

# Test finding generation
python3 -c "
from mod_cloud_attacks import CloudAttackOrchestrator, CloudProvider
orch = CloudAttackOrchestrator(provider=CloudProvider.AWS, deep_mode=True)
findings = orch.run_aws_attacks()
print(f'Findings: {len(findings)}')
for f in findings:
    print(f'  - [{f.severity.name}] {f.title}')
"

# Test all providers
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all
```

### Mock Mode Validation

Test without real cloud access:

```bash
# Enable mock mode for safe testing
export CLOUD_MOCK_MODE=true

# Test all providers
python3 mod_cloud_attacks.py all

# Test specific provider
python3 mod_cloud_attacks.py aws

# Verify findings are generated
python3 mod_cloud_attacks.py gcp --json | jq '.summary'

# Expected output:
# {
#   "total_findings": 5,
#   "critical": 3,
#   "high": 2
# }
```

---

## Real-World Testing Scenarios

### Scenario 1: AWS EC2 Instance Testing

**Setup:**
```bash
# Launch EC2 instance (use caution!)
aws ec2 run-instances --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.micro \
  --key-name my-key-pair

# Get instance IP
aws ec2 describe-instances --query 'Reservations[0].Instances[0].PublicIpAddress'

# SSH into instance
ssh -i my-key.pem ec2-user@EC2_IP
```

**Test IMDS:**
```bash
# From EC2 instance - IMDSv1
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Extract role name
ROLE=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)

# Get credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE/

# Expected output:
# {
#   "Code" : "Success",
#   "LastUpdated" : "2026-07-31T...",
#   "Type" : "AWS4-HMAC-SHA256",
#   "AccessKeyId" : "ASIA...",
#   "SecretAccessKey" : "...",
#   "Token" : "...",
#   "Expiration" : "..."
# }
```

**Run Module:**
```bash
# From EC2 instance
python3 mod_cloud_attacks.py aws --deep

# Expected findings:
# - IMDS v1 Accessible via SSRF (CRITICAL)
# - IMDSv2 Token Exposed (HIGH)
# - IAM Privilege Escalation Chain (CRITICAL)
```

### Scenario 2: GCP Compute Engine Testing

**Setup:**
```bash
# Create GCE instance
gcloud compute instances create test-instance \
  --image-family=debian-11 \
  --image-project=debian-cloud \
  --machine-type=e2-medium \
  --zone=us-central1-a

# SSH into instance
gcloud compute ssh test-instance --zone=us-central1-a
```

**Test Metadata Service:**
```bash
# From GCE instance - Compute metadata
curl -H 'Metadata-Flavor: Google' \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity

# Get access token
curl -H 'Metadata-Flavor: Google' \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://www.googleapis.com

# Expected: JWT token
```

**Run Module:**
```bash
python3 mod_cloud_attacks.py gcp --deep

# Expected findings:
# - GCP Service Account Token Exposed (CRITICAL)
# - Cloud Storage Bucket Misconfiguration (HIGH)
# - GCP Privilege Escalation Chain (CRITICAL)
```

### Scenario 3: Azure VM Testing

**Setup:**
```bash
# Create Azure VM
az vm create --resource-group test-rg \
  --name test-vm \
  --image UbuntuLTS \
  --admin-username azureuser

# Connect to VM
az vm run-command invoke -g test-rg -n test-vm --command-id RunShellScript \
  --scripts "echo 'VM Connected'"
```

**Test Managed Identity:**
```bash
# From Azure VM - IMDS endpoint
curl -H 'Metadata:true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/'

# Expected: JSON with access_token
```

**Run Module:**
```bash
export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
python3 mod_cloud_attacks.py azure --deep

# Expected findings:
# - Azure Managed Identity Token Exposed (CRITICAL)
# - Key Vault Secrets Accessible (CRITICAL)
# - Azure RBAC Privilege Escalation (HIGH)
```

---

## Vulnerability Validation

### Test AWS S3 Misconfiguration

```bash
# Create test S3 bucket
aws s3api create-bucket --bucket test-public-bucket

# Make it public (intentionally for testing)
aws s3api put-bucket-acl --bucket test-public-bucket --acl public-read

# Run module
python3 mod_cloud_attacks.py aws

# Expected: Finding for public S3 bucket access
```

### Test Lambda Secrets

```bash
# Create Lambda function with secrets
cat > lambda_function.py << 'EOF'
import os

def lambda_handler(event, context):
    db_password = os.environ.get('DB_PASSWORD')
    api_key = os.environ.get('API_KEY')
    return {'statusCode': 200}
EOF

zip lambda.zip lambda_function.py

aws lambda create-function \
  --function-name test-function \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT_ID:role/lambda-role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://lambda.zip \
  --environment Variables={DB_PASSWORD=secret123,API_KEY=sk-1234567890}

# Run module
python3 mod_cloud_attacks.py aws

# Expected: Lambda Environment Variable Exposure finding
```

### Test RDS Public Access

```bash
# Create RDS instance with public access (CAUTION!)
aws rds create-db-instance \
  --db-instance-identifier test-db \
  --db-instance-class db.t3.micro \
  --engine mysql \
  --allocated-storage 20 \
  --publicly-accessible

# Run module
python3 mod_cloud_attacks.py aws

# Expected: RDS Security Group Allows World Access finding
```

---

## Output Validation

### Verify Finding Structure

```python
# Each finding should have:
finding = {
    'title': str,           # "IMDS v1 Accessible"
    'description': str,     # Detailed description
    'severity': Enum,       # CRITICAL, HIGH, MEDIUM, LOW
    'provider': Enum,       # AWS, GCP, AZURE
    'technique': str,       # Attack technique name
    'evidence': dict,       # Supporting evidence
    'remediation': str,     # How to fix
    'curl_poc': str,        # Proof of concept command
    'timestamp': str        # ISO format timestamp
}
```

### Validate JSON Output

```bash
# Generate JSON output
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all --json > findings.json

# Validate JSON structure
python3 << 'EOF'
import json

with open('findings.json', 'r') as f:
    data = json.load(f)

# Check top-level keys
required_keys = {'findings', 'privesc_chains', 'summary'}
assert set(data.keys()) == required_keys, f"Missing keys: {required_keys - set(data.keys())}"

# Check summary
assert 'total_findings' in data['summary']
assert 'critical' in data['summary']
assert 'high' in data['summary']

# Check findings
for finding in data['findings']:
    required = {'title', 'description', 'severity', 'provider', 'technique'}
    assert required.issubset(set(finding.keys())), f"Finding missing keys: {required - set(finding.keys())}"

print("✓ JSON structure valid")
print(f"✓ {data['summary']['total_findings']} findings")
print(f"✓ {data['summary']['critical']} critical severity")
EOF
```

### Validate Report Generation

```bash
# Generate report
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all --report report.txt

# Check file exists
test -f report.txt && echo "✓ Report file created" || echo "✗ Report not created"

# Verify content
grep -q "CLOUD ATTACK MODULE REPORT" report.txt && echo "✓ Report header found"
grep -q "CRITICAL SEVERITY FINDINGS" report.txt && echo "✓ Critical findings section"
grep -q "Privilege Escalation Chains" report.txt && echo "✓ PrivEsc chains section"
```

---

## Performance Testing

### Execution Time Benchmarks

```bash
# Quick mode (should complete in <5 seconds)
time CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py aws --quick

# Deep mode (should complete in <30 seconds)
time CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py aws --deep

# All providers (should complete in <60 seconds)
time CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all --deep
```

**Expected Results:**
```
aws --quick:     real    0m2.345s
aws --deep:      real    0m8.123s
all --deep:      real    0m20.456s
```

### Memory Usage

```bash
# Monitor memory during execution
(python3 mod_cloud_attacks.py all &) && \
  PID=$! && \
  watch -n 0.1 "ps -p $PID -o %mem,rss"

# Expected: <200MB RSS memory usage
```

---

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: Cloud Attack Module Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Syntax check
        run: python3 -m py_compile mod_cloud_attacks.py
      
      - name: Mock mode tests
        env:
          CLOUD_MOCK_MODE: "true"
        run: |
          python3 mod_cloud_attacks.py all
          python3 mod_cloud_attacks.py aws --deep
          python3 mod_cloud_attacks.py gcp --quick
          python3 mod_cloud_attacks.py azure
      
      - name: JSON output validation
        env:
          CLOUD_MOCK_MODE: "true"
        run: |
          python3 mod_cloud_attacks.py all --json > findings.json
          python3 -c "import json; json.load(open('findings.json'))"
      
      - name: Report generation
        env:
          CLOUD_MOCK_MODE: "true"
        run: python3 mod_cloud_attacks.py all --report findings.txt
```

### GitLab CI Pipeline

```yaml
cloud-attack-tests:
  image: python:3.11
  script:
    - python3 -m py_compile mod_cloud_attacks.py
    - CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all
    - CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all --json > findings.json
  artifacts:
    paths:
      - findings.json
    reports:
      sast: findings.json
```

---

## Regression Testing

### Checklist for Each Release

- [ ] All 50+ AWS techniques execute without error
- [ ] All 30+ GCP techniques execute without error
- [ ] All 25+ Azure techniques execute without error
- [ ] Mock mode produces 10-15 findings per provider
- [ ] Privilege escalation chains generate correctly
- [ ] JSON output validates against schema
- [ ] Report generation completes without errors
- [ ] No unauthorized API calls to real cloud services
- [ ] Memory usage stays <200MB
- [ ] Execution completes in <60 seconds
- [ ] Finding severity levels are appropriate
- [ ] PoC commands are syntactically correct
- [ ] Remediation guidance is actionable
- [ ] Timestamp format is ISO 8601

### Test Results Template

```
Test Run: [DATE]
Module Version: [VERSION]
Python Version: [VERSION]
Platform: [OS]

AWS Module:
  ✓ IMDS v1 exploitation
  ✓ IMDS v2 bypass
  ✓ S3 bucket enumeration
  ✓ IAM policy enumeration
  ✓ Lambda exploitation
  ✓ RDS abuse
  ✓ Secrets Manager extraction
  ✓ KMS key enumeration
  ✓ EC2 enumeration
  ✓ SSM parameter extraction
  ✓ IAM privilege escalation chain
  Findings: 10
  Critical: 5
  High: 3
  Medium: 2

GCP Module:
  ✓ Compute metadata exploitation
  ✓ Cloud Storage enumeration
  ✓ IAM role enumeration
  ✓ Cloud Functions exploitation
  ✓ Service account key extraction
  ✓ GCP privilege escalation chain
  Findings: 5
  Critical: 3
  High: 2

Azure Module:
  ✓ Managed Identity extraction
  ✓ Key Vault enumeration
  ✓ Storage Account exploitation
  ✓ RBAC privilege escalation
  Findings: 4
  Critical: 2
  High: 1
  Medium: 1

Overall:
  Total Findings: 19
  Total Critical: 10
  Execution Time: 8.2s
  Memory Usage: 156MB
  Status: PASS ✓
```

---

## Known Limitations

### Not Testable in Mock Mode

These require real cloud credentials to validate:

- [ ] Actual IMDS token extraction (requires EC2/GCE/Azure VM)
- [ ] Real S3 bucket enumeration (requires valid AWS credentials)
- [ ] Actual Lambda invocation (requires Lambda function)
- [ ] RDS database connection (requires network access + creds)
- [ ] KMS key operations (requires encryption permissions)
- [ ] Service account key creation (requires IAM permissions)

### Testing Requirements

| Test | Required Credentials | Risk Level |
|------|---------------------|-----------|
| IMDS v1 | EC2 instance access | LOW (read-only) |
| IMDS v2 | EC2 instance access | LOW (read-only) |
| S3 enumeration | AWS access key | MEDIUM (ListBucket) |
| Lambda exec | Lambda role | MEDIUM (Invoke) |
| RDS access | RDS password | HIGH (full database) |
| IAM privesc | IAM permissions | CRITICAL (account takeover) |

---

## Cleanup & Teardown

### AWS Test Resources

```bash
# Delete test S3 bucket
aws s3 rb s3://test-public-bucket --force

# Delete test Lambda
aws lambda delete-function --function-name test-function

# Delete test RDS
aws rds delete-db-instance \
  --db-instance-identifier test-db \
  --skip-final-snapshot

# Delete EC2 instance
aws ec2 terminate-instances --instance-ids i-0123456789abcdef
```

### GCP Test Resources

```bash
# Delete GCE instance
gcloud compute instances delete test-instance --zone=us-central1-a

# Delete storage bucket
gsutil -m rm -r gs://test-bucket/

# Delete service account
gcloud iam service-accounts delete attacker-sa@PROJECT.iam.gserviceaccount.com
```

### Azure Test Resources

```bash
# Delete resource group (includes all resources)
az group delete --name test-rg --yes
```

---

## References

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [Azure Security Center](https://docs.microsoft.com/en-us/azure/security/benchmarks/)
- [OWASP Cloud Top 10](https://owasp.org/www-community/attacks/Cloud_Computing_Attacks)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)
