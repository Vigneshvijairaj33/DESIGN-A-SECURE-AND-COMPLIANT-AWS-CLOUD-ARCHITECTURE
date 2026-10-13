# Security Alert Rules Reference
## Project: Secure Compliant Cloud Architecture

---

## CloudWatch Alarm Rules (CIS AWS Foundations Benchmark)

| Alarm Name | CIS Control | Pattern | Threshold | Severity |
|------------|------------|---------|-----------|----------|
| root-account-usage | CIS 3.3 | `userIdentity.type = "Root"` and not a service event | 1 event | CRITICAL |
| iam-policy-changes | CIS 3.4 | PutGroupPolicy, PutRolePolicy, PutUserPolicy, Create/Delete/Attach Policy | 1 event | HIGH |
| cloudtrail-config-changes | CIS 3.5 | CreateTrail, UpdateTrail, DeleteTrail, StopLogging, StartLogging | 1 event | CRITICAL |
| console-auth-failures | CIS 3.6 | ConsoleLogin with errorMessage = "Failed authentication" | 3 events/5min | HIGH |
| cmk-key-changes | CIS 3.7 | DisableKey, ScheduleKeyDeletion, CancelKeyDeletion | 1 event | HIGH |
| s3-bucket-policy-changes | CIS 3.8 | PutBucketAcl, PutBucketPolicy, DeleteBucketPolicy | 1 event | HIGH |
| config-service-changes | CIS 3.9 | StopConfigurationRecorder, DeleteDeliveryChannel | 1 event | HIGH |
| security-group-changes | CIS 3.10 | AuthorizeSecurityGroupIngress, RevokeSecurityGroupIngress, CreateSecurityGroup, DeleteSecurityGroup | 1 event | MEDIUM |
| nacl-changes | CIS 3.11 | CreateNetworkAcl, CreateNetworkAclEntry, DeleteNetworkAcl | 1 event | MEDIUM |
| network-gateway-changes | CIS 3.12 | CreateCustomerGateway, DeleteCustomerGateway, AttachInternetGateway | 1 event | MEDIUM |
| route-table-changes | CIS 3.13 | CreateRoute, CreateRouteTable, ReplaceRoute | 1 event | LOW |
| vpc-changes | CIS 3.14 | CreateVpc, DeleteVpc, ModifyVpcAttribute | 1 event | MEDIUM |
| unauthorized-api-calls | CIS 3.1 | errorCode = "AccessDenied" or "*UnauthorizedAccess*" | 5 events/5min | MEDIUM |

---

## AI Model Alert Thresholds

| Risk Score | Category | Response SLA | Action |
|-----------|----------|-------------|--------|
| 85–100 | CRITICAL | Immediate (< 15 min) | Page on-call. Review CloudTrail now. Consider suspending role. |
| 65–84 | HIGH | < 2 hours | Security analyst review. Correlate with Config findings. |
| 40–64 | MEDIUM | < 24 hours | Review in daily security report. Monitor for escalation. |
| 0–39 | LOW | Next business day | Log for trend analysis. No immediate action. |

---

## False Positive Management

| Scenario | Likely Cause | Tuning Action |
|----------|-------------|--------------|
| Alert on scheduled job principal | Lambda runs nightly batch → high API volume | Whitelist the Lambda execution role ARN |
| Alert on off-hours | Legitimate maintenance window | Add maintenance window suppression rule in CloudWatch |
| Alert on unusual region | Developer legitimately using us-east-1 Bedrock | Add region to allowed list for that principal |
| Alert on sensitive action | DevOps engineer deploying new IAM role | Require change ticket number in PR; suppress if ticket exists |

---

## Incident Response Workflow

```
Alert Triggered (CloudWatch or AI Model)
         │
         ▼
    Triage (< 15 min for CRITICAL)
    ├─ Confirm alert is not a known false positive
    ├─ Identify affected principal(s) and resource(s)
    └─ Assign severity and responder
         │
         ▼
    Investigation
    ├─ Pull CloudTrail events for principal (last 24 hours)
    ├─ Check AWS Config compliance status
    ├─ Review AI model alert indicators
    ├─ Correlate source IP with known safe ranges
    └─ Check for related alerts (lateral movement pattern)
         │
         ▼
    Containment (if confirmed incident)
    ├─ Revoke session tokens: aws iam delete-session-token
    ├─ Disable compromised access keys (do NOT delete — preserve evidence)
    ├─ Detach over-permissive IAM policies
    └─ Isolate affected EC2 instances (security group to deny all)
         │
         ▼
    Evidence Collection
    ├─ Export CloudTrail events to S3 (evidence bucket)
    ├─ Record Config snapshots before/after
    ├─ Document timeline and actions taken
    └─ Preserve all logs (do not delete)
         │
         ▼
    Recovery
    ├─ Re-enable services with clean configuration
    ├─ Issue new credentials with least privilege
    ├─ Verify monitoring is active
    └─ Conduct post-incident review
```

---

## Notification Contacts

Configure these in `terraform.tfvars` before deployment:

- `alarm_email` — Primary security team email for CloudWatch SNS
- Add secondary contacts directly in the SNS topic after deployment
- For PagerDuty / Slack integration: add SNS → Lambda → webhook post-deployment
