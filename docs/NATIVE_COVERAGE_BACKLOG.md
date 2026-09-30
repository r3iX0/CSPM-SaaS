# Native coverage backlog

What the native rule engine does not check yet, taken from the Prowler 5.43.0 catalogue when the second engine was removed (DECISIONS.md section 168). Each entry is a check Prowler ran that no native rule answered. It is a backlog, not a promise: an entry leaves this file when a native rule answers the same question, or when it is decided the question is not worth asking.

Titles are Prowler's. The CIS column is the CIS Microsoft Azure Foundations Benchmark 6.0 control each check was mapped to, which is what a native rule answering it should map to as well.

## Azure (7 checks)

### Tier 1 — new exposure and identity surface (0)

Closed. Sections 169 to 173 read six new resource types, MySQL's TLS parameters and three tenant policies, and answered thirty-three Tier 1 checks with thirty native rules; three more were already answered by AZ-ID-004 (every user without MFA, which includes those with VM access), AZ-IAM-002 and AZ-IAM-003; and one was declined (HTTP on port 80, now in Tier 3).

### Tier 2 — configuration hygiene (0)

Closed. Sections 174 and 175 declared the checks that needed no new permission as property specs; section 176 added the twenty-one reads the rest needed under scanner role v11 -- Defender for Cloud's contacts, settings and IoT solutions, just-in-time policies, Recovery Services vaults and their protected items, managed disks, activity-log alerts, policy assignments, virtual networks, Network Watchers and their flow logs, Bastion hosts, the file service beneath storage accounts, the keys and secrets in each vault, and three SQL server settings -- plus Entra's named locations under consent already held. Forty-eight native rules answer fifty checks; two moved to Tier 3.

### Tier 3 — deferred (7)

Section 177 ported the other seventeen: runtime versions against a dated end-of-support table judged as of each capture, and the availability and backup checks at LOW severity, under scanner role v12. What remains cannot be asked, or was decided against.

**Unreadable without a secret, or about a retired agent (DECISIONS.md sections 176 and 177).** A function app's host runtime version and its Application Insights connection are written only in its application settings, which sit behind `config/list` -- the action that also returns connection strings and keys, and one the scanner role never requests. The Log Analytics agent that auto-provisioning installed was retired by Microsoft in August 2024, and the read that would ask about it is not in the published operations reference.

- `app_function_latest_runtime_version` — Function app uses the latest supported runtime version (~4)
- `app_function_application_insights_enabled` — Function App has Application Insights configured
- `defender_auto_provisioning_log_analytics_agent_vms_on` — Defender auto-provisioning of Log Analytics agent for Azure VMs is enabled

**Already decided against: AZ-NET-003 excludes ports 80 and 443 on purpose, because serving HTTP is usually the whole point of the workload, and a finding on every web server would bury the ones that matter (DECISIONS.md section 171).**

- `network_http_internet_access_restricted` — Network security group does not allow HTTP (TCP 80) from the Internet

**A design choice rather than a setting to correct (DECISIONS.md section 175).** Mutual TLS is how an application authenticates its callers, not hygiene every app should have; and a custom role for administering resource locks is an organizational arrangement, which the absence of says nothing about how locks are managed.

- `app_client_certificates_on` — Web app requires incoming client certificates
- `iam_custom_role_has_permissions_to_administer_resource_locks` — Custom role has permission to administer resource locks

**A vulnerability verdict: kept as evidence paired with exposure rather than a finding of its own (DECISIONS.md section 62).**

- `defender_container_images_resolved_vulnerabilities` — All Azure running container images in the subscription have no unresolved vulnerabilities

## AWS (575 checks)

Not ported for breadth: AWS has never been run against a live account (`docs/AWS_INTEGRATION.md` section 1). What to close first once it has is the CIS AWS Foundations Benchmark 7.0; the checks below that map to it are marked. The rest, mostly AWS Foundational Security Best Practices, are listed by service.

### Mapped to CIS AWS 7.0 (35)

| Check | Severity | CIS AWS 7.0 | Question |
|---|---|---|---|
| `account_maintain_current_contact_details` | Medium | 2.2 | AWS account contact information is current |
| `account_security_contact_information_is_registered` | Medium | 2.3 | AWS account has security alternate contact registered |
| `apigateway_restapi_logging_enabled` | Medium | 4.10 | API Gateway REST API stage has logging enabled |
| `apigatewayv2_api_access_logging_enabled` | Medium | 4.10 | API Gateway V2 API stage has access logging enabled |
| `awslambda_function_not_publicly_accessible` | Critical | 2.21 | Lambda function resource-based policy does not allow public access |
| `cloudfront_distributions_logging_enabled` | Medium | 4.10 | CloudFront distribution has logging enabled |
| `cloudtrail_s3_dataevents_read_enabled` | Low | 4.9 | CloudTrail trail records S3 object-level read events for all S3 buckets |
| `cloudtrail_s3_dataevents_write_enabled` | Low | 4.8 | CloudTrail trail records all S3 object-level API operations for all buckets |
| `ec2_instance_port_cifs_exposed_to_internet` | Critical | 6.1.2 | EC2 instance does not allow Internet ingress to TCP ports 139 or 445 (CIFS) |
| `ec2_instance_profile_attached` | Medium | 2.16 | EC2 instance is associated with an IAM instance profile role |
| `ec2_securitygroup_allow_ingress_from_internet_to_all_ports` | Critical | 6.3, 6.4 | Security group does not have all ports open to the Internet |
| `efs_encryption_at_rest_enabled` | Medium | 3.3.1 | EFS file system has encryption at rest enabled |
| `elbv2_logging_enabled` | Medium | 4.10 | ELBv2 Application Load Balancer has access logs to S3 configured |
| `eventbridge_bus_exposed` | High | 2.21 | AWS EventBridge event bus policy does not allow public access |
| `glacier_vaults_policy_public_access` | Critical | 2.21 | S3 Glacier vault has no policy or its policy does not allow access to everyone |
| `iam_avoid_root_usage` | High | 2.7 | AWS account root user has not been used in the last day |
| `iam_aws_attached_policy_no_administrative_privileges` | Critical | 2.14 | Attached AWS-managed IAM policy does not allow '*:*' administrative privileges |
| `iam_check_saml_providers_sts` | Low | 2.19 | IAM SAML provider exists in the account |
| `iam_policy_attached_only_to_group_or_roles` | Low | 2.13 | IAM user has no inline or attached policies |
| `iam_policy_cloudshell_admin_not_attached` | Medium | 2.20 | No IAM users, groups, or roles have the AWSCloudShellFullAccess policy attached |
| `iam_root_credentials_management_enabled` | High | 2.1.1 | AWS Organization has centralized root credentials management enabled |
| `iam_root_hardware_mfa_enabled` | Critical | 2.6 | Root account has a hardware MFA device enabled |
| `iam_rotate_access_key_90_days` | Medium | 2.12 | IAM user does not have active access keys older than 90 days |
| `iam_user_console_access_unused` | Medium | 2.11 | IAM user console access is disabled, used within the configured inactivity period, or never used |
| `kms_key_not_publicly_accessible` | Critical | 2.21 | Cloud KMS key does not grant access to allUsers or allAuthenticatedUsers |
| `macie_is_enabled` | Medium | 3.1.3 | Amazon Macie is enabled |
| `organizations_delegated_administrators` | Critical | 2.1.5, 2.1.6 | AWS Organization has only trusted delegated administrators |
| `rds_cluster_multi_az` | Medium | 3.2.4 | RDS cluster has Multi-AZ enabled |
| `rds_instance_multi_az` | Medium | 3.2.4 | RDS instance has Multi-AZ enabled |
| `s3_bucket_no_mfa_delete` | Medium | 3.1.2 | S3 bucket has MFA Delete enabled |
| `s3_bucket_policy_public_write_access` | Critical | 2.21 | S3 bucket policy does not allow public write access |
| `secretsmanager_not_publicly_accessible` | High | 2.21 | Secrets Manager secret resource policy does not allow public access |
| `sns_topics_not_publicly_accessible` | High | 2.21 | SNS topic is not publicly accessible |
| `sqs_queues_not_publicly_accessible` | Critical | 2.21 | SQS queue policy does not allow public access |
| `vpc_peering_routing_tables_with_least_privilege` | Medium | 6.6 | VPC peering connection route tables do not include 0.0.0.0/0 or entire requester/accepter VPC CIDR routes |

### By service

<details><summary><b>ec2</b> — 58 (18 critical, 19 high, 14 medium, 7 low)</summary>

- `ec2_ami_account_block_public_access` (medium) — AMI block public access is enabled at the account level
- `ec2_ami_public` (critical) — EC2 AMI owned by the account is not public
- `ec2_client_vpn_endpoint_connection_logging_enabled` (low) — EC2 Client VPN endpoint has client connection logging enabled
- `ec2_confidential_workload_host_imdsv2_not_enforced` (high) — Confidential-workload host enforces IMDSv2
- `ec2_confidential_workload_host_not_running` (medium) — Nitro Enclave parent instance is in the running state
- `ec2_confidential_workload_host_public_ip` (medium) — Confidential-workload host is not exposed to the internet
- `ec2_confidential_workload_host_unrestricted_ingress` (high) — Confidential-workload host does not expose non-standard ports to the internet
- `ec2_confidential_workload_host_vsock_proxy_exposed` (medium) — Confidential-workload host does not expose likely vsock-proxy TCP ports to the internet
- `ec2_ebs_public_snapshot` (critical) — EBS snapshot is not public
- `ec2_ebs_snapshot_account_block_public_access` (high) — All EBS snapshots have public access blocked
- `ec2_ebs_snapshots_encrypted` (high) — EBS snapshot is encrypted
- `ec2_ebs_volume_encryption` (high) — EBS volume is encrypted
- `ec2_ebs_volume_protected_by_backup_plan` (medium) — EBS volume is protected by a backup plan
- `ec2_ebs_volume_snapshots_exists` (high) — EBS volume has at least one snapshot
- `ec2_elastic_ip_shodan` (medium) — EC2 Elastic IP address is not listed in Shodan
- `ec2_elastic_ip_unassigned` (low) — Elastic IP is associated with an instance or network interface
- `ec2_instance_account_imdsv2_enabled` (high) — IMDSv2 is required by default for EC2 instances at the account level
- `ec2_instance_detailed_monitoring_enabled` (low) — EC2 instance has detailed monitoring enabled
- `ec2_instance_internet_facing_with_instance_profile` (high) — EC2 instance is not internet-facing with an instance profile attached
- `ec2_instance_managed_by_ssm` (medium) — EC2 instance is managed by AWS Systems Manager or not running
- `ec2_instance_older_than_specific_days` (medium) — EC2 instance is not older than the configured maximum age or is not running
- `ec2_instance_paravirtual_type` (medium) — EC2 instance virtualization type is HVM
- `ec2_instance_port_cassandra_exposed_to_internet` (critical) — EC2 instance does not have Cassandra ports (TCP 7000, 7001, 7199, 9042, 9160) open to the Internet
- `ec2_instance_port_elasticsearch_kibana_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to Elasticsearch and Kibana ports (TCP 9200, 9300, 5601)
- `ec2_instance_port_ftp_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP ports 20 or 21 (FTP)
- `ec2_instance_port_kafka_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP port 9092 (Kafka)
- `ec2_instance_port_kerberos_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP ports 88, 464, 749, or 750 (Kerberos)
- `ec2_instance_port_ldap_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP ports 389 or 636 (LDAP/LDAPS)
- `ec2_instance_port_memcached_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP port 11211 (Memcached)
- `ec2_instance_port_mongodb_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP ports 27017 or 27018 (MongoDB)
- `ec2_instance_port_mysql_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP port 3306 (MySQL)
- `ec2_instance_port_oracle_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP ports 1521, 2483, or 2484 (Oracle)
- `ec2_instance_port_postgresql_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP port 5432 (PostgreSQL)
- `ec2_instance_port_rdp_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP port 3389 (RDP)
- `ec2_instance_port_redis_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP port 6379 (Redis)
- `ec2_instance_port_sqlserver_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP ports 1433 or 1434 (SQL Server)
- `ec2_instance_port_ssh_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP port 22 (SSH)
- `ec2_instance_port_telnet_exposed_to_internet` (critical) — EC2 instance does not allow ingress from the Internet to TCP port 23 (Telnet)
- `ec2_instance_public_ip` (medium) — EC2 instance does not have a public IP address
- `ec2_instance_stopped_older_than_specific_days` (low) — EC2 instance has not been stopped longer than the configured maximum days
- `ec2_instance_uses_single_eni` (low) — EC2 instance has no more than one Elastic Network Interface (ENI) attached
- `ec2_instance_with_outdated_ami` (medium) — EC2 instance uses a non-deprecated Amazon AMI
- `ec2_launch_template_imdsv2_required` (high) — EC2 launch template has IMDSv2 enabled and required or instance metadata service disabled
- `ec2_launch_template_no_public_ip` (high) — Amazon EC2 launch template has no public IP addresses configured on network interfaces
- `ec2_networkacl_unused` (low) — Non-default network ACL is associated with a subnet
- `ec2_securitygroup_allow_ingress_from_internet_to_any_port` (high) — Security group has no 0.0.0.0/0 or ::/0 ingress to any port, or is attached only to allowed interface types or instance owners
- `ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip` (medium) — Security group does not have any port open to a specific public IP address
- `ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports` (high) — Security group does not allow ingress from 0.0.0.0/0 or ::/0 to high-risk TCP ports
- `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601` (high) — Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Elasticsearch/Kibana TCP ports 9200, 9300, and 5601
- `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21` (high) — Security group does not allow ingress from 0.0.0.0/0 or ::/0 to FTP ports 20 or 21
- `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092` (high) — Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 9092 (Kafka)
- `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211` (high) — Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Memcached TCP port 11211
- `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23` (high) — Security group does not allow ingress from the Internet to TCP port 23 (Telnet)
- `ec2_securitygroup_allow_wide_open_public_ipv4` (high) — Security group has no ingress or egress rules with public IPv4 CIDR ranges from /1 to /23
- `ec2_securitygroup_from_launch_wizard` (medium) — Security group not created using the EC2 Launch Wizard
- `ec2_securitygroup_not_used` (low) — Non-default EC2 security group is in use
- `ec2_securitygroup_with_many_ingress_egress_rules` (medium) — Security group has 50 or fewer inbound rules and 50 or fewer outbound rules
- `ec2_transitgateway_auto_accept_vpc_attachments` (high) — Amazon EC2 Transit Gateway does not automatically accept shared VPC attachments

</details>

<details><summary><b>iam</b> — 33 (2 critical, 13 high, 16 medium, 2 low)</summary>

- `iam_administrator_access_with_mfa` (high) — IAM group members granted AdministratorAccess have MFA enabled
- `iam_customer_unattached_policy_no_administrative_privileges` (medium) — Unattached customer managed IAM policy does not allow '*:*' administrative privileges
- `iam_group_administrator_access_policy` (high) — IAM group does not have AdministratorAccess policy attached
- `iam_inline_policy_allows_privilege_escalation` (high) — IAM inline policy does not allow privilege escalation
- `iam_inline_policy_no_administrative_privileges` (critical) — Inline IAM policy does not allow '*:*' administrative privileges
- `iam_inline_policy_no_full_access_to_cloudtrail` (high) — Inline IAM policy does not allow 'cloudtrail:*' privileges
- `iam_inline_policy_no_full_access_to_kms` (medium) — Inline IAM policy does not allow kms:* privileges
- `iam_inline_policy_no_wildcard_marketplace_subscribe` (medium) — Inline IAM policy does not allow 'aws-marketplace:Subscribe' on all resources
- `iam_no_custom_policy_permissive_role_assumption` (high) — Custom IAM policy does not allow STS role assumption on wildcard resources
- `iam_password_policy_expires_passwords_within_90_days_or_less` (medium) — IAM account password policy enforces password expiration within 90 days or less
- `iam_password_policy_lowercase` (low) — IAM password policy requires at least one lowercase letter
- `iam_password_policy_number` (medium) — IAM password policy requires at least one number
- `iam_password_policy_symbol` (medium) — IAM password policy requires at least one symbol
- `iam_password_policy_uppercase` (medium) — IAM password policy requires at least one uppercase letter
- `iam_policy_allows_privilege_escalation` (high) — Customer managed IAM policy does not allow actions that can lead to privilege escalation
- `iam_policy_no_agentcore_workload_access_token_wildcard` (high) — Custom IAM policy scopes Bedrock AgentCore workload access token retrieval to workload identity ARNs
- `iam_policy_no_full_access_to_cloudtrail` (medium) — Customer managed IAM policy does not allow cloudtrail:* privileges
- `iam_policy_no_full_access_to_kms` (medium) — Custom IAM policy does not allow 'kms:*' privileges
- `iam_policy_no_wildcard_marketplace_subscribe` (medium) — Custom IAM policy does not allow 'aws-marketplace:Subscribe' on all resources
- `iam_policy_passrole_to_bedrock_agentcore_restricted` (high) — Custom IAM policy restricts iam:PassRole to Bedrock AgentCore to specific roles
- `iam_role_access_not_stale_to_bedrock` (medium) — Regular Bedrock access ensures IAM roles retain only actively used permissions
- `iam_role_administratoraccess_policy` (high) — IAM role does not have AdministratorAccess policy attached
- `iam_role_cross_account_readonlyaccess_policy` (high) — IAM role does not grant ReadOnlyAccess to external AWS accounts
- `iam_role_cross_service_confused_deputy_prevention` (high) — IAM service role prevents cross-service confused deputy attack
- `iam_role_service_trust_restricts_source_to_account` (medium) — IAM role trust policy confines AWS service principals to a specific source account
- `iam_securityaudit_role_created` (low) — At least one IAM role has the SecurityAudit AWS managed policy attached
- `iam_user_access_not_stale_to_bedrock` (medium) — Regular Bedrock access ensures IAM users retain only actively used permissions
- `iam_user_access_not_stale_to_sagemaker` (medium) — Regular SageMaker access ensures IAM users retain only actively used permissions
- `iam_user_administrator_access_policy` (critical) — IAM user does not have AdministratorAccess policy attached
- `iam_user_hardware_mfa_enabled` (high) — IAM user has hardware MFA enabled
- `iam_user_no_setup_initial_access_key` (medium) — IAM user does not have active access keys that have never been used
- `iam_user_two_active_access_key` (medium) — IAM user has at most one active access key
- `iam_user_with_temporary_credentials` (high) — IAM user does not use long-lived credentials to access services other than IAM or STS

</details>

<details><summary><b>rds</b> — 30 (1 critical, 8 high, 14 medium, 7 low)</summary>

- `rds_cluster_backtrack_enabled` (low) — RDS Aurora MySQL cluster has Backtrack enabled
- `rds_cluster_copy_tags_to_snapshots` (low) — RDS DB cluster has copy tags to snapshots enabled
- `rds_cluster_critical_event_subscription` (medium) — RDS cluster event subscription is enabled for maintenance and failure categories
- `rds_cluster_default_admin` (medium) — RDS cluster master username is not admin or postgres
- `rds_cluster_deletion_protection` (medium) — RDS cluster has deletion protection enabled
- `rds_cluster_iam_authentication_enabled` (medium) — RDS cluster has IAM authentication enabled
- `rds_cluster_integration_cloudwatch_logs` (medium) — RDS cluster has CloudWatch Logs export enabled
- `rds_cluster_minor_version_upgrade_enabled` (medium) — RDS cluster has automatic minor version upgrades enabled
- `rds_cluster_non_default_port` (low) — RDS cluster uses a non-default port for its database engine
- `rds_cluster_protected_by_backup_plan` (high) — RDS cluster is protected by an AWS Backup plan
- `rds_cluster_storage_encrypted` (high) — RDS cluster storage is encrypted
- `rds_instance_backup_enabled` (medium) — RDS instance has backup retention period greater than 0 days
- `rds_instance_certificate_expiration` (high) — RDS instance SSL/TLS certificate has more than 3 months of validity remaining
- `rds_instance_copy_tags_to_snapshots` (low) — RDS DB instance has copy tags to snapshots enabled
- `rds_instance_critical_event_subscription` (medium) — RDS instance event subscription is enabled for maintenance, configuration change, and failure categories
- `rds_instance_default_admin` (medium) — RDS instance does not use the default master username (admin or postgres)
- `rds_instance_deletion_protection` (medium) — RDS instance has deletion protection enabled
- `rds_instance_deprecated_engine_version` (high) — RDS instance uses a supported engine version
- `rds_instance_enhanced_monitoring_enabled` (low) — RDS instance has enhanced monitoring enabled
- `rds_instance_event_subscription_parameter_groups` (low) — RDS DB parameter group event subscription is enabled and subscribes to configuration change events or all categories
- `rds_instance_event_subscription_security_groups` (medium) — RDS event subscription for DB security groups is enabled for configuration change and failure events
- `rds_instance_extended_support` (medium) — RDS instance is not enrolled in RDS Extended Support
- `rds_instance_iam_authentication_enabled` (medium) — RDS instance has IAM database authentication enabled
- `rds_instance_inside_vpc` (high) — RDS instance is deployed in a VPC
- `rds_instance_integration_cloudwatch_logs` (medium) — RDS instance exports logs to CloudWatch Logs
- `rds_instance_non_default_port` (low) — RDS instance uses a non-default port for its engine
- `rds_instance_protected_by_backup_plan` (high) — RDS instance is protected by an AWS Backup plan
- `rds_instance_transport_encrypted` (high) — RDS instance or cluster enforces SSL/TLS encryption for client connections
- `rds_snapshots_encrypted` (high) — RDS DB instance snapshot or DB cluster snapshot is encrypted
- `rds_snapshots_public_access` (critical) — RDS snapshot is not publicly shared

</details>

<details><summary><b>bedrock</b> — 17 (1 critical, 11 high, 4 medium, 1 low)</summary>

- `bedrock_agent_guardrail_enabled` (high) — Amazon Bedrock agent uses a guardrail to protect agent sessions
- `bedrock_agent_role_least_privilege` (high) — Amazon Bedrock agent execution role follows least privilege
- `bedrock_agent_role_not_shared_across_agents` (high) — Bedrock Agent has a dedicated execution role
- `bedrock_api_key_no_administrative_privileges` (high) — Amazon Bedrock API key does not have administrative privileges, privilege escalation paths, or full Bedrock service access
- `bedrock_api_key_no_long_term_credentials` (high) — Amazon Bedrock long-term API key has expired
- `bedrock_custom_model_encrypted_with_cmk` (critical) — Bedrock custom model is encrypted with a customer-managed KMS key
- `bedrock_full_access_policy_attached` (high) — IAM role does not have AmazonBedrockFullAccess managed policy attached
- `bedrock_guardrail_contextual_grounding_filter_enabled` (high) — Bedrock guardrail blocks ungrounded and irrelevant model responses
- `bedrock_guardrail_prompt_attack_filter_enabled` (high) — Amazon Bedrock guardrail has prompt attack filter strength set to HIGH
- `bedrock_guardrail_sensitive_information_filter_enabled` (high) — Amazon Bedrock guardrail blocks or masks sensitive information
- `bedrock_guardrails_configured` (medium) — Bedrock has at least one guardrail configured in the audited region
- `bedrock_knowledge_base_encrypted_with_cmk` (high) — Bedrock knowledge base data source is encrypted with a customer-managed KMS key
- `bedrock_model_invocation_logging_enabled` (medium) — Amazon Bedrock model invocation logging is enabled
- `bedrock_model_invocation_logs_encryption_enabled` (high) — Amazon Bedrock model invocation logs are encrypted in the S3 bucket and KMS-encrypted in the CloudWatch log group
- `bedrock_prompt_encrypted_with_cmk` (medium) — Amazon Bedrock prompt is encrypted at rest with a customer-managed KMS key
- `bedrock_prompt_management_exists` (low) — Amazon Bedrock Prompt Management prompts exist in the region
- `bedrock_vpc_endpoints_configured` (medium) — VPC endpoints ensure private connectivity for all Bedrock APIs

</details>

<details><summary><b>sagemaker</b> — 16 (7 high, 6 medium, 3 low)</summary>

- `sagemaker_clarify_exists` (low) — Amazon SageMaker Clarify processing jobs exist in the region
- `sagemaker_domain_sso_configured` (medium) — SageMaker domains use SSO authentication instead of IAM mode
- `sagemaker_endpoint_config_kms_encryption_enabled` (medium) — SageMaker endpoint configuration is encrypted with a KMS key
- `sagemaker_endpoint_config_prod_variant_instances` (medium) — SageMaker endpoint configuration has all production variants with at least two initial instances
- `sagemaker_models_monitor_enabled` (low) — Amazon SageMaker has a monitoring schedule scheduled
- `sagemaker_models_network_isolation_enabled` (high) — Amazon SageMaker model has network isolation enabled
- `sagemaker_models_registry_in_use` (low) — Amazon SageMaker Model Registry should have at least one approved model package
- `sagemaker_models_vpc_settings_configured` (medium) — Amazon SageMaker model has VPC settings enabled
- `sagemaker_notebook_instance_encryption_enabled` (high) — SageMaker notebook instance is encrypted with a KMS key
- `sagemaker_notebook_instance_root_access_disabled` (medium) — Amazon SageMaker notebook instance has root access disabled
- `sagemaker_notebook_instance_vpc_settings_configured` (high) — Amazon SageMaker notebook instance has VPC settings configured
- `sagemaker_notebook_instance_without_direct_internet_access_configured` (high) — Amazon SageMaker notebook instance has direct internet access disabled
- `sagemaker_training_jobs_intercontainer_encryption_enabled` (medium) — Amazon SageMaker training job has inter-container traffic encryption enabled
- `sagemaker_training_jobs_network_isolation_enabled` (high) — Amazon SageMaker training job has network isolation enabled
- `sagemaker_training_jobs_volume_and_output_encryption_enabled` (high) — Amazon SageMaker training job volume has KMS encryption enabled
- `sagemaker_training_jobs_vpc_settings_configured` (high) — Amazon SageMaker training job has VPC configuration enabled

</details>

<details><summary><b>s3</b> — 15 (3 critical, 3 high, 4 medium, 5 low)</summary>

- `s3_access_point_public_access_block` (critical) — S3 access point has all Block Public Access settings enabled
- `s3_bucket_acl_prohibited` (medium) — S3 bucket has bucket ACLs disabled
- `s3_bucket_cross_account_access` (high) — S3 bucket policy does not allow cross-account access
- `s3_bucket_cross_region_replication` (low) — S3 bucket has cross-region replication configured to a bucket in a different region
- `s3_bucket_event_notifications_enabled` (low) — S3 bucket has event notifications enabled
- `s3_bucket_kms_encryption` (medium) — S3 bucket has server-side encryption with AWS KMS
- `s3_bucket_lifecycle_enabled` (low) — S3 bucket has a lifecycle configuration enabled
- `s3_bucket_object_lock` (low) — S3 bucket has Object Lock enabled
- `s3_bucket_object_public` (low) — Spot-check S3 bucket objects for public ACLs
- `s3_bucket_object_versioning` (medium) — S3 bucket has object versioning enabled
- `s3_bucket_public_list_acl` (critical) — S3 bucket is not publicly listable by Everyone or any authenticated AWS user
- `s3_bucket_public_write_acl` (critical) — S3 bucket ACL does not grant write access to Everyone or any AWS customer
- `s3_bucket_server_access_logging_enabled` (medium) — S3 bucket has server access logging enabled
- `s3_bucket_shadow_resource_vulnerability` (high) — S3 bucket is not a known shadow resource owned by another account
- `s3_multi_region_access_point_public_access_block` (high) — S3 Multi-Region Access Point has all Block Public Access settings enabled

</details>

<details><summary><b>cloudfront</b> — 13 (2 high, 5 medium, 6 low)</summary>

- `cloudfront_distributions_custom_ssl_certificate` (medium) — CloudFront distribution uses a custom SSL/TLS certificate
- `cloudfront_distributions_default_root_object` (high) — CloudFront distribution has a default root object configured
- `cloudfront_distributions_field_level_encryption_enabled` (low) — CloudFront distribution has Field Level Encryption enabled
- `cloudfront_distributions_geo_restrictions_enabled` (low) — CloudFront distribution has Geo restrictions enabled
- `cloudfront_distributions_https_enabled` (medium) — CloudFront distribution has viewer protocol policy set to HTTPS only or redirect to HTTPS
- `cloudfront_distributions_https_sni_enabled` (low) — CloudFront distribution serves HTTPS requests using SNI
- `cloudfront_distributions_multiple_origin_failover_configured` (low) — CloudFront distribution has origin failover configured with at least two origins
- `cloudfront_distributions_origin_traffic_encrypted` (medium) — CloudFront distribution encrypts traffic to custom origins
- `cloudfront_distributions_pqc_tls_enabled` (low) — CloudFront distributions enforce a post-quantum TLS 1.3 security policy
- `cloudfront_distributions_s3_origin_access_control` (medium) — CloudFront distribution uses Origin Access Control (OAC) for all S3 origins
- `cloudfront_distributions_s3_origin_non_existent_bucket` (high) — CloudFront distribution S3 origins reference existing buckets
- `cloudfront_distributions_using_deprecated_ssl_protocols` (low) — CloudFront distribution does not use SSLv3, TLSv1, or TLSv1.1 for origin connections
- `cloudfront_distributions_using_waf` (medium) — CloudFront distribution uses an AWS WAF web ACL

</details>

<details><summary><b>elbv2</b> — 13 (11 medium, 2 low)</summary>

- `elbv2_alb_drop_invalid_header_fields_enabled` (medium) — Application Load Balancer should be configured to drop invalid HTTP header fields
- `elbv2_cross_zone_load_balancing_enabled` (medium) — ELBv2 Network or Gateway Load Balancer has cross-zone load balancing enabled
- `elbv2_deletion_protection` (medium) — ELBv2 load balancer has deletion protection enabled
- `elbv2_desync_mitigation_mode` (medium) — Application Load Balancer has desync mitigation mode set to strictest or defensive, or drops invalid header fields
- `elbv2_insecure_ssl_ciphers` (medium) — ELBv2 load balancer uses a secure SSL policy on HTTPS listeners
- `elbv2_internet_facing` (medium) — Application Load Balancer is not publicly accessible (no inbound TCP from 0.0.0.0/0 or ::/0)
- `elbv2_is_in_multiple_az` (medium) — ELBv2 load balancer is configured across multiple Availability Zones
- `elbv2_listener_fips_tls_enabled` (low) — ELBv2 HTTPS/TLS listeners use a FIPS TLS security policy
- `elbv2_listener_pqc_tls_enabled` (low) — ELBv2 HTTPS/TLS listeners use a post-quantum TLS security policy
- `elbv2_listeners_underneath` (medium) — ELBv2 load balancer has at least one listener
- `elbv2_nlb_tls_termination_enabled` (medium) — ELBv2 Network Load Balancer has TLS termination enabled
- `elbv2_ssl_listeners` (medium) — ELBv2 Application Load Balancer listeners use HTTPS or redirect HTTP to HTTPS
- `elbv2_waf_acl_attached` (medium) — Application Load Balancer has a WAF Web ACL attached

</details>

<details><summary><b>cognito</b> — 12 (12 medium)</summary>

- `cognito_identity_pool_guest_access_disabled` (medium) — Cognito identity pool has guest access disabled
- `cognito_user_pool_client_prevent_user_existence_errors` (medium) — Amazon Cognito user pool client has Prevent User Existence Errors enabled
- `cognito_user_pool_client_token_revocation_enabled` (medium) — Amazon Cognito user pool client has token revocation enabled
- `cognito_user_pool_deletion_protection_enabled` (medium) — Cognito user pool has deletion protection enabled
- `cognito_user_pool_mfa_enabled` (medium) — Amazon Cognito user pool requires Multi-Factor Authentication (MFA)
- `cognito_user_pool_password_policy_lowercase` (medium) — Cognito user pool password policy requires at least one lowercase letter
- `cognito_user_pool_password_policy_minimum_length_14` (medium) — Cognito user pool has a password policy with a minimum length of 14 characters or more
- `cognito_user_pool_password_policy_number` (medium) — Cognito user pool password policy requires at least one number
- `cognito_user_pool_password_policy_symbol` (medium) — Cognito user pool password policy requires at least one symbol
- `cognito_user_pool_password_policy_uppercase` (medium) — Cognito user pool password policy requires at least one uppercase letter
- `cognito_user_pool_self_registration_disabled` (medium) — Amazon Cognito user pool has self registration disabled
- `cognito_user_pool_temporary_password_expiration` (medium) — Cognito user pool has temporary password expiration set to 7 days or less

</details>

<details><summary><b>glue</b> — 12 (4 high, 8 medium)</summary>

- `glue_data_catalogs_connection_passwords_encryption_enabled` (high) — Glue data catalog connection password is encrypted with a KMS key
- `glue_data_catalogs_metadata_encryption_enabled` (medium) — Glue Data Catalog metadata is encrypted with KMS
- `glue_data_catalogs_not_publicly_accessible` (high) — Glue Data Catalog is not publicly accessible via its resource policy
- `glue_database_connections_ssl_enabled` (high) — Glue connection has SSL enabled
- `glue_development_endpoints_cloudwatch_logs_encryption_enabled` (medium) — Glue development endpoint has CloudWatch Logs encryption enabled
- `glue_development_endpoints_job_bookmark_encryption_enabled` (medium) — Glue development endpoint has Job Bookmark encryption enabled
- `glue_development_endpoints_s3_encryption_enabled` (medium) — Glue development endpoint has S3 encryption enabled
- `glue_etl_jobs_amazon_s3_encryption_enabled` (high) — Glue job has S3 encryption enabled
- `glue_etl_jobs_cloudwatch_logs_encryption_enabled` (medium) — Glue ETL job has CloudWatch Logs encryption enabled
- `glue_etl_jobs_job_bookmark_encryption_enabled` (medium) — Glue ETL job has Job bookmark encryption enabled
- `glue_etl_jobs_logging_enabled` (medium) — Glue ETL job has continuous CloudWatch logging enabled
- `glue_ml_transform_encrypted_at_rest` (medium) — Glue ML Transform is encrypted at rest

</details>

<details><summary><b>opensearch</b> — 12 (2 critical, 5 high, 4 medium, 1 low)</summary>

- `opensearch_service_domains_access_control_enabled` (high) — Amazon OpenSearch Service domain has fine-grained access control enabled
- `opensearch_service_domains_audit_logging_enabled` (high) — Amazon OpenSearch Service domain has audit logging enabled
- `opensearch_service_domains_cloudwatch_logging_enabled` (low) — Amazon OpenSearch Service domain publishes search and index slow logs to CloudWatch Logs
- `opensearch_service_domains_encryption_at_rest_enabled` (critical) — Amazon OpenSearch Service domain has encryption at rest enabled
- `opensearch_service_domains_fault_tolerant_data_nodes` (medium) — OpenSearch domain has at least 3 data nodes and Zone Awareness enabled
- `opensearch_service_domains_fault_tolerant_master_nodes` (medium) — OpenSearch domain has at least 3 dedicated master nodes
- `opensearch_service_domains_https_communications_enforced` (high) — OpenSearch domain has HTTPS enforcement enabled
- `opensearch_service_domains_internal_user_database_enabled` (medium) — Amazon OpenSearch Service domain has internal user database disabled
- `opensearch_service_domains_node_to_node_encryption_enabled` (high) — Amazon OpenSearch Service domain has node-to-node encryption enabled
- `opensearch_service_domains_not_publicly_accessible` (critical) — Amazon OpenSearch Service domain is not publicly accessible
- `opensearch_service_domains_updated_to_the_latest_service_software_version` (high) — Amazon OpenSearch Service domain is updated to the latest service software version
- `opensearch_service_domains_use_cognito_authentication_for_kibana` (medium) — Amazon OpenSearch Service domain has either Amazon Cognito or SAML authentication enabled for Kibana

</details>

<details><summary><b>guardduty</b> — 11 (9 high, 2 medium)</summary>

- `guardduty_ai_protection_enabled` (high) — GuardDuty detector has AI Protection enabled
- `guardduty_centrally_managed` (medium) — GuardDuty detector is managed by an administrator account or is the administrator with member accounts
- `guardduty_delegated_admin_enabled_all_regions` (high) — GuardDuty has delegated admin configured and is enabled in all regions with organization auto-enable
- `guardduty_ec2_malware_protection_enabled` (high) — GuardDuty detector has Malware Protection for EC2 enabled
- `guardduty_eks_audit_log_enabled` (high) — GuardDuty detector has EKS Audit Log Monitoring enabled
- `guardduty_eks_runtime_monitoring_enabled` (medium) — GuardDuty detector has EKS Runtime Monitoring enabled
- `guardduty_lambda_protection_enabled` (high) — GuardDuty detector has Lambda Protection enabled
- `guardduty_no_high_severity_findings` (high) — GuardDuty detector has no high severity findings
- `guardduty_rds_protection_enabled` (high) — GuardDuty detector has RDS Protection enabled
- `guardduty_runtime_monitoring_enabled` (high) — GuardDuty detector has Runtime Monitoring enabled
- `guardduty_s3_protection_enabled` (high) — GuardDuty detector has S3 Protection enabled

</details>

<details><summary><b>ecs</b> — 10 (7 high, 2 medium, 1 low)</summary>

- `ecs_cluster_container_insights_enabled` (medium) — ECS cluster has Container Insights enabled or enhanced
- `ecs_service_fargate_latest_platform_version` (medium) — ECS Fargate service uses the latest Fargate platform version
- `ecs_service_no_assign_public_ip` (high) — ECS service does not have automatic public IP assignment
- `ecs_task_definitions_containers_readonly_access` (high) — ECS task definition has all containers with read-only root filesystems
- `ecs_task_definitions_host_namespace_not_shared` (high) — ECS task definition does not share the host's process namespace with its containers
- `ecs_task_definitions_host_networking_mode_users` (high) — Amazon ECS task definition does not use host network mode, or non-privileged containers specify a non-root user
- `ecs_task_definitions_logging_block_mode` (low) — ECS task definition has container logging in non-blocking mode
- `ecs_task_definitions_logging_enabled` (high) — ECS task definition has logging configured for all containers
- `ecs_task_definitions_no_privileged_containers` (high) — ECS task definition has no privileged containers
- `ecs_task_set_no_assign_public_ip` (high) — ECS task set does not automatically assign a public IP address

</details>

<details><summary><b>neptune</b> — 10 (1 critical, 1 high, 7 medium, 1 low)</summary>

- `neptune_cluster_backup_enabled` (medium) — Neptune cluster has automated backups enabled with retention period equal to or greater than the configured minimum
- `neptune_cluster_copy_tags_to_snapshots` (low) — Neptune DB cluster is configured to copy tags to snapshots.
- `neptune_cluster_deletion_protection` (medium) — Neptune cluster has deletion protection enabled
- `neptune_cluster_iam_authentication_enabled` (medium) — Neptune cluster has IAM authentication enabled
- `neptune_cluster_integration_cloudwatch_logs` (medium) — Neptune cluster has CloudWatch audit logs enabled
- `neptune_cluster_multi_az` (medium) — Neptune cluster has Multi-AZ enabled
- `neptune_cluster_public_snapshot` (critical) — NeptuneDB cluster snapshot is not publicly shared
- `neptune_cluster_snapshot_encrypted` (medium) — Neptune DB cluster snapshot is encrypted at rest
- `neptune_cluster_storage_encrypted` (high) — Neptune cluster storage is encrypted at rest
- `neptune_cluster_uses_public_subnet` (medium) — Neptune cluster is not using public subnets

</details>

<details><summary><b>redshift</b> — 10 (2 critical, 2 high, 5 medium, 1 low)</summary>

- `redshift_cluster_audit_logging` (medium) — Redshift cluster has audit logging enabled
- `redshift_cluster_automated_snapshot` (high) — Redshift cluster has automated snapshots enabled
- `redshift_cluster_automatic_upgrades` (medium) — Redshift cluster has automatic version upgrade enabled
- `redshift_cluster_encrypted_at_rest` (critical) — Redshift cluster is encrypted at rest
- `redshift_cluster_enhanced_vpc_routing` (medium) — Redshift cluster has Enhanced VPC Routing enabled
- `redshift_cluster_in_transit_encryption_enabled` (high) — Redshift cluster is encrypted in transit
- `redshift_cluster_multi_az_enabled` (medium) — Redshift cluster has Multi-AZ enabled
- `redshift_cluster_non_default_database_name` (low) — Redshift cluster does not use the default database name dev
- `redshift_cluster_non_default_username` (medium) — Amazon Redshift cluster does not use the default admin username
- `redshift_cluster_public_access` (critical) — Redshift cluster is not publicly exposed to the Internet

</details>

<details><summary><b>awslambda</b> — 9 (2 high, 5 medium, 2 low)</summary>

- `awslambda_function_env_vars_not_encrypted_with_cmk` (medium) — Lambda function environment variables are encrypted with a customer-managed KMS key
- `awslambda_function_inside_vpc` (low) — Lambda function is deployed inside a VPC
- `awslambda_function_invoke_api_operations_cloudtrail_logging_enabled` (low) — Lambda function Invoke API calls are recorded by CloudTrail
- `awslambda_function_no_dead_letter_queue` (medium) — Lambda function has a Dead Letter Queue configured
- `awslambda_function_url_cors_policy` (medium) — Lambda function URL CORS does not allow wildcard origins (*)
- `awslambda_function_url_public` (high) — Lambda function URL is not publicly accessible
- `awslambda_function_using_cross_account_layers` (high) — Lambda function does not use cross-account layers
- `awslambda_function_using_supported_runtimes` (medium) — Lambda function uses a supported runtime
- `awslambda_function_vpc_multi_az` (medium) — Lambda function is configured with VPC subnets in at least two Availability Zones

</details>

<details><summary><b>codebuild</b> — 9 (1 critical, 3 high, 4 medium, 1 low)</summary>

- `codebuild_project_logging_enabled` (medium) — CodeBuild project has CloudWatch Logs or S3 logging enabled
- `codebuild_project_not_publicly_accessible` (high) — CodeBuild project visibility is private
- `codebuild_project_older_90_days` (medium) — CodeBuild project has been invoked in the last 90 days
- `codebuild_project_s3_logs_encrypted` (low) — CodeBuild project S3 logs are encrypted at rest
- `codebuild_project_source_repo_url_no_sensitive_credentials` (critical) — CodeBuild project source repository URLs do not contain sensitive credentials
- `codebuild_project_user_controlled_buildspec` (medium) — CodeBuild project does not use a user-controlled buildspec file
- `codebuild_project_uses_allowed_github_organizations` (high) — CodeBuild project using GitHub uses an allowed GitHub organization
- `codebuild_project_webhook_filters_use_anchored_patterns` (high) — CodeBuild project webhook filters use anchored regex patterns
- `codebuild_report_group_export_encrypted` (medium) — CodeBuild report group exports to S3 are encrypted at rest

</details>

<details><summary><b>dms</b> — 9 (1 critical, 1 high, 7 medium)</summary>

- `dms_endpoint_mongodb_authentication_enabled` (medium) — DMS MongoDB endpoint has an authentication mechanism enabled
- `dms_endpoint_neptune_iam_authorization_enabled` (medium) — DMS endpoint for Neptune has IAM authorization enabled
- `dms_endpoint_redis_in_transit_encryption_enabled` (medium) — DMS endpoint for Redis OSS is encrypted in transit
- `dms_endpoint_ssl_enabled` (high) — DMS endpoint has SSL enabled
- `dms_instance_minor_version_upgrade_enabled` (medium) — DMS replication instance has auto minor version upgrade enabled
- `dms_instance_multi_az_enabled` (medium) — DMS replication instance has Multi-AZ enabled
- `dms_instance_no_public_access` (critical) — DMS replication instance is not publicly exposed to the Internet
- `dms_replication_task_source_logging_enabled` (medium) — DMS replication task has logging enabled and SOURCE_CAPTURE and SOURCE_UNLOAD components set to at least Default severity
- `dms_replication_task_target_logging_enabled` (medium) — DMS replication task has TARGET_APPLY and TARGET_LOAD logging enabled with at least default severity

</details>

<details><summary><b>dynamodb</b> — 9 (9 medium)</summary>

- `dynamodb_accelerator_cluster_encryption_enabled` (medium) — DynamoDB DAX cluster has encryption at rest enabled
- `dynamodb_accelerator_cluster_in_transit_encryption_enabled` (medium) — DynamoDB Accelerator (DAX) cluster has encryption in transit enabled
- `dynamodb_accelerator_cluster_multi_az` (medium) — DynamoDB Accelerator (DAX) cluster has nodes in multiple Availability Zones
- `dynamodb_table_autoscaling_enabled` (medium) — DynamoDB table uses on-demand capacity or has auto scaling enabled for read and write capacity units
- `dynamodb_table_cross_account_access` (medium) — DynamoDB table resource-based policy does not allow cross-account access
- `dynamodb_table_deletion_protection_enabled` (medium) — DynamoDB table has deletion protection enabled
- `dynamodb_table_protected_by_backup_plan` (medium) — DynamoDB table is protected by a backup plan
- `dynamodb_tables_kms_cmk_encryption_enabled` (medium) — DynamoDB table is encrypted at rest with AWS KMS
- `dynamodb_tables_pitr_enabled` (medium) — DynamoDB table has point-in-time recovery (PITR) enabled

</details>

<details><summary><b>elb</b> — 9 (9 medium)</summary>

- `elb_connection_draining_enabled` (medium) — Classic Load Balancer has connection draining enabled
- `elb_cross_zone_load_balancing_enabled` (medium) — Classic Load Balancer has cross-zone load balancing enabled
- `elb_desync_mitigation_mode` (medium) — Classic Load Balancer desync mitigation mode is defensive or strictest
- `elb_insecure_ssl_ciphers` (medium) — Elastic Load Balancer HTTPS listeners, if present, use the ELBSecurityPolicy-TLS-1-2-2017-01 policy
- `elb_internet_facing` (medium) — Elastic Load Balancer is not internet-facing
- `elb_is_in_multiple_az` (medium) — Classic Load Balancer is in multiple Availability Zones
- `elb_logging_enabled` (medium) — Elastic Load Balancer has access logs to S3 configured
- `elb_ssl_listeners` (medium) — Elastic Load Balancer has only HTTPS or SSL listeners
- `elb_ssl_listeners_use_acm_certificate` (medium) — Classic Load Balancer HTTPS/SSL listeners use ACM-issued certificates

</details>

<details><summary><b>vpc</b> — 9 (3 high, 6 medium)</summary>

- `vpc_different_regions` (medium) — VPCs are present in more than one region
- `vpc_endpoint_connections_trust_boundaries` (high) — VPC endpoint policy allows access only from trusted AWS accounts
- `vpc_endpoint_for_ec2_enabled` (medium) — VPC has an Amazon EC2 VPC endpoint
- `vpc_endpoint_multi_az_enabled` (medium) — Amazon VPC interface endpoint has subnets in multiple Availability Zones
- `vpc_endpoint_services_allowed_principals_trust_boundaries` (high) — VPC endpoint service allows only trusted principals or none
- `vpc_subnet_different_az` (medium) — VPC has subnets in more than one Availability Zone
- `vpc_subnet_no_public_ip_by_default` (high) — VPC subnet does not assign public IP addresses by default
- `vpc_subnet_separate_private_public` (medium) — VPC has both public and private subnets
- `vpc_vpn_connection_tunnels_up` (medium) — AWS Site-to-Site VPN connection has both tunnels up

</details>

<details><summary><b>apigateway</b> — 8 (6 medium, 2 low)</summary>

- `apigateway_domain_name_pqc_tls_enabled` (low) — API Gateway custom domain names use a post-quantum TLS security policy
- `apigateway_restapi_authorizers_enabled` (medium) — API Gateway REST API has an authorizer at API level or all methods are authorized
- `apigateway_restapi_cache_encrypted` (medium) — API Gateway REST API stage cache data is encrypted at rest
- `apigateway_restapi_client_certificate_enabled` (medium) — API Gateway REST API stage has client certificate enabled
- `apigateway_restapi_public` (medium) — API Gateway REST API endpoint is private
- `apigateway_restapi_public_with_authorizer` (medium) — API Gateway REST API with a public endpoint has an authorizer configured
- `apigateway_restapi_tracing_enabled` (low) — API Gateway REST API stage has X-Ray tracing enabled
- `apigateway_restapi_waf_acl_attached` (medium) — API Gateway stage has a WAF Web ACL attached

</details>

<details><summary><b>eks</b> — 8 (5 high, 3 medium)</summary>

- `eks_cluster_deletion_protection_enabled` (high) — EKS cluster has deletion protection enabled
- `eks_cluster_kms_cmk_encryption_in_secrets_enabled` (medium) — EKS cluster has Kubernetes secrets encryption enabled
- `eks_cluster_network_policy_enabled` (high) — EKS cluster has network policy enabled
- `eks_cluster_not_publicly_accessible` (high) — EKS cluster endpoint is not publicly accessible from 0.0.0.0/0
- `eks_cluster_private_nodes_enabled` (high) — EKS cluster has private endpoint access enabled
- `eks_cluster_uses_a_supported_version` (high) — EKS cluster uses a supported Kubernetes version
- `eks_cluster_vpc_cni_network_policy_enforced` (medium) — EKS cluster enforces Kubernetes network policies through the Amazon VPC CNI add-on
- `eks_control_plane_logging_all_types_enabled` (medium) — EKS cluster has control plane logging enabled for api, audit, authenticator, controllerManager, and scheduler

</details>

<details><summary><b>elasticache</b> — 8 (2 high, 6 medium)</summary>

- `elasticache_cluster_uses_public_subnet` (medium) — ElastiCache cluster is not using public subnets
- `elasticache_redis_cluster_auto_minor_version_upgrades` (high) — ElastiCache Redis cache cluster has automatic minor version upgrades enabled
- `elasticache_redis_cluster_automatic_failover_enabled` (medium) — ElastiCache Redis cluster has automatic failover enabled
- `elasticache_redis_cluster_backup_enabled` (high) — ElastiCache Redis cache cluster has automated snapshot backups enabled with retention of at least 7 days
- `elasticache_redis_cluster_in_transit_encryption_enabled` (medium) — ElastiCache Redis cache cluster has in-transit encryption enabled
- `elasticache_redis_cluster_multi_az_enabled` (medium) — ElastiCache Redis replication group has Multi-AZ enabled
- `elasticache_redis_cluster_rest_encryption_enabled` (medium) — ElastiCache Redis cache cluster has at rest encryption enabled
- `elasticache_redis_replication_group_auth_enabled` (medium) — ElastiCache Redis replication group with engine version < 6.0 has Redis OSS AUTH enabled

</details>

<details><summary><b>kafka</b> — 8 (2 critical, 3 high, 3 medium)</summary>

- `kafka_cluster_encryption_at_rest_uses_cmk` (medium) — Kafka cluster has encryption at rest enabled with a customer managed key (CMK) or is serverless
- `kafka_cluster_enhanced_monitoring_enabled` (medium) — Amazon MSK cluster has enhanced monitoring enabled
- `kafka_cluster_in_transit_encryption_enabled` (high) — Kafka cluster has encryption in transit enabled
- `kafka_cluster_is_public` (critical) — Kafka cluster is not publicly accessible
- `kafka_cluster_mutual_tls_authentication_enabled` (high) — Kafka cluster has TLS authentication enabled
- `kafka_cluster_unrestricted_access_disabled` (critical) — Kafka cluster requires authentication
- `kafka_cluster_uses_latest_version` (medium) — MSK cluster uses the latest Kafka version or is serverless with AWS-managed version
- `kafka_connector_in_transit_encryption_enabled` (high) — MSK Connect connector has encryption in transit enabled

</details>

<details><summary><b>kms</b> — 8 (1 critical, 3 high, 3 medium, 1 low)</summary>

- `kms_cmk_are_used` (low) — KMS customer managed key is enabled or scheduled for deletion
- `kms_cmk_not_deleted_unintentionally` (critical) — AWS KMS customer managed key is not scheduled for deletion
- `kms_cmk_not_multi_region` (medium) — AWS KMS customer managed key is single-Region
- `kms_key_enclave_attestation_bypassable_path` (high) — KMS enclave key has no authorization path that bypasses attestation
- `kms_key_enclave_attestation_not_enforced` (high) — KMS enclave key requires kms:RecipientAttestation conditions on sensitive actions
- `kms_key_enclave_attestation_pcr_mismatch` (medium) — KMS enclave key attestation PCRs match customer-supplied golden values
- `kms_key_enclave_attestation_unknown_image` (medium) — No enclave with an unknown image identity has called this KMS key
- `kms_key_enclave_debug_attestation_detected` (high) — No Nitro Enclave debug-mode attestation observed against this KMS key

</details>

<details><summary><b>waf</b> — 8 (1 high, 7 medium)</summary>

- `waf_global_rule_with_conditions` (medium) — AWS WAF Classic Global rule has at least one condition
- `waf_global_rulegroup_not_empty` (high) — AWS WAF Classic global rule group has at least one rule
- `waf_global_webacl_logging_enabled` (medium) — AWS WAF Classic Global Web ACL has logging enabled
- `waf_global_webacl_with_rules` (medium) — AWS WAF Classic global Web ACL has at least one rule or rule group
- `waf_regional_rule_with_conditions` (medium) — AWS WAF Classic Regional rule has at least one condition
- `waf_regional_rulegroup_not_empty` (medium) — AWS WAF Classic Regional rule group has at least one rule
- `waf_regional_webacl_logging_enabled` (medium) — AWS WAF Classic Regional Web ACL has logging enabled
- `waf_regional_webacl_with_rules` (medium) — AWS WAF Classic Regional Web ACL has at least one rule or rule group

</details>

<details><summary><b>autoscaling</b> — 7 (2 high, 4 medium, 1 low)</summary>

- `autoscaling_group_capacity_rebalance_enabled` (medium) — Amazon EC2 Auto Scaling group has Capacity Rebalancing enabled
- `autoscaling_group_elb_health_check_enabled` (low) — Auto Scaling group associated with a load balancer has ELB health checks enabled
- `autoscaling_group_launch_configuration_no_public_ip` (high) — Auto Scaling group associated launch configuration does not assign a public IP address
- `autoscaling_group_launch_configuration_requires_imdsv2` (high) — Auto Scaling group enforces IMDSv2 or disables the instance metadata service
- `autoscaling_group_multiple_az` (medium) — Auto Scaling group uses multiple Availability Zones
- `autoscaling_group_multiple_instance_types` (medium) — Auto Scaling group spans multiple Availability Zones and has multiple instance types per Availability Zone
- `autoscaling_group_using_ec2_launch_template` (medium) — Amazon EC2 Auto Scaling group uses an EC2 launch template

</details>

<details><summary><b>cloudwatch</b> — 7 (3 high, 4 medium)</summary>

- `cloudwatch_alarm_actions_alarm_state_configured` (high) — CloudWatch metric alarm has actions configured for the ALARM state
- `cloudwatch_alarm_actions_enabled` (high) — CloudWatch metric alarm has actions enabled
- `cloudwatch_cross_account_sharing_disabled` (medium) — CloudWatch does not allow cross-account sharing
- `cloudwatch_log_group_agentcore_data_protection_policy_enabled` (medium) — Bedrock AgentCore log groups have a CloudWatch Logs data protection policy activated
- `cloudwatch_log_group_kms_encryption_enabled` (medium) — CloudWatch log group is encrypted with an AWS KMS key
- `cloudwatch_log_group_not_publicly_accessible` (high) — CloudWatch Log Group is not publicly accessible
- `cloudwatch_log_group_retention_policy_specific_days_enabled` (medium) — CloudWatch log group has a retention policy of at least the configured minimum days or never expires

</details>

<details><summary><b>ecr</b> — 7 (1 critical, 5 medium, 1 low)</summary>

- `ecr_registry_enhanced_scanning_enabled` (medium) — ECR registry has enhanced scanning enabled
- `ecr_registry_scan_images_on_push_enabled` (medium) — ECR registry has automated image scanning enabled for all repositories
- `ecr_repositories_lifecycle_policy_enabled` (low) — ECR repository has a lifecycle policy configured
- `ecr_repositories_not_publicly_accessible` (critical) — ECR repository is not publicly accessible
- `ecr_repositories_scan_images_on_push_enabled` (medium) — [DEPRECATED] ECR repository has image scanning on push enabled
- `ecr_repositories_scan_vulnerabilities_in_latest_image` (medium) — ECR repository latest image is scanned with no vulnerabilities at or above the configured minimum severity
- `ecr_repositories_tag_immutability` (medium) — ECR repository has image tag immutability enabled

</details>

<details><summary><b>inspector2</b> — 7 (1 critical, 2 high, 4 medium)</summary>

- `inspector2_active_findings_exist` (high) — Inspector2 is enabled with no active findings
- `inspector2_active_findings_kev_within_due_date` (critical) — Inspector2 has no active findings for CISA Known Exploited Vulnerabilities past their remediation due date
- `inspector2_active_findings_no_known_exploited_vulnerabilities` (high) — Inspector2 has no active findings for CISA Known Exploited Vulnerabilities
- `inspector2_active_findings_within_max_age` (medium) — Inspector2 has no active findings older than the configured maximum age
- `inspector2_coverage_recently_scanned` (medium) — Inspector2 covered resource was scanned within the configured number of days
- `inspector2_coverage_scan_status_active` (medium) — Inspector2 covered resource is actively scanned
- `inspector2_is_enabled` (medium) — Inspector2 is enabled for Amazon EC2 instances, ECR container images, Lambda functions, and Lambda code

</details>

<details><summary><b>networkfirewall</b> — 7 (5 high, 2 medium)</summary>

- `networkfirewall_deletion_protection` (medium) — Network Firewall has deletion protection enabled
- `networkfirewall_in_all_vpc` (medium) — VPC has Network Firewall enabled
- `networkfirewall_logging_enabled` (high) — Network Firewall has logging enabled
- `networkfirewall_multi_az` (high) — Network Firewall firewall is deployed across multiple Availability Zones
- `networkfirewall_policy_default_action_fragmented_packets` (high) — Network Firewall policy drops or forwards fragmented packets by default
- `networkfirewall_policy_default_action_full_packets` (high) — Network Firewall firewall policy default stateless action for full packets is drop or forward
- `networkfirewall_policy_rule_group_associated` (high) — Network Firewall policy has at least one rule group associated

</details>

<details><summary><b>cloudtrail</b> — 6 (1 critical, 2 medium, 3 low)</summary>

- `cloudtrail_bedrock_logging_enabled` (medium) — CloudTrail logs Amazon Bedrock API calls for security auditing
- `cloudtrail_bucket_requires_mfa_delete` (medium) — CloudTrail trail S3 bucket has MFA delete enabled
- `cloudtrail_cloudwatch_logging_enabled` (low) — CloudTrail trail has delivered logs to CloudWatch Logs in the last 24 hours
- `cloudtrail_insights_exist` (low) — CloudTrail trail has Insights enabled
- `cloudtrail_logs_s3_bucket_is_not_publicly_accessible` (critical) — CloudTrail trail S3 bucket is not publicly accessible
- `cloudtrail_multi_region_enabled_logging_management_events` (low) — CloudTrail trail logs management events for read and write operations

</details>

<details><summary><b>directoryservice</b> — 6 (5 medium, 1 low)</summary>

- `directoryservice_directory_log_forwarding_enabled` (medium) — Directory Service directory has log forwarding to CloudWatch Logs enabled
- `directoryservice_directory_monitor_notifications` (medium) — Directory Service directory has SNS notifications enabled
- `directoryservice_directory_snapshots_limit` (low) — Directory Service directory has adequate remaining manual snapshot quota
- `directoryservice_ldap_certificate_expiration` (medium) — Directory Service LDAP certificate expires in more than 90 days
- `directoryservice_radius_server_security_protocol` (medium) — Directory Service directory RADIUS server uses MS-CHAPv2
- `directoryservice_supported_mfa_radius_enabled` (medium) — AWS Directory Service directory has RADIUS-based MFA enabled

</details>

<details><summary><b>documentdb</b> — 6 (1 critical, 5 medium)</summary>

- `documentdb_cluster_backup_enabled` (medium) — DocumentDB cluster has automated backups enabled with retention period of at least 7 days
- `documentdb_cluster_cloudwatch_log_export` (medium) — DocumentDB cluster exports audit and profiler logs to CloudWatch Logs
- `documentdb_cluster_deletion_protection` (medium) — DocumentDB cluster has deletion protection enabled
- `documentdb_cluster_multi_az_enabled` (medium) — DocumentDB cluster has Multi-AZ enabled
- `documentdb_cluster_public_snapshot` (critical) — DocumentDB manual cluster snapshot is not shared publicly
- `documentdb_cluster_storage_encrypted` (medium) — DocumentDB cluster storage is encrypted at rest

</details>

<details><summary><b>efs</b> — 6 (6 medium)</summary>

- `efs_access_point_enforce_root_directory` (medium) — EFS file system has no access points allowing access to the root directory
- `efs_access_point_enforce_user_identity` (medium) — EFS file system has all access points with a defined POSIX user
- `efs_have_backup_enabled` (medium) — EFS file system has backup enabled
- `efs_mount_target_not_publicly_accessible` (medium) — EFS file system has no publicly accessible mount targets
- `efs_multi_az_enabled` (medium) — EFS file system is Multi-AZ with more than one mount target
- `efs_not_publicly_accessible` (medium) — EFS file system policy does not allow access to any client within the VPC

</details>

<details><summary><b>shield</b> — 6 (6 medium)</summary>

- `shield_advanced_protection_in_associated_elastic_ips` (medium) — Elastic IP address is protected by AWS Shield Advanced
- `shield_advanced_protection_in_classic_load_balancers` (medium) — Classic Load Balancer is protected by AWS Shield Advanced
- `shield_advanced_protection_in_cloudfront_distributions` (medium) — CloudFront distribution is protected by AWS Shield Advanced
- `shield_advanced_protection_in_global_accelerators` (medium) — Global Accelerator accelerator is protected by AWS Shield Advanced
- `shield_advanced_protection_in_internet_facing_load_balancers` (medium) — Internet-facing Application Load Balancer is protected by AWS Shield Advanced
- `shield_advanced_protection_in_route53_hosted_zones` (medium) — Route53 hosted zone is protected by AWS Shield Advanced

</details>

<details><summary><b>backup</b> — 5 (2 medium, 3 low)</summary>

- `backup_plans_exist` (low) — At least one AWS Backup plan exists
- `backup_recovery_point_encrypted` (medium) — AWS Backup recovery point is encrypted at rest
- `backup_reportplans_exist` (low) — At least one AWS Backup report plan exists
- `backup_vaults_encrypted` (medium) — AWS Backup vault is encrypted at rest
- `backup_vaults_exist` (low) — At least one AWS Backup vault exists

</details>

<details><summary><b>mq</b> — 5 (1 high, 1 medium, 3 low)</summary>

- `mq_broker_active_deployment_mode` (low) — Apache ActiveMQ broker is configured in active/standby Multi-AZ deployment mode
- `mq_broker_auto_minor_version_upgrades` (low) — Amazon MQ broker has automated minor version upgrades enabled
- `mq_broker_cluster_deployment_mode` (medium) — MQ RabbitMQ broker has cluster (multi-AZ) deployment mode
- `mq_broker_logging_enabled` (low) — MQ broker has general logging enabled and, for ActiveMQ, audit logging enabled
- `mq_broker_not_publicly_accessible` (high) — Amazon MQ broker is not publicly accessible

</details>

<details><summary><b>appstream</b> — 4 (4 medium)</summary>

- `appstream_fleet_default_internet_access_disabled` (medium) — AppStream fleet has default internet access disabled
- `appstream_fleet_maximum_session_duration` (medium) — AppStream fleet maximum user session duration is less than 10 hours
- `appstream_fleet_session_disconnect_timeout` (medium) — AppStream fleet session disconnect timeout is 5 minutes or less
- `appstream_fleet_session_idle_disconnect_timeout` (medium) — AppStream fleet session idle disconnect timeout is 10 minutes or less

</details>

<details><summary><b>lightsail</b> — 4 (2 high, 1 medium, 1 low)</summary>

- `lightsail_database_public` (high) — Lightsail database public access disabled
- `lightsail_instance_automated_snapshots` (medium) — Lightsail instance has automated snapshots enabled
- `lightsail_instance_public` (high) — Lightsail instance has no publicly accessible ports
- `lightsail_static_ip_unused` (low) — Lightsail static IP is associated with an instance

</details>

<details><summary><b>organizations</b> — 4 (1 high, 2 medium, 1 low)</summary>

- `organizations_account_part_of_organizations` (medium) — AWS account is a member of an active AWS Organization
- `organizations_opt_out_ai_services_policy` (medium) — AWS Organization has opted out of all AI services and child accounts cannot override the policy
- `organizations_scp_check_deny_regions` (high) — AWS Organization restricts operations to only the configured AWS Regions with SCP policies
- `organizations_tags_policies_enabled_and_attached` (low) — AWS Organization has tag policies enabled and attached

</details>

<details><summary><b>route53</b> — 4 (2 high, 2 medium)</summary>

- `route53_dangling_ip_subdomain_takeover` (high) — Route53 record does not point to a dangling AWS resource
- `route53_domains_privacy_protection_enabled` (medium) — Route 53 domain has admin contact privacy protection enabled
- `route53_domains_transferlock_enabled` (high) — Route 53 domain has Transfer Lock enabled
- `route53_public_hosted_zones_cloudwatch_logging_enabled` (medium) — Route53 public hosted zone has query logging enabled to a CloudWatch Logs log group

</details>

<details><summary><b>secretsmanager</b> — 4 (2 high, 2 medium)</summary>

- `secretsmanager_automatic_rotation_enabled` (high) — Secrets Manager secret has rotation enabled
- `secretsmanager_has_restrictive_resource_policy` (high) — Secrets Manager secret has a restrictive resource-based policy
- `secretsmanager_secret_rotated_periodically` (medium) — AWS Secrets Manager secret is rotated within the configured maximum number of days
- `secretsmanager_secret_unused` (medium) — Secrets Manager secret has been accessed within the last 90 days

</details>

<details><summary><b>acm</b> — 3 (2 high, 1 medium)</summary>

- `acm_certificates_expiration_check` (high) — ACM certificate expires in more than the configured threshold of days
- `acm_certificates_transparency_logs_enabled` (medium) — ACM certificate is imported or has Certificate Transparency logging enabled
- `acm_certificates_with_secure_key_algorithms` (high) — ACM certificate uses a secure key algorithm

</details>

<details><summary><b>athena</b> — 3 (3 medium)</summary>

- `athena_workgroup_encryption` (medium) — Athena workgroup encrypts query results in S3 with server-side encryption
- `athena_workgroup_enforce_configuration` (medium) — Athena workgroup enforces workgroup configuration and cannot be overridden by client-side settings
- `athena_workgroup_logging_enabled` (medium) — Amazon Athena workgroup has CloudWatch logging enabled

</details>

<details><summary><b>elasticbeanstalk</b> — 3 (2 high, 1 low)</summary>

- `elasticbeanstalk_environment_cloudwatch_logging_enabled` (high) — Elastic Beanstalk environment streams logs to CloudWatch Logs
- `elasticbeanstalk_environment_enhanced_health_reporting` (low) — Elastic Beanstalk environment has enhanced health reporting enabled
- `elasticbeanstalk_environment_managed_updates_enabled` (high) — Elastic Beanstalk environment has managed platform updates enabled

</details>

<details><summary><b>emr</b> — 3 (1 high, 2 medium)</summary>

- `emr_cluster_account_public_block_enabled` (high) — EMR account has Block Public Access enabled
- `emr_cluster_master_nodes_no_public_ip` (medium) — EMR Cluster without Public IP.
- `emr_cluster_publicly_accesible` (medium) — EMR cluster is not publicly accessible

</details>

<details><summary><b>eventbridge</b> — 3 (2 high, 1 medium)</summary>

- `eventbridge_bus_cross_account_access` (high) — AWS EventBridge event bus does not allow cross-account access
- `eventbridge_global_endpoint_event_replication_enabled` (medium) — EventBridge global endpoint has event replication enabled
- `eventbridge_schema_registry_cross_account_access` (high) — AWS EventBridge schema registry does not allow cross-account access

</details>

<details><summary><b>fsx</b> — 3 (3 low)</summary>

- `fsx_file_system_copy_tags_to_backups_enabled` (low) — FSx file system has copy tags to backups enabled
- `fsx_file_system_copy_tags_to_volumes_enabled` (low) — FSx file system has copy tags to volumes enabled
- `fsx_windows_file_system_multi_az_enabled` (low) — FSx Windows file system is configured for Multi-AZ deployment

</details>

<details><summary><b>transfer</b> — 3 (1 high, 2 low)</summary>

- `transfer_server_fips_security_policy_enabled` (low) — AWS Transfer Family server uses a FIPS security policy
- `transfer_server_in_transit_encryption_enabled` (high) — Transfer Family server has encryption in transit enabled
- `transfer_server_pqc_ssh_kex_enabled` (low) — AWS Transfer Family server uses a post-quantum hybrid SSH key exchange security policy

</details>

<details><summary><b>wafv2</b> — 3 (1 high, 2 medium)</summary>

- `wafv2_webacl_logging_enabled` (medium) — AWS WAFv2 Web ACL has logging enabled
- `wafv2_webacl_rule_logging_enabled` (medium) — AWS WAFv2 Web ACL has Amazon CloudWatch metrics enabled for all rules and rule groups
- `wafv2_webacl_with_rules` (high) — AWS WAFv2 Web ACL has at least one rule or rule group attached

</details>

<details><summary><b>account</b> — 2 (2 medium)</summary>

- `account_maintain_different_contact_details_to_security_billing_and_operations` (medium) — AWS account has distinct Security, Billing, and Operations contact details, different from each other and from the root contact
- `account_security_questions_are_registered_in_the_aws_account` (medium) — [DEPRECATED] AWS root user has security challenge questions configured

</details>

<details><summary><b>appsync</b> — 2 (1 high, 1 medium)</summary>

- `appsync_field_level_logging_enabled` (medium) — AWS AppSync API has field-level logging set to ALL or ERROR
- `appsync_graphql_api_no_api_key_authentication` (high) — AWS AppSync GraphQL API does not use API key authentication

</details>

<details><summary><b>cloudformation</b> — 2 (1 high, 1 medium)</summary>

- `cloudformation_stack_cdktoolkit_bootstrap_version` (high) — CDKToolkit CloudFormation stack has Bootstrap version 21 or higher
- `cloudformation_stacks_termination_protection_enabled` (medium) — CloudFormation stack has termination protection enabled

</details>

<details><summary><b>config</b> — 2 (1 high, 1 medium)</summary>

- `config_delegated_admin_and_org_aggregator_all_regions` (high) — AWS Config has a delegated administrator and an organization aggregator covering all AWS regions
- `config_recorder_using_aws_service_role` (medium) — AWS Config recorder uses the AWSServiceRoleForConfig service-linked role

</details>

<details><summary><b>directconnect</b> — 2 (2 medium)</summary>

- `directconnect_connection_redundancy` (medium) — Direct Connect connections span at least two locations per region
- `directconnect_virtual_interface_redundancy` (medium) — Direct Connect gateway or virtual private gateway has at least two virtual interfaces on different Direct Connect connections

</details>

<details><summary><b>kinesis</b> — 2 (1 high, 1 medium)</summary>

- `kinesis_stream_data_retention_period` (medium) — Kinesis stream retains data for at least the required minimum hours
- `kinesis_stream_encrypted_at_rest` (high) — Kinesis stream is encrypted at rest with KMS

</details>

<details><summary><b>memorydb</b> — 2 (2 medium)</summary>

- `memorydb_cluster_auto_minor_version_upgrades` (medium) — MemoryDB cluster has automatic minor version upgrades enabled
- `memorydb_cluster_in_transit_encryption_enabled` (medium) — MemoryDB cluster has in-transit encryption enabled

</details>

<details><summary><b>rolesanywhere</b> — 2 (1 medium, 1 low)</summary>

- `rolesanywhere_profile_restricts_session_permissions` (medium) — IAM Roles Anywhere profiles scope down the vended session permissions
- `rolesanywhere_trust_anchor_pqc_pki` (low) — IAM Roles Anywhere trust anchors are backed by a post-quantum (ML-DSA) PKI

</details>

<details><summary><b>ses</b> — 2 (1 high, 1 medium)</summary>

- `ses_identity_dkim_enabled` (medium) — SES identity has DKIM signing enabled
- `ses_identity_not_publicly_accessible` (high) — SES identity resource policy does not allow public access

</details>

<details><summary><b>sns</b> — 2 (2 high)</summary>

- `sns_subscription_not_using_http_endpoints` (high) — SNS subscription uses an HTTPS endpoint
- `sns_topics_kms_encryption_at_rest_enabled` (high) — SNS topic is encrypted at rest with KMS

</details>

<details><summary><b>ssm</b> — 2 (2 high)</summary>

- `ssm_documents_set_as_public` (high) — SSM document is not public and shared only with trusted AWS accounts
- `ssm_managed_compliant_patching` (high) — EC2 managed instance is compliant with Systems Manager patching requirements

</details>

<details><summary><b>stepfunctions</b> — 2 (2 medium)</summary>

- `stepfunctions_statemachine_encrypted_with_cmk` (medium) — Step Functions state machine is encrypted at rest with a customer-managed KMS key
- `stepfunctions_statemachine_logging_enabled` (medium) — Step Functions state machine has logging enabled

</details>

<details><summary><b>storagegateway</b> — 2 (2 medium)</summary>

- `storagegateway_fileshare_encryption_enabled` (medium) — Storage Gateway file share is encrypted with KMS CMK
- `storagegateway_gateway_fault_tolerant` (medium) — AWS Storage Gateway gateway is not hosted on EC2

</details>

<details><summary><b>trustedadvisor</b> — 2 (1 medium, 1 low)</summary>

- `trustedadvisor_errors_and_warnings` (medium) — Trusted Advisor check has no errors or warnings
- `trustedadvisor_premium_support_plan_subscribed` (low) — AWS account is subscribed to an AWS Premium Support plan

</details>

<details><summary><b>workspaces</b> — 2 (2 high)</summary>

- `workspaces_volume_encryption_enabled` (high) — Amazon WorkSpaces workspace root and user volumes are encrypted
- `workspaces_vpc_2private_1public_subnets_nat` (high) — Workspace is in a private subnet and its VPC has at least 1 public subnet, 2 private subnets, and a NAT Gateway

</details>

<details><summary><b>accessanalyzer</b> — 1 (1 low)</summary>

- `accessanalyzer_enabled_without_findings` (low) — IAM Access Analyzer analyzer is active and has no active findings

</details>

<details><summary><b>acmpca</b> — 1 (1 low)</summary>

- `acmpca_certificate_authority_pqc_key_algorithm` (low) — AWS Private CA certificate authorities use a post-quantum (ML-DSA) key algorithm

</details>

<details><summary><b>apigatewayv2</b> — 1 (1 medium)</summary>

- `apigatewayv2_api_authorizers_enabled` (medium) — API Gateway V2 API has an authorizer configured

</details>

<details><summary><b>codeartifact</b> — 1 (1 critical)</summary>

- `codeartifact_packages_external_public_publishing_disabled` (critical) — Internal CodeArtifact package does not allow publishing versions already present in external public sources

</details>

<details><summary><b>codepipeline</b> — 1 (1 medium)</summary>

- `codepipeline_project_repo_private` (medium) — CodePipeline pipeline should use private repository source with authenticated connection

</details>

<details><summary><b>datasync</b> — 1 (1 high)</summary>

- `datasync_task_logging_enabled` (high) — DataSync task has CloudWatch Logs log group configured for logging

</details>

<details><summary><b>dlm</b> — 1 (1 medium)</summary>

- `dlm_ebs_snapshot_lifecycle_policy_exists` (medium) — Region with EBS snapshots has at least one EBS snapshot lifecycle policy defined

</details>

<details><summary><b>drs</b> — 1 (1 medium)</summary>

- `drs_job_exist` (medium) — Region has AWS Elastic Disaster Recovery (DRS) enabled with at least one recovery job

</details>

<details><summary><b>firehose</b> — 1 (1 medium)</summary>

- `firehose_stream_encrypted_at_rest` (medium) — Kinesis Data Firehose delivery stream is encrypted at rest

</details>

<details><summary><b>fms</b> — 1 (1 medium)</summary>

- `fms_policy_compliant` (medium) — All AWS FMS policies in the admin account are compliant for all accounts

</details>

<details><summary><b>macie</b> — 1 (1 high)</summary>

- `macie_automated_sensitive_data_discovery_enabled` (high) — Macie automated sensitive data discovery is enabled

</details>

<details><summary><b>resourceexplorer2</b> — 1 (1 low)</summary>

- `resourceexplorer2_indexes_found` (low) — Resource Explorer indexes exist

</details>

<details><summary><b>securityhub</b> — 1 (1 high)</summary>

- `securityhub_delegated_admin_enabled_all_regions` (high) — Security Hub has delegated admin configured and is enabled in all regions with organization auto-enable

</details>

<details><summary><b>servicecatalog</b> — 1 (1 high)</summary>

- `servicecatalog_portfolio_shared_within_organization_only` (high) — Service Catalog portfolio is shared only within the AWS Organization

</details>

<details><summary><b>sqs</b> — 1 (1 medium)</summary>

- `sqs_queues_server_side_encryption_enabled` (medium) — SQS queue has server-side encryption enabled

</details>

<details><summary><b>ssmincidents</b> — 1 (1 medium)</summary>

- `ssmincidents_enabled_with_plans` (medium) — SSM Incidents replication set is ACTIVE and has at least one response plan

</details>

<details><summary><b>wellarchitected</b> — 1 (1 medium)</summary>

- `wellarchitected_workload_no_high_or_medium_risks` (medium) — AWS Well-Architected Tool workload has no high or medium risks

</details>

## Never to be ported (31)

Checks the second engine excluded on purpose, with the reason it gave. Most hold for a native rule just the same; read the reason again before porting one. Six filed here under "reads activity records" read configuration instead -- the AKS Defender profile, Defender CSPM, and four Cognito user pool settings -- and were ported in section 177.

- Scans the contents of code, environment variables, user data or logs for secrets. Cleave never reads secret material, so it neither asks for the permission nor stores what such a check would print. `amplify_app_no_secrets_in_environment`, `apigateway_restapi_no_secrets_in_stage_variables`, `autoscaling_find_secrets_ec2_launch_configuration`, `awslambda_function_no_secrets_in_code`, `awslambda_function_no_secrets_in_variables`, `awslambda_layer_no_secrets_in_content`, `batch_job_definition_no_secrets`, `cloudformation_stack_outputs_find_secrets`, `cloudwatch_log_group_no_secrets_in_logs`, `codebuild_project_no_secrets_in_variables`, `codecommit_repository_no_secrets`, `datapipeline_pipeline_no_secrets_in_definition`, `ec2_instance_secrets_user_data`, `ec2_launch_template_no_secrets`, `ecr_repository_image_no_secrets`, `ecs_task_definitions_no_environment_secrets`, `elasticbeanstalk_environment_no_secrets_in_configuration`, `glue_catalog_connection_no_secrets`, `glue_etl_jobs_no_secrets_in_arguments`, `sagemaker_notebook_instance_no_secrets`, `ssm_document_secrets`, `stepfunctions_statemachine_no_secrets_in_definition`
- Reads activity records (sign-ins, API calls, log contents) rather than configuration. Cleave assesses posture and does not ingest a customer's event stream. `cloudtrail_threat_detection_enumeration`, `cloudtrail_threat_detection_llm_jacking`, `cloudtrail_threat_detection_privilege_escalation`
- Queries the customer's log contents rather than reading configuration. `apim_threat_detection_llm_jacking`
- Needs Microsoft.Web/sites/host/listkeys/action, which returns the function keys themselves. The scanner holds Reader and no list-keys action. `app_function_access_keys_configured`
- Informational: Prowler reports it without saying anything is wrong. `kms_key_enclave_attestation_no_deployment_binding`
- Sends the customer's public IP addresses to Shodan, a third party, and needs an API key of its own. `network_public_ip_shodan`
- Judges against a list of approved sizes the customer has not given Cleave; with Prowler's empty default every machine fails. `vm_desired_sku_size`
- Judges against a list of approved images the customer has not given Cleave; with Prowler's empty default every machine fails. `vm_ensure_using_approved_images`
