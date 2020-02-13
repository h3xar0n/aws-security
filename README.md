# AWS Security Grindfest

- [Data Protection](#data-protection)
- [Incident Response](#incident-response)
- [Infrastructure Security](#infrastructure-security)
- [Identity and Access Management](#identity-and-access-management)
- [Logging and Monitoring](#logging-and-monitoring)
- [Next Up](#next-up)
- [Attempt Log](#attempt-log)

## Data Protection

### AWS KMS
#### CMK
- Imported key material
  - Automatic key rotation is not available for CMKs that have imported key material, you will need to do this manually.
- Customer managed keys
  - A customer managed CMK supports automatic key rotation once per year. 
  - Creating and managing your own CMK gives you more flexibility, including the ability to create, rotate, disable, and define access controls, and to audit the encryption keys used to protect your data. 
- AWS managed keys 
  - AWS managed keys automatically rotate once every three years.

### AWS Systems Manager 
#### Parameter Store
- Services that support parameter store:
  - Amazon EC2
  - Amazon ECS
  - AWS Lambda
  - AWS CloudFormation
  - AWS CodeBuild
  - AWS CodeDeploy
- Configure integration with the following AWS services for encryption, notification, monitoring, and auditing:
  - AWS KMS
  - Amazon SNS
  - Amazon CloudWatch
  - AWS CloudTrail
- If a service does not directly support it (e.g., RDS), just **use Lambda in association with the service**

### AWS Direct Connect
- With AWS Direct Connect plus VPN, you can combine one or more AWS Direct Connect dedicated network connections with the Amazon VPC VPN. 
- This combination provides an IPsec-encrypted private connection that also reduces network costs, increases bandwidth throughput, and provides a more consistent network experience than internet-based VPN connections.

### AWS ElastiCache
- Supports encryption only for Redis 3.2.6, 4.0.10 and later, not Memcached.

## Incident Response

### AWS IAM
#### Account Compromise
- If you suspect that your account is compromised, do the following:
  - Change your AWS account root user password.
  - Rotate and delete all root and AWS Identity and Access Management (IAM) access keys.
  - Delete any potentially compromised IAM users, and change the password for all other IAM users.
  - Delete any resources on your account you didn't create, such as EC2 instances and AMIs, EBS volumes and snapshots, and IAM users.
  - Respond to any notifications you received from AWS Support through the AWS Support Center.

### AWS VPC
- VPC Flow Logs enables you to capture information about the IP traffic going to and from network interfaces in your VPC. 
- Flow logs can help you with a number of tasks:
  - Diagnosing overly restrictive security group rules
  - Monitoring the traffic that is reaching your instance
  - Determining the direction of the traffic to and from the network interfaces
  - Aiding in investigating suspicius traffic

### AWS CloudTrail
- CloudTrail provides event history of your AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, command line tools, and other AWS services.
- It is recommended to use a dedicated S3 bucket for CloudTrail logs. 
#### Multiple accounts
- Within an AWS Organization, you can create one CloudTrail to cover all accounts.
#### Data events
- Data events provide insight into the resource operations performed on or within a resource, these events are often high-volume activities. 
- Example data events include S3 object-level API activity and Lambda function execution activity, the Invoke API. 
- Data events are disabled by default when you create a trail. 
- To record CloudTrail data events, you must explicitly add the supported resources or resource types for which you want to collect activity to a trail.
#### Regions
- When you apply a trail to all regions, CloudTrail uses the trail that you create in a particular region to create trails with identical configurations in all other regions in your account. 
#### Integrity
- To determine whether a log file was modified, deleted, or unchanged after CloudTrail delivered it, you can use CloudTrail log file integrity validation.

### AWS CloudWatch
- You can use Amazon CloudWatch Logs to monitor, store, and access your log files from EC2 instances, AWS CloudTrail, Route 53, and other sources. 
- You can then retrieve the associated log data from CloudWatch Logs. 
- CloudWatch alone lacks the business rules that are provided with GuardDuty to create an event whenever malicious or unauthorized behavior is observed.
- If an anomaly is detect, CloudWatch Event can trigger a Lambda.

### AWS GuardDuty
- It is a managed service that can watch CloudTrail, VPC Flow Logs and DNS Logs, watching for malicious activity. 
- It can detect instances attempting to communicate with a command and control server.
- It has a build-in list of suspect IP addresses and you can also upload your own lists of IPs.
- GuardDuty can trigger CloudWatch events which can then be used for a variety of activities like notifications or automatically responding to a threat.

### AWS EC2
- If you connect to your instance using SSH and get any of the following errors, "Host key not found in `[directory]`", "Permission denied (publickey)", or "Authentication failed, permission denied", verify that you are connecting with the appropriate user name for your AMI *and* that you have specified the proper private key (.pem) file for your instance.

## Infrastructure Security

### AWS Systems Manager 
#### Patch Manager
- The default predefined patch baseline for Windows servers in Patch Manager is `AWS-DefaultPatchBaseline`.

### AWS Marketplace
#### IDS/IPS
- AWS GuardDuty is not an IDS. While it does perform _threat_ detection based on logs, it does not detect _intrusion_. 
- AWS Shield is not an IPS. It mitigates DDoS attacks, but it does not prevent intrusion.
- AWS acknowledge that they do not provide IPS/IDS. 
  - Instead they suggest that third-party software can be used to provide additional functionality such as deep packet inspection, IPS/IDS, or network threat protection. 
  - Search for IPS on AWS Marketplace and you will find a range of suitable products!

### Amazon Cloudfront
#### Encryption in transit
- End-to-end encryption _between_ a user and S3 entails using TLS; it does not entail server-side encryption (SSE) for S3, which is encryption at rest.

### AWS Trusted Advisor
- Checks security groups for rules that allow unrestricted access (0.0.0.0/0) to specific ports such as SSH. 
  - Unrestricted access increases opportunities for malicious activity (hacking, denial-of-service attacks, loss of data). 
  - The ports with highest risk are flagged red, and those with less risk are flagged yellow. 
  - Ports flagged green are typically used by applications that require unrestricted access, such as HTTP and SMTP.
- AWS Config can alert you to any modifications to a security group but will not perform a check for unrestricted access.
- Running a manual check or a full penetration test is not an efficient way to get this information.

### Amazon Virtual Private Cloud
#### DNS servers
- By default, AWS provides the Amazon DNS server. 
- To use your own DNS server you can create a new set of DHCP options for your VPC. 
- The default DHCP option set specifies AmazonProvidedDNS but you can provide the IP address of up to 4 of your own DNS servers. 
- You cannot update the existing option set, you must delete it and create a new one.
#### Security groups
- Security groups are stateful, if you have allowed the inbound traffic you do not need to create a rule to allow the outbound reply. 
- By default an SG allows any outbound traffic so you don't need to add an outbound rule to a server in a public subnet.

### Amazon EC2
If you lose the private key for an EBS-backed instance, you can regain access to your instance. You must: 
1. stop the instance, 
2. detach its root volume and attach it to another instance as a data volume, 
3. modify the `authorized_keys` file, 
4. move the volume back to the original instance, and 
5. restart the instance.

## Identity and Access Management

### AWS IAM
#### Policy evaluation logic
1. The AWS service receives the request
2. AWS first authenticates the principal.
    - Except for services such as S3 that allow anonymous access). 
3. Next, AWS determines which policy to apply to the request. 
    - Actions (or operations) – The actions or operations that the principal wants to perform.
    - Resources – The AWS resource object upon which the actions or operations are performed.
    - Principal – The user, role, federated user, or application that sent the request. Information about the principal includes the policies that are associated with that principal.
    - Environment data – Information about the IP address, user agent, SSL enabled status, or the time of day.
    - Resource data – Data related to the resource that is being requested. This can include information such as a DynamoDB table name or a tag on an Amazon EC2 instance.
4. Then, AWS evaluates the policy types and arranges an order of evaluation. 
    - Identity-based policies
    - Resource-based policies
    - IAM permissions boundaries
    - AWS Organizations service control policies (SCPs)
    - Session policies (e.g. for federated user sessions)
5. Finally, AWS then processes the policies against the request context to determine if it is allowed.

![Policy Evaluation Diagram](PolicyEvaluationHorizontal.png)

### AWS KMS
#### Parameter Store
- Parameter Store uses KMS customer master keys to encrypt the parameter values when you create or change them.
- An instance role needs permission both to read an SSM parameter and to use KMS to decrypt it.

## Logging and Monitoring

### AWS Lambda
- For Lambda to send logs to CloudWatch, the function execution role needs to permission to write to CloudWatch.

### CloudWatch
#### CloudWatch Logs
- You can use Amazon CloudWatch Logs to monitor, store, and access your log files from EC2 instances, AWS CloudTrail, Route 53, and other sources. 
- You can then retrieve the associated log data from CloudWatch Logs.
#### CloudWatch Events
- You can use CloudWatch Events to schedule automated actions that self-trigger at certain times using cron or rate expressions.
- You can configure Amazon Inspector as a target for CloudWatch Events. 

### Amazon Inspector
- The runtime behavior package checks for insecure protocols like Telnet, FTP, HTTP, IMAP, rlogin etc. 
- Neither the AWS Config restricted-common-ports check or Trusted Advisor will give you this information.

### AWS CloudTrail
- CloudTrail provides event history of your AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, command line tools, and other AWS services.
- Management and Data events are handled by separate CloudTrails. 
  - You should log the events to separate buckets, then configure access to the CloudTrail and read only access to the S3 bucket using an IAM policy attached to the user or group. 
  - Give each class of user only the access they need.

## Next Up
- [ ] Restructure notes under services
- [ ] Create diagram for policy evaluation
- [ ] Distinguish Inspector, GuardDuty, Config, and Trusted Advisor with table or diagram
  - [ ] [Backdoor Finding](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html)
  - [ ] [Trusted Advisor](https://aws.amazon.com/premiumsupport/technology/trusted-advisor/)
  - [ ] [Amazon Inspector FAQ](https://aws.amazon.com/inspector/faqs/)
  - [ ] [GuardDuty FAQ](https://aws.amazon.com/guardduty/faqs/)
  - [ ] [How Config Works](https://docs.aws.amazon.com/config/latest/developerguide/how-does-config-work.html)
- [ ] Distinguish CloudTrail, CloudWatch, and VPC Flow Logs with table or diagram
  - [ ] [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
  - [ ] [CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
  - [ ] [CloudTrail 2](https://aws.amazon.com/cloudtrail/)
  - [ ] [CloudTrail FAQ](https://aws.amazon.com/cloudtrail/faqs/)
  - [ ] [CloudTrail Integrity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
  - [ ] [CloudTrail for Orgs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html)
  - [ ] [Athena x CloudTrail](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
  - [ ] [Permissions for CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/control-user-permissions-for-cloudtrail.html)
  - [ ] [Encryption CloudTrail Log Files](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html)
  - [ ] [CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html)
  - [ ] [CloudWatch Agent](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html)
  - [ ] [CloudWatch Agent x IAM](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/create-iam-roles-for-cloudwatch-agent.html)
- [ ] Create diagrams or mnemonics and >=3 bullet points for special cases:
  - [ ] [AWS Direct Connect Plus VPN](https://docs.aws.amazon.com/whitepapers/latest/aws-vpc-connectivity-options/aws-direct-connect-plus-vpn-network-to-amazon.html)
  - [ ] [SSM Parameter Store](https://docs.aws.amazon.com/kms/latest/developerguide/services-parameter-store.html)
  - [ ] [Lambda Access to DynamoDB](https://aws.amazon.com/blogs/security/how-to-create-an-aws-iam-policy-to-grant-aws-lambda-access-to-an-amazon-dynamodb-table/)
  - [ ] [DDoS Whitepaper](https://d1.awsstatic.com/whitepapers/Security/DDoS_White_Paper.pdf)
  - [ ] [Troubleshooting EC2 Connection](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/TroubleshootingInstancesConnecting.html)
- [ ] Create diagrams or mnemonics and >=1 bullet point for other cases:
  - [ ] [Secrets Manager And Resource Based Policies](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-based-policies.html)
  - [ ] [Rotating Secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)
  - [ ] [KMS Grants](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html)
  - [ ] [EBS Encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
  - [ ] [SSE-S3](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html)
  - [ ] [SSE](https://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html)
  - [ ] [Memcached vs Redis](https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/SelectEngine.html)
  - [ ] [ASFS](https://aws.amazon.com/blogs/security/aws-federated-authentication-with-active-directory-federation-services-ad-fs/)
  - [ ] [Lambda Invocation Modes](https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventsourcemapping.html)
  - [ ] [Custom Origins](https://aws.amazon.com/premiumsupport/knowledge-center/custom-origin-cloudfront-fails/)
  - [ ] [HTTPS Requirements](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html#https-requirements-aws-region)
  - [ ] [VPC DNS](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html)
- [ ] Attempt 3 (target: >80%)

## Attempt Log
1. 65%
2. 77%
3. 

(>90% needed to take official practice)
