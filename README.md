# AWS Security Grindfest

- [AWS Trusted Advisor](#aws-trusted-advisor)
- [AWS Config](#aws-config)
- [Amazon Inspector](#amazon-inspector)
- [AWS GuardDuty](#aws-guardduty)
- [AWS VPC](#aws-vpc)
- [AWS KMS](#aws-kms)
- [AWS Systems Manager](#aws-systems-manager)
- [AWS Direct Connect](#aws-direct-connect)
- [AWS ElastiCache](#aws-elasticache)
- [AWS IAM](#aws-iam)
- [AWS CloudTrail](#aws-cloudtrail)
- [AWS CloudWatch](#aws-cloudwatch)
- [AWS EC2](#aws-ec2)
- [Attempt Log](#attempt-log)
- [AWS Marketplace](#aws-marketplace)
- [Amazon Cloudfront](#amazon-cloudfront)
- [AWS Lambda](#aws-lambda)
- [Test Ideas](#test-ideas)
- [Next Up](#next-up)
- [Attempt Log](#attempt-log)

## AWS Trusted Advisor
- Checks Security Groups for rules that allow unrestricted access (0.0.0.0/0) to specific ports such as SSH. 
  - Unrestricted access increases opportunities for malicious activity (hacking, denial-of-service attacks, loss of data). 
    - [AWS Config](#aws-config) can alert you to any _modifications_ to a Security Group but out of the box, it will not perform a check for _unrestricted access_.
  - The ports with highest risk are flagged red, and those with less risk are flagged yellow. 
  - Ports flagged green are typically used by applications that require unrestricted access, such as HTTP and SMTP.
- Running a manual check or a full penetration test is not an efficient way to get this information.
- Other core best practice checks:
  - S3 Bucket Permissions
  - IAM Use
  - MFA on Root Account
  - EBS Public Snapshots
  - RDS Public Snapshots
- For customizable tracking, use [AWS Config](#aws-config)

## AWS Config
Config reads CloudTrail logs and does two things: 
1. It creates a timeline of changes made to tracked resources (so you can see how a resource like an S3 bucket has been modified over time), and
2. It allows you to create rules to detect whether your environment is in compliance with certain policies (e.g. all your EBS volumes are encrypted). 
You can send notifications or take automated action with Lambda when a resource violates a rule.

![How Config Works](how-AWSconfig-works.png)

## Amazon Inspector
- The runtime behavior package checks for insecure protocols like Telnet, FTP, HTTP, IMAP, rlogin etc. 
- Neither the AWS Config restricted-common-ports check or Trusted Advisor will give you this information.

## AWS GuardDuty
- It is a managed service that can watch CloudTrail, VPC Flow Logs and DNS Logs, watching for malicious activity. 
- It can detect instances exhibiting signs of compromise, such as: 
  - Attempting to communicate with a command and control server.
  - Behaving as a spam bot with email traffic over port 25.
  - Sending requests that look like it is part of a DoS attack
  - [GuardDuty Backdoor](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html)
- It has a build-in list of suspect IP addresses and you can also upload your own lists of IPs.
- GuardDuty can trigger CloudWatch events which can then be used for a variety of activities like notifications or automatically responding to a threat.

## AWS VPC
- VPC Flow Logs enables you to capture information about the IP traffic going to and from network interfaces in your VPC. 
- Flow log data can be published to Amazon CloudWatch Logs and Amazon S3.
- Flow logs can help you with a number of tasks:
  - Diagnosing overly restrictive security group rules
  - Monitoring the traffic that is reaching your instance
  - Determining the direction of the traffic to and from the network interfaces
  - Aiding in investigating suspicius traffic
### DNS servers
- By default, AWS provides the Amazon DNS server. 
- To use your own DNS server you can create a new set of DHCP options for your VPC. 
- The default DHCP option set specifies AmazonProvidedDNS but you can provide the IP address of up to 4 of your own DNS servers. 
- You cannot update the existing option set, you must delete it and create a new one.
### Security groups
- Security groups are stateful, if you have allowed the inbound traffic you do not need to create a rule to allow the outbound reply. 
- By default an SG allows any outbound traffic so you don't need to add an outbound rule to a server in a public subnet.

## AWS KMS
### CMK
- Imported key material
  - Automatic key rotation is not available for CMKs that have imported key material, you will need to do this manually.
- Customer managed keys
  - A customer managed CMK supports automatic key rotation once per year. 
  - Creating and managing your own CMK gives you more flexibility, including the ability to create, rotate, disable, and define access controls, and to audit the encryption keys used to protect your data. 
- AWS managed keys 
  - AWS managed keys automatically rotate once every three years.

## AWS Systems Manager 
### Parameter Store
- Services that support parameter store:
  - Amazon EC2
  - Amazon ECS
  - AWS Lambda
    - If a service does not directly support it (e.g., RDS), just **use Lambda in association with the service**
  - AWS CloudFormation
  - AWS CodeBuild
  - AWS CodeDeploy
- Configure integration with the following AWS services for encryption, notification, monitoring, and auditing:
  - AWS KMS
  - Amazon SNS
  - Amazon CloudWatch
  - AWS CloudTrail
- Parameter Store uses KMS customer master keys to encrypt the parameter values when you create or change them.
  - An instance role needs permission both to read an SSM parameter and to use KMS to decrypt it.
### Patch Manager
- The default predefined patch baseline for Windows servers in Patch Manager is `AWS-DefaultPatchBaseline`.

## AWS Direct Connect
- With AWS Direct Connect plus VPN, you can combine one or more AWS Direct Connect dedicated network connections with the Amazon VPC VPN. 
- This combination provides an IPsec-encrypted private connection that also reduces network costs, increases bandwidth throughput, and provides a more consistent network experience than internet-based VPN connections.

## AWS ElastiCache
- Supports encryption only for Redis 3.2.6, 4.0.10 and later, not Memcached.

## AWS IAM
### Account Compromise
- If you suspect that your account is compromised, do the following:
  - Change your AWS account root user password.
  - Rotate and delete all root and AWS Identity and Access Management (IAM) access keys.
  - Delete any potentially compromised IAM users, and change the password for all other IAM users.
  - Delete any resources on your account you didn't create, such as EC2 instances and AMIs, EBS volumes and snapshots, and IAM users.
  - Respond to any notifications you received from AWS Support through the AWS Support Center.
### Policy evaluation logic
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

## AWS CloudTrail
- CloudTrail provides event history of your AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, command line tools, and other AWS services.
- It is recommended to use a dedicated S3 bucket for CloudTrail logs. 
### Multiple accounts
- Within an AWS Organization, you can create one CloudTrail to cover all accounts.
### Data events
- Management and Data events are handled by separate CloudTrails. 
  - You should log the events to separate buckets, then configure access to the CloudTrail and read only access to the S3 bucket using an IAM policy attached to the user or group. 
  - Give each class of user only the access they need.
- Data events provide insight into the resource operations performed on or within a resource, these events are often high-volume activities. 
- Example data events include S3 object-level API activity and Lambda function execution activity, the Invoke API. 
- Data events are disabled by default when you create a trail. 
- To record CloudTrail data events, you must explicitly add the supported resources or resource types for which you want to collect activity to a trail.
### Regions
- When you apply a trail to all regions, CloudTrail uses the trail that you create in a particular region to create trails with identical configurations in all other regions in your account. 
### Integrity
- To determine whether a log file was modified, deleted, or unchanged after CloudTrail delivered it, you can use CloudTrail log file integrity validation.

## AWS CloudWatch
- You can use Amazon CloudWatch Logs to monitor, store, and access your log files from EC2 instances, AWS CloudTrail, Route 53, and other sources. 
- You can then retrieve the associated log data from CloudWatch Logs. 
- CloudWatch alone lacks the business rules that are provided with GuardDuty to create an event whenever malicious or unauthorized behavior is observed.
- If an anomaly is detect, CloudWatch Event can trigger a Lambda.
### CloudWatch Logs
- You can use Amazon CloudWatch Logs to monitor, store, and access your log files from EC2 instances, AWS CloudTrail, Route 53, and other sources. 
- You can then retrieve the associated log data from CloudWatch Logs.
### CloudWatch Events
- You can use CloudWatch Events to schedule automated actions that self-trigger at certain times using cron or rate expressions.
- You can configure Amazon Inspector as a target for CloudWatch Events. 

## AWS EC2
- If you connect to your instance using SSH and get any of the following errors, "Host key not found in `[directory]`", "Permission denied (publickey)", or "Authentication failed, permission denied", verify that you are connecting with the appropriate user name for your AMI *and* that you have specified the proper private key (.pem) file for your instance.
- If you lose the private key for an EBS-backed instance, you can regain access to your instance. You must: 
1. stop the instance, 
2. detach its root volume and attach it to another instance as a data volume, 
3. modify the `authorized_keys` file, 
4. move the volume back to the original instance, and 
5. restart the instance.

## AWS Marketplace
### IDS/IPS
- AWS GuardDuty is not an IDS. While it does perform _threat_ detection based on logs, it does not detect _intrusion_. 
- AWS Shield is not an IPS. It mitigates DDoS attacks, but it does not prevent intrusion.
- AWS acknowledge that they do not provide IPS/IDS. 
  - Instead they suggest that third-party software can be used to provide additional functionality such as deep packet inspection, IPS/IDS, or network threat protection. 
  - Search for IPS on AWS Marketplace and you will find a range of suitable products!

## Amazon Cloudfront
### Encryption in transit
- End-to-end encryption _between_ a user and S3 entails using TLS; it does not entail server-side encryption (SSE) for S3, which is encryption at rest.

## AWS Lambda
- For Lambda to send logs to CloudWatch, the function execution role needs to permission to write to CloudWatch.

## Test Ideas
- Try out Trusted Advisor vs AWS Config vs AWS Inspector for detecting: 
  - An open SSH port:
    - Does Trusted Advisor catch the exposure?
    - Does Inspector detect the port?
    - If a Config rule is set, and a notification created, does Config notice the exposure?
    - If a Config Lambda is set and configuration changes, does Config close the port?
  - An open HTTP (not HTTPS) port:
    - Does Trusted Advisor catch the exposure?
    - Does Inspector detect the port?
    - If a Config rule is set, and a notification created, does Config notice the exposure?
    - If a Config Lambda is set and configuration changes, does Config close the port?
- Try out VPC Flow Logs going to S3 vs CloudWatch Logs
  - Observe SSH traffic
  - Observe HTTP traffic
  - Create an HTTP redirect to HTTPS and observe

## Next Up
- [x] ~Restructure notes under services~
- [x] ~Create diagram for policy evaluation~
- [ ] Distinguish Inspector, GuardDuty, Config, and Trusted Advisor
  - [x] [Backdoor Finding](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html)
  - [x] [Trusted Advisor](https://aws.amazon.com/premiumsupport/technology/trusted-advisor/)
  - [x] [How Config Works](https://docs.aws.amazon.com/config/latest/developerguide/how-does-config-work.html)
  - [x] [Amazon Inspector FAQ](https://aws.amazon.com/inspector/faqs/)
  - [x] [GuardDuty FAQ](https://aws.amazon.com/guardduty/faqs/)
- [ ] Distinguish CloudTrail, CloudWatch, GuardDuty, and VPC Flow Logs with table or diagram
  - [x] [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
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
- [ ] Create diagrams or mnemonics or 1-3 bullet points for special cases:
  - [ ] [AWS Direct Connect Plus VPN](https://docs.aws.amazon.com/whitepapers/latest/aws-vpc-connectivity-options/aws-direct-connect-plus-vpn-network-to-amazon.html)
  - [ ] [SSM Parameter Store](https://docs.aws.amazon.com/kms/latest/developerguide/services-parameter-store.html)
  - [ ] [Lambda Access to DynamoDB](https://aws.amazon.com/blogs/security/how-to-create-an-aws-iam-policy-to-grant-aws-lambda-access-to-an-amazon-dynamodb-table/)
  - [ ] [DDoS Whitepaper](https://d1.awsstatic.com/whitepapers/Security/DDoS_White_Paper.pdf)
  - [ ] [Troubleshooting EC2 Connection](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/TroubleshootingInstancesConnecting.html)
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
- [ ] Review and remove unneeded notes
- [ ] For each wrong or flagged questions:
   - [ ] Read and take 1-3 bullets
   - [ ] For wrong questions, also note answers if different from bullets
- [ ] Iterative control exercise
  - [ ] Architectect and diagram a full workload with minimal controls
  - [ ] Build the workload
  - [ ] Draft blog 1.1
  - [ ] Pentest the workload
  - [ ] Draft blog 1.2
  - [ ] Architect and diagram an improved workload with native controls
  - [ ] Build the improved workload
  - [ ] Draft blog 2.1
  - [ ] Pentest the improved workload
  - [ ] Run account hijacking attack
  - [ ] Draft blog 2.2
  - [ ] Add CloudFlare, Castle
  - [ ] Draft blog 3.1
  - [ ] Run account hijacking attack against CloudFlare, Castle
  - [ ] Draft blog 3.2
- [ ] Attempt 4 (target: >90%)
- [ ] Review and remove unneeded notes
- [ ] For each wrong or flagged questions:
   - [ ] Read and take 1-3 bullets
   - [ ] For wrong questions, also note answers if different from bullets
- [ ] Review video on how to prepare for official practice
- [ ] Official practice
- [ ] Review and remove unneeded notes
- [ ] For each question, research correct answer

## Attempt Log
1. 65%
2. 77%
3. 
4. 
5.

(>90% needed to take official practice)
