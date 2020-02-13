# AWS Security Grindfest

- [Data Protection](#data-protection)
- [Incident Response](#incident-response)
- [Infrastructure Security](#infrastructure-security)
- [Identity and Access Management](#identity-and-access-management)

## Data Protection

### AWS KMS
#### CMK
- Deleting a key
  - Data can’t be decrypted if the corresponding CMK has been deleted.
  - Only delete a CMK if you no longer need to access any files that it was used to encrypt.
- Imported key material
  - Automatic rotation is not supported for a CMK with imported key material. 
  - You cannot import different key material into a CMK, so you must reimport the same key material if it expires or is accidentally deleted.
  - Automatic key rotation is not available for CMKs that have imported key material, you will need to do this manually.
- Customer managed keys
  - A customer managed CMK supports automatic key rotation once per year. 
  - Creating and managing your own CMK gives you more flexibility, including the ability to create, rotate, disable, and define access controls, and to audit the encryption keys used to protect your data. 
- AWS managed keys 
  - AWS managed keys automatically rotate once every three years.

### Amazon S3
#### Glacier Vault
- Glacier Vault Lock allows you to easily deploy and enforce compliance controls for individual Glacier vaults with a vault lock policy.
- You can specify controls such as Write Once Read Many in a vault lock policy and lock the policy from future edits.
- After the vault lock enters the in-progress state, you have 24 hours to complete the lock. 
- If you don't complete the vault lock process within 24 hours after entering the in-progress state, your vault automatically exits the in-progress state, and the vault lock policy is removed. 
- While the lock is in-progress, if it doesn't work as expected, you can abort the lock and restart from the beginning.

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

## Incident Response

### AWS Config
- AWS Config generates configuration items when the configuration of a resource changes.
- It maintains historical records of the configuration items of your resources from the time you start the configuration recorder.

### AWS IAM
#### Account Compromise
- If you suspect that your account is compromised, do the following:
  - Change your AWS account root user password.
  - Rotate and delete all root and AWS Identity and Access Management (IAM) access keys.
  - Delete any potentially compromised IAM users, and change the password for all other IAM users.
  - Delete any resources on your account you didn't create, such as EC2 instances and AMIs, EBS volumes and snapshots, and IAM users.
  - Respond to any notifications you received from AWS Support through the AWS Support Center.

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
