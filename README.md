# AWS Security Grindfest

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

