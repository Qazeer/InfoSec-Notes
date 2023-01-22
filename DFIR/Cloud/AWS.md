# DFIR - Cloud - AWS

### AWS account information enumeration

###### AWS CLI access

The `AWS Command Line Interface (AWS CLI)` can be used to access AWS resources
through a command line utility. To setup the `AWS CLI` environment, notably the
configuration of credentials, the `aws configure` command may be used.

The `aws configure` will ask for the following information, that will be stored
(in clear-text) in the `config` and `credentials` files (by default in a `.aws`
folder in the current's user home directory):
  - `Access key ID`
  - `Secret access key`
  - AWS default region
  - Output format

To create a `Access key ID` and `secret access key`, refer to the
[AWS official documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html).

###### Manual enumeration with AWS CLI

The following commands can be used to retrieve basic information about the AWS
account:

```bash
# Retrieves information about the IAM entity usage (number of users, groups, roles, etc.).
aws iam get-credential-report

# Lists the IAM users, with their creation date and password last used timestamp.
aws iam list-users

# Lists the users'access keys, with their status and creation date.
aws iam list-access-keys

# Lists the IAM groups (collection of IAM users that can be associated with specific permissions).
aws iam list-groups

# Retrieves the groups associated with a given user.
aws iam list-groups-for-user --user-name "<USERNAME>"

# Lists the IAM roles (an IAM identity that can be associated with specific permissions. An IAM role can be assumed can users allowed to do so).
aws iam list-roles

# Lists all the IAM policies (an IAM policy grants IAM identities - users, groups, or roles - to resources. Permissions in the policies determine whether an IAM principal (user or role) request is allowed or denied.)
aws iam list-policies

# Lists all the IAM policy names and ARN.
aws iam list-policies --query 'Policies[*].[PolicyName, Arn]' --output text

# Lists the metadata of the specified IAM policy.
aws iam list-policies --query 'Policies[?PolicyName==`<POLICY_NAME>`]'

# Retrieves the IAM policies associated with the specified user / group / role.
# Inline IAM policies embedded in the specified IAM user.
aws iam list-user-policies --user-name "<USERNAME>"
# IAM policies attached to the specified IAM user.
aws iam list-group-policies --group-name "<GROUPNAME>"
aws iam list-role-policies --role-name "<ROLENAME>"

# Lists all the IAM users, groups, and roles that the specified policy is attached to.
# Example policy ARN: arn:aws:iam::aws:policy/service-role/AWSApplicationMigrationReplicationServerPolicy
aws iam list-entities-for-policy --policy-arn "<POLICY_ARN>"

# Lists the version associated with an IAM policy.
aws iam list-policy-versions --policy-arn "<POLICY_ARN>"

# Retrieves the permissions associated with an IAM policy (and policy version).
aws iam get-policy-version --policy-arn "<POLICY_ARN>" --version-id "<v1 | POLICY_VERSION_ID>"

# Lists the S3 buckets in the account.
aws s3 ls

# Retrieves more detailed (compared to s3 ls) information on a bucket (and bucket files).
aws s3api list-objects --bucket <BUCKET_NAME>

# Download / upload files from / to a S3 bucket.
# Source / destination for s3://<BUCKET> or local path.
aws s3 cp [--recursive] <SOURCE> <DEST>
```

###### Automated enumeration with ScoutSuite

[`Scout Suite`](https://github.com/nccgroup/ScoutSuite) leverage the API
provided by AWS (as well as other possible Cloud providers) to automatically
enumerate the configuration of the account. It can be used to quickly gather
information on the attack surface of the AWS account across all regions.

```bash
python3 scout.py aws [--access-key-id <ACCESS_KEY_ID>] [--secret-access-key <ACCESS_KEY_SECRET>]
```

### AWS logs overview

A number of log sources are available in `AWS` that can be useful for incident
response purposes:

| Name | Description |
|------|-------------|
| `CloudTrail` | Logs of every operation conducted in the AWS account. Essentially logs all API calls made in the account. <br><br> For each action / operation, the following information are logged: <br> - Unique Event ID. <br> - Event name (such as `ListPolicies`, `AssumeRole`, etc.). <br> - The timestamp of the operation. <br> - The region the operation was conducted in. <br> - Information on who realized the action (IAM identity, source IP address, user agent). <br> - The eventual impacted resource. <br> - The eventual request parameters. <br> - ...  |
| `CloudWatch` | System performance metrics, such as CPU usage, filesystem or network inputs/outputs, etc. <br><br> An additional `CloudWatch` agent can be installed on EC2 hosts to forward OS-level logs to `CloudWatch`. <br><br> Additionally, `CloudTrail` logs can be forwarded to `CloudWatch`, for instance to configure automated alerting. |
| `Config` | Logs periodically the configuration state of a number of resources (`EC2`, `VPC`, security groups, etc.). Can be used to detect change in configuration and retrieve historical data on configuration changes (who and when was a given resource created / modified). |
| `S3 Access Logs` | Logs bucket-level activities, i.e access, upload, modification, and deletion of data stored in a `S3 bucket` (versus operation on the bucket object itself as logged by `CloudTrail`). <br><br> `S3 Access Logs` i disabled by default and must be enabled on a per bucket basis. |
| `VPC Flow Logs` | Logs `VPC`-level `IP` network traffic to `CloudWatch`. <br><br> Different version of `VPC Flow Logs`, 2 to 5 to date, can be enabled. Higher versions record an increased number of fields per record. The `version 2`, enabled by default, records the following fields (in order): <br> - version number. <br> - account id (AWS account ID of the owner of the source network interface for which traffic is recorded). <br> - interface id (ID of the network interface for which the traffic is recorded). <br> - source address. <br> - destination address. <br> - source port. <br> - destination port. <br> - network protocol. <br> - number of packets transferred during the "flow" log. <br> - number of bytes transferred during the "flow" log. <br> - start of the "flow" log. <br> - end of the flow log. <br> - whether the traffic was accepted (`ACCEPT`) or rejected (`REJECT`). <br> - status of the flow log. <br><br> For more information on `VPC Flow Logs`, refer to the official [AWS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html). |
| `WAF Logs` | Logs requests processed by the `AWS WAF` service. `WAF Logs` can notably be forwarded to `CloudWatch` or stored in a `S3` bucket. <br><br> Information about the request (source IP, eventual requests headers, eventual parameters, etc.) as well as the rule matched are logged. |

### AWS logs collection

###### Multi-regions CloudTrail logs export

The [`awsCloudTrailDownload.py`](https://github.com/dlcowen/sansfor509/blob/main/AWS/awsCloudTrailDownload.py)
Python script can be used to download the `CloudTrail` logs across all regions.

```bash
python awsCloudTrailDownload.py
```

###### Automated logs export with Invictus-AWS

The [`Invictus-AWS`](https://github.com/invictus-ir/Invictus-AWS) Python script
can be used to retrieve information about the environment (service usage and
configuration) and export logs from a number of sources (`CloudTrail`,
`CloudWatch`, `S3 Access Logs`, ...) to an `S3` bucket. `Invictus-AWS` is
region bound.

```
# Configures the required API access.
aws configure

# Exports the configuration and logs from the specified region (such as "us-east-1").
python3 invictus-aws.py --region=<REGION>

# Downlaods locally the exported / collected elements from invictus-aws.py.
aws s3 cp --recursive s3://<INVICTUS_BUCKET> <EXPORT_FOLDER>
```

###### CloudWatch logs export with awslogs

The [`awslogs`](https://github.com/jorgebastida/awslogs) utility can be used to
access and filter the AWS `CloudWatch` logs. `awslogs` requires the permissions
associated with the [`CloudWatchLogsReadOnlylAccess` policy](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/iam-identity-based-access-control-cwl.html).

```bash
awslogs <get | groups | streams> [--aws-region "<AWS_REGION>"] [--aws-access-key-id "<ACCESS_KEY_ID>"] [--aws-secret-access-key "<ACCESS_KEY_SECRET>"]

# Lists the existing logs groups.
awslogs groups

# Lists the streams in the specified log group.
awslogs streams <LOG_GROUP>

# Retrieves the logs in all or the specified log group / stream.
# The start / end filtering support multiple filtering options: DD/MM/YYYY HH:mm, <INT><m | h | d | w>.
awslogs get <ALL | LOG_GROUP> <ALL | LOG_GROUP_STREAM> -s <START> -e <END>
```

### CloudTrail logs analysis

###### CloudTrail key fields

| Field name | Description |
|------------|-------------|
| `eventTime` | Event timestamp in `UTC`. |
| `awsRegion` | The region the request was made to, such as `us-east-1`. |
| `eventSource` | The service the request was made to. <br><br> Such as `s3.amazonaws.com` for `S3` buckets, `sts.amazonaws.com` for the `Security Token Service (STS)` for temporary credentials request, etc. |
| `eventName` | The request action, matching one of the API for that service. <br><br> For example, `AssumeRole`, `ListBuckets`, `SendCommand`, etc. |
| `errorCode` <br> | The error code and human-readable error message associated with an event if (and only if) the operation failed. |
| `readOnly` | Whether the operation is a read-only operation (`true` or `false`). |
| `userIdentity` | Information about the user that made the request. <br><br> * `userIdentity.type`: the type of the identity. <br> Possible types: <br> - `Root`: account root user. <br> - `IAMUser`: IAM user. <br> - `AssumedRole`: temporary security credentials obtained with a role by making a call to the `AWS STS`'s `AssumeRole` API. <br> - `Role`: <br> - `FederatedUser`: temporary security credentials for a federated user (`Active Directory`, `AWS Directory Service`, etc.), obtained via a call to the `AWS STS`'s `GetFederationToken` API. - `AWSAccount`: another AWS account. <br> - `AWSService`: AWS account that belongs to an AWS service. <br><br> * [Optional] `userIdentity.userName`: Human readable name of the identity that made the call. <br> Generally only available for `IAMUser` or `Root` identity. <br><br> * [Optional] `userIdentity.arn`: `ARN` of the entity (user or role) that made the call. <br><br> * [Optional] `userIdentity.principalId`: Unique identifier for the entity that made the call. <br> For temporary security credentials, this value includes the session name. For instance, for `AssumedRole` events, the `principalId` is the unique identifier that contains the role ID and the role session name returned in the `AssumeRole` event's `responseElements.assumedRoleUser.assumedRoleId`. <br><br> *  [Optional] `userIdentity.accountId`: The account that owns the entity that granted permissions for the request <br><br> * [Optional] `userIdentity.accessKeyId`: The eventual `access key ID` that was used to make the request. <br> `Access key IDs` beginning with `AKIA` are long-term credentials (for an `IAM user` or the AWS account root user) while `access key IDs` beginning with `ASIA` are temporary credentials (created using `AWS STS` operations). <br><br> * [Optional] `userIdentity.sessionContext`: Populated for requests made with temporary security credentials to contain information about the session that was created. <br> `userIdentity.sessionContext.creationDate`: when the session was created. <br> `userIdentity.sessionContext.mfaAuthenticated`: whether the initial credentials were authenticated MFA. <br> `userIdentity.sessionContext.`: <br> `userIdentity.sessionContext.sourceIdentity`: the original identity (user or role) making the request (with `type`, `arn`, `userName` sub-fields). |
| `sourceIPAddress` | The IP address that the request was made from. <br><br> For requests from services within AWS, only the `DNS` name of the service (for example `ec2.amazonaws.com`) is displayed. |
| `userAgent` | The `User-Agent` through which the request was made. |
| `resources` | A list of resource(s) accessed in the event. <br><br> For each resource, the following fields may be available: <br> - `type`: resource type identifier (in the format: `AWS::<AWS_SERVICE_NAME>::<AWS_DATA_TYPE_NAME>`). <br> - `ARN`: `ARN` of the resource. <br> - `accountId`: account that owns the resource. |
| `requestParameters` | The parameters, if any, that were sent with the request. <br><br> For example, `requestParameters.bucketName`, `requestParameters.userName`, etc. |
| `responseElements` | The response element(s) for actions that make changes (create, update, or delete actions). <br><br> For example, `responseElements.user.createDate`, `responseElements.accessKey.accessKeyId`, etc. |

###### CloudTrail notable API / events

| `eventSource` | `eventName` | Type | Description |
|-------------|-----------|------|-------------|
| `sts.amazonaws.com` | `GetCallerIdentity` | Reconnaissance | Return details about the IAM user or role whose credentials are used to call the operation. |
| `iam.amazonaws.com` | `ListUsers` | Reconnaissance | Enumerate the IAM users in the AWS account, that match the optional specified path prefix `requestParameters.pathPrefix`. |
| `iam.amazonaws.com` | `ListRoles` | Reconnaissance | Enumerate the IAM roles in the AWS account, that match the optional specified path prefix `requestParameters.pathPrefix`. |
| `iam.amazonaws.com` | `ListGroups` | Reconnaissance | Enumerate the IAM groups in the AWS account, that match the optional specified path prefix `requestParameters.pathPrefix`. |
| `iam.amazonaws.com` | `ListPolicies` | Reconnaissance | Enumerate the IAM policies in the AWS account, that match the optional specified path prefix `requestParameters.pathPrefix`. |
| `ec2.amazonaws.com` | `DescribeInstances` | Reconnaissance | Enumerate and retrieve information on all or the specified instances. <br><br> Notable fields: <br> `requestParameters.instanceId`: optional list of instance id(s) to enumerate. <br> `requestParameters.filter`: optional filter(s). |
| `sts.amazonaws.com` | `AssumeRole` | Privilege escalation | Returns a set of temporary security credentials that can be used to access AWS resources under the privileges granted by the role. A role is a set of policies. <br><br> Notable fields: <br> `requestParameters.roleArn`: The `ARN` of the role to assume. <br> `requestParameters.roleSessionName`: a unique identifier (in the form of `i-089eb6ce74072ae1f`) to identify the session. <br> `requestParameters.durationSeconds`: the validity period of the temporary credentials. Minimum value of 900 seconds up to the maximum session duration set for the role (maximum 43200 seconds). <br><br> `responseElements.assumedRoleUser.arn`: the `ARN` of the temporary security credentials, that will be logged under `userIdentity.arn` (for API calls made during the session). <br> `responseElements.assumedRoleUser.assumedRoleId`: a unique identifier containing the role ID and the role session name, that will be logged under `userIdentity.principalId` (for API calls made during the session). <br> `responseElements.credentials.accessKeyId`: the access key ID that identifies the temporary security credentials, that will be logged under `userIdentity.accessKeyId` (for API calls made during the session). <br> `responseElements.credentials.expiration`: the date on which the current credentials expire. |
| `sts.amazonaws.com` | `AttachUserPolicy` | Privilege escalation | Attaches the specified managed policy to the specified user. A policy is the most atomic level of privileges that can be granted. <br><br> Notable fields: <br> `requestParameters.userName` <br> `requestParameters.policyArn` |
| `sts.amazonaws.com` | `PutUserPolicy` | Privilege escalation | Add (or update) an inline policy embedded in the specified IAM user. A policy is the most atomic level of privileges that can be granted. <br><br> Notable fields: <br> `requestParameters.userName` <br> `requestParameters.policyName` <br>  `requestParameters.policyDocument`: policy in JSON format. |
| `iam.amazonaws.com` | `CreateAccessKey` | Privilege escalation <br><br> Persistence | Create a new AWS secret access key for the user specified by `requestParameters.userName`. <br><br> Notable fields: <br> `responseElements.accessKey.accessKeyId` <br> `responseElements.accessKey.createDate` <br> `responseElements.accessKey.status` <br> `responseElements.accessKey.userName` |
| `iam.amazonaws.com` | `CreateLoginProfile` | Privilege escalation <br><br> Persistence | Create a password for the user specified by `requestParameters.userName` (to allow the user to access the AWS Management Console). <br><br> As a privilege escalation vector, a user (`userIdentity.userName`) can create a password for a (more privileged) user (`requestParameters.userName`) to connect as the user through the management console and elevate privileges. |
| `iam.amazonaws.com` | `UpdateLoginProfile` | Privilege escalation <br><br> Persistence | Create a password for the user specified by `requestParameters.userName` (to allow the user to access the AWS Management Console). <br><br> As a privilege escalation vector, a user (`userIdentity.userName`) can reset the password of a (more privileged) user (`requestParameters.userName`) to compromise that user and elevate privileges. |
| `ec2.amazonaws.com` | `RunInstances` | Execution <br><br> Persistence | Create and run new EC2 instance(s). <br><br> Notable fields: <br> `requestParameters.instanceType` <br><br> The `requestParameters.instancesSet.items{}` list contains (for each request instance): <br> `imageId` <br> `tags{}` list with a `Key`=`Name` with `Value`=`<INSTANCE_NAME>` <br> `keyName` for the key credentials associated with the instance. <br><br> The `responseElements.instancesSet.items{}` list contains (for each created instance): <br> `instanceId` <br> `keyName` <br> `subnetId` <br> `privateIpAddress` |
| `ssm.amazonaws.com` | `SendCommand` | Execution | Run command(s) on one or more instances. <br><br> Notable fields: <br> `requestParameters.instanceIds` / `responseElements.command.instanceIds`: list of instance ids for the command execution. <br> `requestParameters.documentName` / `responseElements.documentName`: name of the SSM document to run (such as `AWS-RunShellScript` or `AWS-RunPowerShellScript`). <br> `requestParameters.parameters`: required and optional parameters specified in the document being run (can be `HIDDEN_DUE_TO_SECURITY_REASONS` for shell / powershell execution). |
| `ssm.amazonaws.com` | `StartSession` | Execution | Initiate a connection to the target instance. <br><br> Notable fields: <br> `requestParameters.target`: target instance id. <br> `responseElements.sessionId`: identifier of the session. <br> `responseElements.streamUrl`: an URL on the target instance `SSM Agent` used by the `Session Manager client` to send commands and receive output. <br> `responseElements.tokenValue`: a token used to authenticate the connection (hidden in `CloudTrail`). |
| `ssm.amazonaws.com` | `ResumeSession` | Execution | Reconnect a connection after it has been disconnected (but not terminated). <br><br> Notable fields: <br> `requestParameters.sessionId`: identifier of the disconnected session. <br> `responseElements.sessionId`: identifier of the session. <br> `responseElements.streamUrl`: an URL on the target instance `SSM Agent` used by the `Session Manager client` to send commands and receive output. <br> `responseElements.tokenValue`: a token used to authenticate the connection (hidden in `CloudTrail`). |
| `ec2.amazonaws.com` | `ModifyInstanceAttribute` | Execution <br><br> Persistence | Modify the specified attribute of the specified instance. <br><br> A modification of the `userData` attribute can be used to execute code at boot time, requiring a restart of a running instance (`StopInstances` then `StartInstances`). <br><br> *Does not allow the modification of the long-terme key pair(s) associated with an instance. There is no AWS API to conduct such operation.* <br><br> Notable fields: <br> `requestParameters.instanceId` <br> `requestParameters.attribute` (`userData` for the user data). <br> `requestParameters.userData` (specified user data). |
| `ec2.amazonaws.com` | `SendSSHPublicKey` | Execution | Push a temporary SSH public key to the specified EC2 instance for use by the specified user. The key remains for 60 seconds. Used by the `EC2 Instance Connect` service for `SSH` access (directly or through the service web-based interface). <br><br> Notable fields: <br> `requestParameters.instanceId` |
| `lambda.amazonaws.com` | `CreateFunction` | Execution <br><br> Persistence | Create a new Lambda function. <br><br> Notable fields: <br> `requestParameters.functionName` <br> `requestParameters.code` but doesn't include the `ZipFile` parameter (that contains the base64-encoded contents of the deployment package). |
| `lambda.amazonaws.com` | `UpdateFunctionCode` | Execution <br><br> Persistence | Update an existing Lambda function's code. <br><br> Notable fields: <br> `requestParameters.functionName` <br> `requestParameters.code` but doesn't include the `ZipFile` parameter (that contains the base64-encoded contents of the deployment package). |
| `s3.amazonaws.com` | `PutBucketAcl` | Exfiltration | Set the `ACL` of the specified bucket. Note that the use of `ACL` for `S3` is generally deprecated (in favor of using policy). <br><br> Notable fields: <br> `requestParameters.bucket` <br> `requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI` array : URIs for the container for the entity being granted permissions. <br> If the array contains the string `http://acs.amazonaws.com/groups/global/AuthenticatedUsers` or `http://acs.amazonaws.com/groups/global/AllUsers`, the specified bucket is made public. |
| `iam.amazonaws.com` | `CreateUser` | Persistence | Create a new AWS user in the account. <br><br> Notable fields: <br> `responseElements.user.arn` <br> `responseElements.user.createDate` <br> `responseElements.user.userId` <br> `responseElements.user.userName` |
| `ec2.amazonaws.com` | `CreateKeyPair` | Persistence | Create a key pair with the specified name in the AWS Region. <br><br> Notable fields: <br> `requestParameters.keyName` / `responseElements.keyName` <br> `responseElements.keyFingerprint` <br> `responseElements.keyPairId` |
| `ec2.amazonaws.com` | `ImportKeyPair` | Persistence | Import the public key (previously created), only providing the public key to AWS. <br><br> Notable fields: <br> `requestParameters.keyName` / `responseElements.keyName` <br> `responseElements.keyFingerprint` <br> `responseElements.keyPairId` |
| `sts.amazonaws.com` | `GetSessionToken` | Persistence | Return a set of temporary credentials for an `AWS account` or `IAM user`. <br><br> The temporary security credentials created by `GetSessionToken` can be used to make API calls to any AWS service with the following exceptions: <br> - Calls to `IAM` API operations are prohibited unless MFA authentication information is included in the request. <br> - Calls to `STS` API are prohibited (except `AssumeRole` and `GetCallerIdentity`). <br><br> Notable fields: <br> `responseElements.accessKeyId` <br> `responseElements.expiration` |

###### CloudTrail logs manual analysis with jq

The `jq` utility supports querying JSON formatted data and can be used to
select and filter events from `CloudTrail` exported logs.

The following queries illustrate how `jq` can be used to select, order, and
filter events from `CloudTrail` JSON logs:

```bash
# The following queries assume that the exported events are placed in a top-level "Records" field.

# Select the specified fields (eventTime, eventName, awsRegion, sourceIPAddress, and userIdentity).
jq '.Records[] | {eventTime, eventName, awsRegion, sourceIPAddress, userIdentity}' <JSON_FILE | *>

# Sorts events by their timestamp.
jq '.Records | sort_by(.eventTime)[]' <JSON_FILE | *>

# Select events between two timestamps.
jq ".Records | sort_by(.eventTime)[] | select(.eventTime | . == null or (fromdateiso8601 > $(TZ=UTC date -d"YYYY-MM-DDTHH:MM" +%s) and fromdateiso8601 < $(TZ=UTC date -d"YYYY-MM-DDTHH:MM" +%s)))" <JSON_FILE | *>

# Select the event that modified the account state.
jq '.Records[] | select(.readOnly == false)' <JSON_FILE | *>

# Select the specified event linked to the specified source IP address.
jq '.Records[] | select(.sourceIPAddress == <IP>)' <JSON_FILE | *>

# Select the events that contains the "Get" or "List" keyword.
jq '.Records[] | select(.eventName | match("Get|List"))'

# Select the events conducted by a given principal.
jq '.Records | sort_by(.eventTime)[] | select(.userIdentity.principalId | match("<USERNAME>")?)' *

# Count the occurrence by source IP address in a collection of CloudTrail export files.
echo 'def counter(stream):
  reduce stream as $s ({}; .[$s|tostring] += 1);

counter(.Records[].sourceIPAddress)
| to_entries[]
| {sourceIPAddress: (.key), Count: .value, file: input_filename}' > ip_count.jq
jq -f ip_count.jq *
```

--------------------------------------------------------------------------------

### References

https://www.youtube.com/watch?v=VLIFasM8VbY

https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/logging-and-events.html

https://www.chrisfarris.com/post/aws-ir/

https://www.datadoghq.com/blog/monitoring-cloudtrail-logs/

https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html

https://www.wiz.io/blog/hunting-for-signs-of-persistence-in-the-cloud-an-ir-guide

https://docs.datadoghq.com/fr/security/default_rules/#cat-cloud-siem-log-detection

https://docs.sekoia.io/xdr/features/collect/integrations/cloud_and_saas/aws/aws_cloudtrail/

https://docs.aws.amazon.com/fr_fr/lambda/latest/dg/logging-using-cloudtrail.html

https://easttimor.github.io/aws-incident-response/

https://stackoverflow.com/questions/61257189/ec2-instance-connect-and-iam-public-keys

https://docs.datadoghq.com/fr/security/default_rules/aws-bucket-acl-made-public/
