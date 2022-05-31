# DFIR - Cloud - AWS

### AWS CLI

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

### AWS account information enumeration

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

# Lists  all the IAM users, groups, and roles that the specified policy is attached to.
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

### AWS logs

###### Overview

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

###### [CloudWatch] awslogs

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

###### CloudTrail logs export

`CloudTrail` logs can be exported to an S3 bucket using the following
procedure:

```bash
# 1. creation of an S3 bucket for the export.
aws s3api create-bucket --bucket <BUCKET_NAME> --create-bucket-configuration LocationConstraint=<BUCKET_REGION>

# 2. [Optional step] creation of an user with full access to S3 and CloudTrail.
TODO
```

###### CloudTrail exported logs manual analysis with jq

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

https://www.datadoghq.com/blog/monitoring-cloudtrail-logs/
