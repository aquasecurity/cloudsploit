# CloudSploit Lambda Deployment Guide

The `Makefile` has all of the commands required to build, package, and deploy CloudSploit to AWS Lambda. It makes use of environment variables for configuration.

## Environment Variable COnfiguration

|   Environment Variable    | Description
|---------------------------|-------------
| `ARTIFACT_BUCKET`         | The name of the bucket to upload the zipped lambda code to
| `STACK_NAME`              | The name to give the cloudformation stack
| `DEFAULT_ROLE_NAME`       | The default to use for the name of the role for CloudSploit to assume
| `SECRETS_MANAGER_PREFIX`  | The prefix to be used for secrets manager secrets
| `BUCKET_NAME`             | The name of the bucket to write output to
| `BUCKET_PREFIX`           | The prefix to write within the bucket
| `CREATE_BUCKET`           | Whether or not to create the bucket, using the given bucket name ("no" or "yes")
| `SNS_TOPIC`               | The topic to subscribe the CloudSploit lambda to
| `SCHEDULE`                | A schedule expression to run the lambda on
| `SCHEDULED_ACCOUNT_ID`    | If schedule provided, the account ID to scan
| `SCHEDULED_ROLE_NAME`     | If schedule provided, the role name to assume
| `SCHEDULED_EXTERNAL_ID`   | If schedule provided, the external ID to use when assuming the role

## Sample Config File

```bash
export ARTIFACT_BUCKET=mybucket
export STACK_NAME=cloudsploit-test
export DEFAULT_ROLE_NAME=cloudsploit-role
export SECRETS_MANAGER_PREFIX="/cloudsploit/secrets/"
export BUCKET_NAME=cloudsploit-output-bucket
export BUCKET_PREFIX="/"
export CREATE_BUCKET=yes
export SNS_TOPIC=""
export SCHEDULE=""
export SCHEDULED_ACCOUNT_ID=""
export SCHEDULED_ROLE_NAME=""
export SCHEDULED_EXTERNAL_ID=""
```

## Deploy Process
1. Create a file with the above variables called `config.ENVIRONMENT-DESIGNATOR`, where ENVIRONMENT-DESIGNATOR can be your environment (dev, stage, prod)
2. run `make deploy env=ENVIRONMENT-DESIGNATOR`
    * Make deploy will install the npm modules, build the lambda SAM package, and deploy the lambda as a Cloudformation Template.

## Lambda Trigger
The Lambda can be triggered by a StepFunction or via the AWS CLI using the following event structure:
```json
{
    "aws": {
        "roleArn": "arn:aws:iam::ACCOUNTID:role/ROLENAME"
    },
    "s3Prefix": "PREFIX_FOR_FINDINGS_FROM_THIS_SPECIFIC_INVOCATION"
}
```
Substitute the appropriate values for ACCOUNTID, ROLENAME and PREFIX_FOR_FINDINGS_FROM_THIS_SPECIFIC_INVOCATION

More details on Lambda Invocation options are in the lambda_event_details.md file