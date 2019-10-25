# CloudSploit Lambda Deployment Guide

The `deploy.sh` has all of the commands required to build, package, and deploy CloudSploit to AWS Lambda. It makes use of environment variables for configuration.

## Environment Variable COnfiguration

|   Environment Variable    | Description
|---------------------------|-------------
| `ARTIFACT_BUCKET`         | The name of the bucket to upload the zipped lambda code to
| `STACK_NAME`              | The name to give the cloudformation stack
| `DEFAULT_ROLE_NAME`       | The default to use for the name of the role for cloudsploit to assume
| `SECRETS_MANAGER_PREFIX`  | The prefix to be used for secrets manager secrets
| `BUCKET_NAME`             | The name of the bucket to write output to
| `BUCKET_PREFIX`           | The prefix to write within the bucket
| `CREATE_BUCKET`           | Whether or not to create the bucket, using the given bucket name ("no" or "yes")
| `SNS_TOPIC`               | The topic to subscribe the cloudsploit lambda to
| `SCHEDULE`                | A schedule expression to run the lambda on
| `SCHEDULED_ACCOUNT_ID`    | If schedule provided, the account ID to scan
| `SCHEDULED_ROLE_NAME`     | If schedule provided, the role name to assume
| `SCHEDULED_EXTERNAL_ID`   | If schedule provided, the external ID to use when assuming the role

## Example Deployment

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
./cloudformation/deploy.sh
```
