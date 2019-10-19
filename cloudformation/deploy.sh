#!/bin/bash
set -euxo pipefail

if [[ -z "${CREATE_BUCKET}" ]]; then
  CREATE_BUCKET="no"
else
  CREATE_BUCKET="yes"
fi
# TODO - this should be broken into separate build and deploy steps

npm install

aws cloudformation package \
  --s3-bucket ${ARTIFACT_BUCKET} \
  --template-file ./cloudformation/template.yaml \
  --output-template-file ./template.packaged.yaml

aws cloudformation deploy \
  --template-file ./template.packaged.yaml \
  --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset \
  --stack-name ${STACK_NAME} \
  --parameter-overrides \
    DefaultRoleName=${DEFAULT_ROLE_NAME} \
    SecretsManagerPrefix=${SECRETS_MANAGER_PREFIX} \
    BucketName=${BUCKET_NAME} \
    BucketPrefix=${BUCKET_PREFIX} \
    CreateBucket=${CREATE_BUCKET} \
    SNSTopic=${SNS_TOPIC} \
    Schedule=${SCHEDULE} \
    ScheduledAccountId=${SCHEDULED_ACCOUNT_ID} \
    ScheduledRoleName=${SCHEDULED_ROLE_NAME} \
    ScheduledExternalId=${SCHEDULED_EXTERNAL_ID}
